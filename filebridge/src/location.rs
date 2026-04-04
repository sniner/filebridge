use crate::client::FileBridgeClient;
use crate::error::Error;
use crate::models::Metadata;
use crate::Result;
use hmac::{Hmac, Mac};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

fn unix_timestamp() -> Result<String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Api(reqwest::StatusCode::INTERNAL_SERVER_ERROR, "System clock error".into()))?
        .as_secs()
        .to_string())
}

/// A handle to a specific shared directory on a Filebridge server.
///
/// Provides methods for reading, writing, listing, and deleting files.
/// Obtained via [`FileBridgeClient::location`].
pub struct FileBridgeLocation<'a> {
    client: &'a FileBridgeClient,
    dir_id: String,
    token: Option<String>,
}

#[derive(Deserialize)]
struct ListResponse {
    items: Vec<Metadata>,
}

/// Encrypted request envelope for token-mode: path and parameters in body instead of URL.
#[derive(Serialize)]
struct RequestEnvelope<'a> {
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    length: Option<u64>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    extensive: bool,
}

impl<'a> FileBridgeLocation<'a> {
    /// Creates a new location handle. Prefer [`FileBridgeClient::location`] instead.
    pub fn new(client: &'a FileBridgeClient, dir_id: &str, token: Option<String>) -> Self {
        Self {
            client,
            dir_id: dir_id.to_string(),
            token,
        }
    }

    /// Base URL for this location without any file path (used in token-mode).
    fn base_url(&self) -> Result<url::Url> {
        Ok(self
            .client
            .base_url
            .join(&format!("api/v1/fs/{}", self.dir_id))?)
    }

    /// Build an encrypted request envelope body.
    fn encrypt_envelope(
        &self,
        token: &str,
        sig: &str,
        path: &str,
        offset: Option<u64>,
        length: Option<u64>,
        extensive: bool,
    ) -> Result<String> {
        let envelope = RequestEnvelope {
            path,
            offset,
            length,
            extensive,
        };
        let json_bytes = serde_json::to_vec(&envelope)?;
        Ok(crate::stream::encrypt_json_response(token, sig, &json_bytes)?)
    }

    /// Reads the entire file at `path` and returns its contents.
    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        self._read(path, None, None).await
    }

    /// Reads a byte range from the file at `path`.
    pub async fn read_range(
        &self,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>> {
        self._read(path, Some(offset), Some(length)).await
    }

    async fn _read(
        &self,
        path: &str,
        offset: Option<u64>,
        length: Option<u64>,
    ) -> Result<Vec<u8>> {
        if let Some(token) = &self.token {
            // Token mode: path in encrypted body, not URL
            let url = self.base_url()?;
            let timestamp = unix_timestamp()?;
            let nonce = format!("{:016x}", rand::random::<u64>());
            let signature =
                self.calculate_signature(token, &timestamp, &nonce, &Method::GET, &url)?;
            let envelope_body = self.encrypt_envelope(token, &signature, path, offset, length, false)?;

            let rb = self
                .client
                .client
                .request(Method::GET, url)
                .header("Accept", "application/vnd.filebridge.stream, application/json")
                .header("Content-Type", "application/vnd.filebridge.request")
                .header("X-Signature", &signature)
                .header("X-Timestamp", timestamp)
                .header("X-Nonce", &nonce)
                .body(envelope_body);

            let resp = rb.send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(Error::Api(status, text));
            }
            let resp_nonce = resp
                .headers()
                .get("X-Nonce")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            if resp_nonce != nonce {
                return Err(Error::NonceMismatch);
            }
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");

            if content_type.contains("application/json") {
                let json_val = self
                    .parse_json_response(resp, Some(&signature))
                    .await?;
                if json_val.get("items").is_some() {
                    return Err(Error::IsDirectory);
                }
                return Err(Error::Api(
                    reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                    "Unexpected JSON metadata instead of file content".to_string(),
                ));
            }

            if content_type.contains("application/vnd.filebridge.stream") {
                // Decrypt stream response
                let body = resp.bytes().await?;
                return self.decrypt_stream_content(&signature, &body);
            }

            return Ok(resp.bytes().await?.to_vec());
        }

        // No token: path in URL
        let mut url = self
            .client
            .base_url
            .join(&format!("api/v1/fs/{}/{}", self.dir_id, path))?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(off) = offset {
                query.append_pair("offset", &off.to_string());
            }
            if let Some(len) = length {
                query.append_pair("length", &len.to_string());
            }
        }

        let rb = self
            .client
            .client
            .request(Method::GET, url)
            .header("Accept", "application/octet-stream, application/json");

        let resp = rb.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Api(status, text));
        }

        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        if content_type.contains("application/json") {
            let json_val = self.parse_json_response(resp, None).await?;
            if json_val.get("items").is_some() {
                return Err(Error::IsDirectory);
            }
            return Err(Error::Api(
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                "Unexpected JSON metadata instead of file content".to_string(),
            ));
        }

        Ok(resp.bytes().await?.to_vec())
    }

    /// Streams file content into the provided async writer.
    ///
    /// Returns the HMAC signature of the stream if authentication is enabled.
    pub async fn read_stream<W: tokio::io::AsyncWrite + std::marker::Unpin>(
        &self,
        path: &str,
        mut writer: W,
    ) -> Result<Option<String>> {
        let timestamp = unix_timestamp()?;

        let mut req_sig = String::new();
        let mut req_nonce = String::new();

        let rb = if let Some(token) = &self.token {
            // Token mode: path in encrypted body
            let url = self.base_url()?;
            let nonce = format!("{:016x}", rand::random::<u64>());
            req_nonce = nonce.clone();
            let signature =
                self.calculate_signature(token, &timestamp, &nonce, &Method::GET, &url)?;
            let envelope_body =
                self.encrypt_envelope(token, &signature, path, None, None, false)?;
            req_sig = signature.clone();
            self.client
                .client
                .request(Method::GET, url)
                .header("Accept", "application/vnd.filebridge.stream")
                .header("Content-Type", "application/vnd.filebridge.request")
                .header("X-Signature", signature)
                .header("X-Timestamp", &timestamp)
                .header("X-Nonce", nonce)
                .body(envelope_body)
        } else {
            // No token: use plain octet-stream; stream framing adds no value without encryption
            // and avoids triggering the server's Content-Length calculation for framed responses.
            let url = self
                .client
                .base_url
                .join(&format!("api/v1/fs/{}/{}", self.dir_id, path))?;
            self.client
                .client
                .request(Method::GET, url)
                .header("Accept", "application/octet-stream, application/json")
        };

        let mut resp = rb.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Api(status, text));
        }

        if self.token.is_some() {
            let resp_nonce = resp
                .headers()
                .get("X-Nonce")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            if resp_nonce != req_nonce {
                return Err(Error::NonceMismatch);
            }
        }

        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        if content_type.contains("application/json") {
            let sig_opt = if !req_sig.is_empty() {
                Some(req_sig.as_str())
            } else {
                None
            };
            let json_val = self.parse_json_response(resp, sig_opt).await?;
            if json_val.get("items").is_some() {
                return Err(Error::IsDirectory);
            }
            return Err(Error::Api(
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                "Unexpected JSON response instead of stream".to_string(),
            ));
        }

        use tokio::io::AsyncWriteExt;

        // No token: server returns raw bytes; write them directly to the writer.
        if self.token.is_none() {
            while let Some(chunk) = resp.chunk().await? {
                writer.write_all(&chunk).await?;
            }
            return Ok(None);
        }

        let mut aead: Option<crate::stream::StreamAead> = None;
        if let Some(token_str) = &self.token
            && !req_sig.is_empty() {
                aead = Some(crate::stream::StreamAead::new(token_str, &req_sig)?);
            }

        use crate::stream::{StreamDecoder, StreamFrame};

        let mut decoder = StreamDecoder::new();
        let mut server_stop_hmac: Option<String> = None;
        let mut decrypt_buf: Vec<u8> = Vec::with_capacity(64 * 1024 + 16 + 1);

        while let Some(chunk) = resp.chunk().await? {
            decoder.push(&chunk);

            while let Some(frame) = decoder.next_frame()? {
                match frame {
                    StreamFrame::Meta { .. } => {
                        // META frames are not expected in read responses
                    }
                    StreamFrame::Data { payload } => {
                        if let Some(ref mut a) = aead {
                            decrypt_buf.clear();
                            decrypt_buf.extend_from_slice(&payload);
                            a.decrypt(&mut decrypt_buf)?;
                            writer.write_all(&decrypt_buf).await?;
                        } else {
                            return Err(Error::TokenRequired);
                        }
                    }
                    StreamFrame::Stop { signature } => {
                        server_stop_hmac = signature;
                    }
                }
            }
        }

        let mut computed_hmac = None;
        if let Some(mut a) = aead {
            if let Some(remote_stop) = &server_stop_hmac {
                a.verify_stop(remote_stop)?;
                computed_hmac = Some(remote_stop.clone());
            } else {
                return Err(Error::Api(
                    reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                    "Missing STOP frame in stream".to_string(),
                ));
            }
        }

        Ok(computed_hmac)
    }

    /// Streams data from the provided async reader into a file at `path`.
    pub async fn write_stream<R: tokio::io::AsyncRead + std::marker::Unpin + Send + 'static>(
        &self,
        path: &str,
        mut reader: R,
    ) -> Result<()> {
        let timestamp = unix_timestamp()?;

        let mut req_sig = String::new();
        let mut req_nonce = String::new();

        // In token mode: URL is just /api/v1/fs/{dir_id}, path in META frame
        let (rb, meta_envelope) = if let Some(token) = &self.token {
            let url = self.base_url()?;
            let nonce = format!("{:016x}", rand::random::<u64>());
            req_nonce = nonce.clone();
            let signature =
                self.calculate_signature(token, &timestamp, &nonce, &Method::PUT, &url)?;
            req_sig = signature.clone();
            let envelope_body =
                self.encrypt_envelope(token, &signature, path, None, None, false)?;
            let rb = self
                .client
                .client
                .request(Method::PUT, url)
                .header("Content-Type", "application/vnd.filebridge.stream")
                .header("X-Signature", signature)
                .header("X-Timestamp", &timestamp)
                .header("X-Nonce", nonce);
            (rb, Some(envelope_body))
        } else {
            let url = self
                .client
                .base_url
                .join(&format!("api/v1/fs/{}/{}", self.dir_id, path))?;
            let rb = self
                .client
                .client
                .request(Method::PUT, url)
                .header("Content-Type", "application/vnd.filebridge.stream");
            (rb, None)
        };

        let token_opt = self.token.clone();
        let req_sig_clone = req_sig.clone();
        let stream = async_stream::stream! {
            // In token mode, emit META frame first with encrypted envelope
            if let Some(envelope) = meta_envelope {
                let meta_frame = crate::stream::encode_meta(envelope.as_bytes());
                yield Ok::<_, std::io::Error>(bytes::Bytes::from(meta_frame));
            }

            let mut aead = if let Some(t) = token_opt {
                if req_sig_clone.is_empty() { None }
                else { crate::stream::StreamAead::new(&t, &req_sig_clone).ok() }
            } else { None };

            let mut buf = vec![0; 64 * 1024];
            let mut chunk: Vec<u8> = Vec::with_capacity(64 * 1024 + 16 + 1);
            use tokio::io::AsyncReadExt;
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => {
                        let stop_sig = aead.as_mut().and_then(|a| a.finalize().ok());
                        let frame = crate::stream::encode_stop(stop_sig.as_deref());
                        yield Ok::<_, std::io::Error>(bytes::Bytes::from(frame));
                        break;
                    }
                    Ok(n) => {
                        chunk.clear();
                        chunk.extend_from_slice(&buf[..n]);
                        if let Some(ref mut a) = aead
                            && a.encrypt(&mut chunk).is_err() {
                                yield Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Encryption failed"));
                                break;
                            }

                        let frame = crate::stream::encode_data(&chunk);
                        yield Ok::<_, std::io::Error>(bytes::Bytes::from(frame));
                    }
                    Err(e) => {
                        yield Err(e);
                        break;
                    }
                }
            }
        };

        let rb = rb.body(reqwest::Body::wrap_stream(stream));
        let resp = rb.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Api(status, text));
        }

        if self.token.is_some() {
            let resp_nonce = resp
                .headers()
                .get("X-Nonce")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            if resp_nonce != req_nonce {
                return Err(Error::NonceMismatch);
            }
        }

        Ok(())
    }

    /// Writes `data` to the file at `path`, optionally starting at `offset`.
    pub async fn write(&self, path: &str, data: &[u8], offset: Option<u64>) -> Result<()> {
        if let Some(token) = &self.token {
            // Token mode: use stream format with META frame, path in encrypted body
            let url = self.base_url()?;
            let req_ts = unix_timestamp()?;
            let req_nonce = format!("{:016x}", rand::random::<u64>());
            let req_sig =
                self.calculate_signature(token, &req_ts, &req_nonce, &Method::PUT, &url)?;
            let envelope_body =
                self.encrypt_envelope(token, &req_sig, path, offset, None, false)?;

            // Build stream body: META + DATA chunks + STOP
            let mut body_buf = Vec::new();
            body_buf.extend_from_slice(&crate::stream::encode_meta(envelope_body.as_bytes()));

            let mut aead = crate::stream::StreamAead::new(token, &req_sig)?;
            const CHUNK_SIZE: usize = 64 * 1024;
            for chunk_start in (0..data.len()).step_by(CHUNK_SIZE) {
                let chunk_end = (chunk_start + CHUNK_SIZE).min(data.len());
                let mut chunk = data[chunk_start..chunk_end].to_vec();
                aead.encrypt(&mut chunk)?;
                body_buf.extend_from_slice(&crate::stream::encode_data(&chunk));
            }
            // Handle empty data case
            if data.is_empty() {
                // No DATA frames needed
            }
            let stop_sig = aead.finalize()?;
            body_buf.extend_from_slice(&crate::stream::encode_stop(Some(&stop_sig)));

            let resp = self
                .client
                .client
                .request(Method::PUT, url)
                .header("Content-Type", "application/vnd.filebridge.stream")
                .header("X-Signature", &req_sig)
                .header("X-Timestamp", req_ts)
                .header("X-Nonce", &req_nonce)
                .body(body_buf)
                .send()
                .await?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(Error::Api(status, text));
            }
            let resp_nonce = resp
                .headers()
                .get("X-Nonce")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            if resp_nonce != req_nonce {
                return Err(Error::NonceMismatch);
            }
            return Ok(());
        }

        // No token: path in URL
        let mut url = self
            .client
            .base_url
            .join(&format!("api/v1/fs/{}/{}", self.dir_id, path))?;
        if let Some(off) = offset {
            url.query_pairs_mut()
                .append_pair("offset", &off.to_string());
        }

        self.send_request_binary(Method::PUT, url, data.to_vec(), None)
            .await?;
        Ok(())
    }

    /// Deletes the file at `path`.
    pub async fn delete(&self, path: &str) -> Result<()> {
        if self.token.is_some() {
            self.send_encrypted_request(Method::DELETE, path, None, None, false)
                .await?;
        } else {
            let url = self
                .client
                .base_url
                .join(&format!("api/v1/fs/{}/{}", self.dir_id, path))?;
            self.send_request_binary(Method::DELETE, url, vec![], None)
                .await?;
        }
        Ok(())
    }

    /// Returns metadata for the file or directory at `path`.
    pub async fn info(&self, path: &str) -> Result<Metadata> {
        self._info(path, false).await
    }

    /// Returns extended metadata (includes SHA-256 hash) for the file at `path`.
    pub async fn info_extensive(&self, path: &str) -> Result<Metadata> {
        self._info(path, true).await
    }

    async fn _info(&self, path: &str, extensive: bool) -> Result<Metadata> {
        let (resp, sig) = if self.token.is_some() {
            self.send_encrypted_request(Method::GET, path, None, None, extensive)
                .await?
        } else {
            let mut url = self
                .client
                .base_url
                .join(&format!("api/v1/fs/{}/{}", self.dir_id, path))?;
            if extensive {
                url.query_pairs_mut()
                    .append_pair("extensive", "true");
            }
            self.send_request_binary(Method::GET, url, vec![], None)
                .await?
        };
        let json_val = self.parse_json_response(resp, sig.as_deref()).await?;
        Ok(serde_json::from_value(json_val)?)
    }

    /// Lists entries in a directory. Pass `None` to list the root directory.
    pub async fn list(&self, path: Option<&str>) -> Result<Vec<Metadata>> {
        self._list(path, false).await
    }

    /// Lists entries with extended metadata (includes SHA-256 hashes).
    pub async fn list_extensive(&self, path: Option<&str>) -> Result<Vec<Metadata>> {
        self._list(path, true).await
    }

    async fn _list(&self, path: Option<&str>, extensive: bool) -> Result<Vec<Metadata>> {
        let effective_path = path.unwrap_or("");
        let (resp, sig) = if self.token.is_some() {
            self.send_encrypted_request(Method::GET, effective_path, None, None, extensive)
                .await?
        } else {
            let url_path = if effective_path.is_empty() {
                format!("api/v1/fs/{}", self.dir_id)
            } else {
                format!("api/v1/fs/{}/{}", self.dir_id, effective_path)
            };
            let mut url = self.client.base_url.join(&url_path)?;
            if extensive {
                url.query_pairs_mut()
                    .append_pair("extensive", "true");
            }
            self.send_request_binary(Method::GET, url, vec![], None)
                .await?
        };

        let json_val = self.parse_json_response(resp, sig.as_deref()).await?;
        if json_val.get("items").is_some() {
            let list_resp: ListResponse = serde_json::from_value(json_val)?;
            Ok(list_resp.items)
        } else {
            let meta: Metadata = serde_json::from_value(json_val)?;
            Ok(vec![meta])
        }
    }

    async fn parse_json_response(
        &self,
        resp: reqwest::Response,
        sig: Option<&str>,
    ) -> Result<serde_json::Value> {
        if let (Some(token), Some(sig_str)) = (&self.token, sig)
            && !sig_str.is_empty() {
                let body = resp.bytes().await?;
                let envelope: serde_json::Value = serde_json::from_slice(&body)?;
                let encoded = envelope["message"].as_str().ok_or_else(|| {
                    Error::Api(
                        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                        "Missing 'message' in encrypted response".to_string(),
                    )
                })?;
                let json_bytes = crate::stream::decrypt_json_response(token, sig_str, encoded)?;
                return Ok(serde_json::from_slice(&json_bytes)?);
            }
        Ok(resp.json().await?)
    }

    /// Send a request with path+params in encrypted body (token-mode only).
    async fn send_encrypted_request(
        &self,
        method: Method,
        path: &str,
        offset: Option<u64>,
        length: Option<u64>,
        extensive: bool,
    ) -> Result<(reqwest::Response, Option<String>)> {
        let token = self.token.as_deref().ok_or(Error::TokenRequired)?;
        let url = self.base_url()?;
        let timestamp = unix_timestamp()?;
        let nonce = format!("{:016x}", rand::random::<u64>());
        let signature =
            self.calculate_signature(token, &timestamp, &nonce, &method, &url)?;
        let envelope_body =
            self.encrypt_envelope(token, &signature, path, offset, length, extensive)?;

        let resp = self
            .client
            .client
            .request(method, url)
            .header("Content-Type", "application/vnd.filebridge.request")
            .header("X-Signature", &signature)
            .header("X-Timestamp", timestamp)
            .header("X-Nonce", &nonce)
            .body(envelope_body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Api(status, text));
        }

        let resp_nonce = resp
            .headers()
            .get("X-Nonce")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        if resp_nonce != nonce {
            return Err(Error::NonceMismatch);
        }

        Ok((resp, Some(signature)))
    }

    async fn send_request_binary(
        &self,
        method: Method,
        url: url::Url,
        body_bytes: Vec<u8>,
        precalc_sig: Option<(&str, &str, &str)>,
    ) -> Result<(reqwest::Response, Option<String>)> {
        let (timestamp, nonce, signature) = if let Some((ts, non, sig)) = precalc_sig {
            (ts.to_string(), non.to_string(), sig.to_string())
        } else {
            let ts = unix_timestamp()?;
            let non = format!("{:016x}", rand::random::<u64>());
            let sig = if let Some(token) = &self.token {
                self.calculate_signature(token, &ts, &non, &method, &url)?
            } else {
                String::new()
            };
            (ts, non, sig)
        };

        let mut rb = self.client.client.request(method, url);

        let used_sig: Option<String> = if self.token.is_some() {
            rb = rb
                .header("X-Signature", &signature)
                .header("X-Timestamp", &timestamp)
                .header("X-Nonce", &nonce);
            Some(signature)
        } else {
            None
        };

        if !body_bytes.is_empty() {
            rb = rb
                .header("Content-Type", "application/octet-stream")
                .body(body_bytes);
        }

        let resp = rb.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Api(status, text));
        }

        if self.token.is_some() {
            let resp_nonce = resp
                .headers()
                .get("X-Nonce")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            if resp_nonce != nonce {
                return Err(Error::NonceMismatch);
            }
        }
        Ok((resp, used_sig))
    }

    /// Decrypt a stream response body (DATA + STOP frames) using the signature as IV.
    fn decrypt_stream_content(&self, sig: &str, data: &[u8]) -> Result<Vec<u8>> {
        let token = self.token.as_deref().ok_or(Error::TokenRequired)?;
        let mut aead =
            crate::stream::StreamAead::new(token, sig)?;
        let mut decoder = crate::stream::StreamDecoder::new();
        decoder.push(data);

        let mut result = Vec::new();
        loop {
            match decoder.next_frame()? {
                None => break,
                Some(crate::stream::StreamFrame::Meta { .. }) => {}
                Some(crate::stream::StreamFrame::Data { payload }) => {
                    let mut buf = payload.to_vec();
                    aead.decrypt(&mut buf)?;
                    result.extend_from_slice(&buf);
                }
                Some(crate::stream::StreamFrame::Stop { signature }) => {
                    if let Some(stop_sig) = &signature {
                        aead.verify_stop(stop_sig)?;
                    }
                    break;
                }
            }
        }
        Ok(result)
    }

    fn calculate_signature(
        &self,
        token: &str,
        timestamp: &str,
        nonce: &str,
        method: &Method,
        url: &url::Url,
    ) -> Result<String> {
        let mut mac = HmacSha256::new_from_slice(token.as_bytes()).map_err(|_| Error::Hmac)?;
        mac.update(timestamp.as_bytes());
        mac.update(nonce.as_bytes());
        mac.update(method.as_str().as_bytes());
        mac.update(url.path().as_bytes());
        if let Some(q) = url.query() {
            mac.update(b"?");
            mac.update(q.as_bytes());
        }

        Ok(hex::encode(mac.finalize().into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::FileBridgeClient;
    use sha2::Digest;

    #[test]
    fn test_signature_basic() {
        let client = FileBridgeClient::new("http://localhost:8000").unwrap();
        let loc = client.location("demo", Some("secret".to_string()));
        let url = url::Url::parse("http://localhost:8000/api/v1/fs/demo/test").unwrap();

        let sig = loc
            .calculate_signature(
                "secret",
                "123456789",
                "1234567890abcdef",
                &Method::GET,
                &url,
            )
            .unwrap();

        // Manual check or known good value
        let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
        mac.update(b"123456789");
        mac.update(b"1234567890abcdef");
        mac.update(b"GET");
        mac.update(b"/api/v1/fs/demo/test");
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig, expected);
    }

    #[test]
    fn test_signature_with_query() {
        let client = FileBridgeClient::new("http://localhost:8000").unwrap();
        let loc = client.location("demo", Some("secret".to_string()));
        let url = url::Url::parse("http://localhost:8000/api/v1/fs/demo/test?offset=100&length=50")
            .unwrap();

        let sig = loc
            .calculate_signature(
                "secret",
                "123456789",
                "1234567890abcdef",
                &Method::GET,
                &url,
            )
            .unwrap();

        let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
        mac.update(b"123456789");
        mac.update(b"1234567890abcdef");
        mac.update(b"GET");
        mac.update(b"/api/v1/fs/demo/test?offset=100&length=50");
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig, expected);
    }

    #[test]
    fn test_content_hash_calculation() {
        let test_data = b"Hello, World!";
        let mut hasher = sha2::Sha256::new();
        hasher.update(test_data);
        let hash = format!("{:x}", hasher.finalize());

        // Just verify it's a valid SHA256 hash (64 hex characters)
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Print the hash for verification
        println!("SHA256 of 'Hello, World!': {}", hash);
    }
}
