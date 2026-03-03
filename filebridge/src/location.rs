use crate::client::FileBridgeClient;
use crate::error::Error;
use crate::models::Metadata;
use crate::Result;
use hmac::{Hmac, Mac};
use reqwest::Method;
use serde::Deserialize;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub struct FileBridgeLocation<'a> {
    client: &'a FileBridgeClient,
    dir_id: String,
    token: Option<String>,
}

#[derive(Deserialize)]
struct ListResponse {
    items: Vec<Metadata>,
}

impl<'a> FileBridgeLocation<'a> {
    pub fn new(client: &'a FileBridgeClient, dir_id: &str, token: Option<String>) -> Self {
        Self {
            client,
            dir_id: dir_id.to_string(),
            token,
        }
    }

    pub async fn read(
        &self,
        path: &str,
        offset: Option<u64>,
        length: Option<u64>,
    ) -> Result<Vec<u8>> {
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

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();

        let mut rb = self
            .client
            .client
            .request(Method::GET, url.clone())
            .header("Accept", "application/octet-stream, application/json");

        if let Some(token) = &self.token {
            let nonce = format!("{:016x}", rand::random::<u64>());
            let signature =
                self.calculate_signature(token, &timestamp, &nonce, &Method::GET, &url)?;
            let sig_for_decrypt = signature.clone();
            rb = rb
                .header("X-Signature", signature)
                .header("X-Timestamp", timestamp)
                .header("X-Nonce", &nonce);

            let resp = rb.send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(Error::Api(status, text));
            }
            // Verify Nonce
            let resp_nonce = resp
                .headers()
                .get("X-Nonce")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            if resp_nonce != nonce {
                return Err(Error::Hmac);
            }
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");

            if content_type.contains("application/json") {
                let json_val = self
                    .parse_json_response(resp, Some(&sig_for_decrypt))
                    .await?;
                if json_val.get("items").is_some() {
                    return Err(Error::IsDirectory);
                }

                return Err(Error::Api(
                    reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                    "Unexpected JSON metadata instead of file content".to_string(),
                ));
            }

            // Default: Octet Stream
            return Ok(resp.bytes().await?.to_vec());
        }

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

        // Default: Octet Stream
        Ok(resp.bytes().await?.to_vec())
    }

    pub async fn read_stream<W: tokio::io::AsyncWrite + std::marker::Unpin>(
        &self,
        path: &str,
        mut writer: W,
    ) -> Result<Option<String>> {
        let url = self
            .client
            .base_url
            .join(&format!("api/v1/fs/{}/{}", self.dir_id, path))?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();

        let mut rb = self
            .client
            .client
            .request(Method::GET, url.clone())
            .header("Accept", "application/vnd.filebridge.stream");

        let mut req_sig = String::new();
        let mut req_nonce = String::new();
        if let Some(token) = &self.token {
            let nonce = format!("{:016x}", rand::random::<u64>());
            req_nonce = nonce.clone();
            let signature =
                self.calculate_signature(token, &timestamp, &nonce, &Method::GET, &url)?;
            req_sig = signature.clone();
            rb = rb
                .header("X-Signature", signature)
                .header("X-Timestamp", timestamp)
                .header("X-Nonce", nonce);
        }

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
                return Err(Error::Hmac);
            }
        }
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

        let mut aead: Option<crate::stream::StreamAead> = None;
        if let Some(token_str) = &self.token
            && !req_sig.is_empty() {
                aead = match crate::stream::StreamAead::new(token_str, &req_sig) {
                    Ok(a) => Some(a),
                    Err(_) => return Err(Error::Hmac),
                };
            }

        use crate::stream::{StreamDecoder, StreamFrame};
        use tokio::io::AsyncWriteExt;

        let expects_hmac = self.token.is_some() && !req_sig.is_empty();
        let mut decoder = StreamDecoder::new();
        let mut server_stop_hmac: Option<String> = None;
        let mut decrypt_buf: Vec<u8> = Vec::with_capacity(64 * 1024 + 16 + 1);

        while let Some(chunk) = resp.chunk().await? {
            decoder.push(&chunk);

            while let Some(frame) = decoder.next_frame().map_err(|e| {
                Error::Api(reqwest::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            })? {
                match frame {
                    StreamFrame::Data { payload } => {
                        if expects_hmac {
                            if let Some(ref mut a) = aead {
                                decrypt_buf.clear();
                                decrypt_buf.extend_from_slice(&payload);
                                if a.decrypt(&mut decrypt_buf).is_err() {
                                    return Err(Error::Hmac);
                                }
                                writer.write_all(&decrypt_buf).await?;
                            } else {
                                return Err(Error::Hmac);
                            }
                        } else {
                            writer.write_all(&payload).await?;
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
                if a.verify_stop(remote_stop).is_err() {
                    return Err(Error::Hmac);
                }
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

    pub async fn write_stream<R: tokio::io::AsyncRead + std::marker::Unpin + Send + 'static>(
        &self,
        path: &str,
        mut reader: R,
    ) -> Result<()> {
        let url = self
            .client
            .base_url
            .join(&format!("api/v1/fs/{}/{}", self.dir_id, path))?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();

        let mut rb = self
            .client
            .client
            .request(Method::PUT, url.clone())
            .header("Content-Type", "application/vnd.filebridge.stream");

        let mut req_sig = String::new();
        let mut req_nonce = String::new();
        if let Some(token) = &self.token {
            let nonce = format!("{:016x}", rand::random::<u64>());
            req_nonce = nonce.clone();
            let signature =
                self.calculate_signature(token, &timestamp, &nonce, &Method::PUT, &url)?;
            req_sig = signature.clone();
            rb = rb
                .header("X-Signature", signature)
                .header("X-Timestamp", timestamp)
                .header("X-Nonce", nonce);
        }

        let token_opt = self.token.clone();

        let req_sig_clone = req_sig.clone();
        let stream = async_stream::stream! {
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

        rb = rb.body(reqwest::Body::wrap_stream(stream));
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
                return Err(Error::Hmac);
            }
        }

        Ok(())
    }

    pub async fn write(&self, path: &str, data: &[u8], offset: Option<u64>) -> Result<()> {
        let mut url = self
            .client
            .base_url
            .join(&format!("api/v1/fs/{}/{}", self.dir_id, path))?;
        if let Some(off) = offset {
            url.query_pairs_mut()
                .append_pair("offset", &off.to_string());
        }

        let mut precalc_sig = None;
        let req_nonce: String;
        let req_sig: String;
        let req_ts: String;

        if let Some(token) = &self.token {
            req_ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string();
            req_nonce = format!("{:016x}", rand::random::<u64>());
            req_sig = self.calculate_signature(token, &req_ts, &req_nonce, &Method::PUT, &url)?;
            precalc_sig = Some((req_ts.as_str(), req_nonce.as_str(), req_sig.as_str()));
        }

        self.send_request_binary(
            Method::PUT,
            url,
            data.to_vec(),
            precalc_sig,
        )
        .await?;
        Ok(())
    }

    pub async fn delete(&self, path: &str) -> Result<()> {
        let url = self
            .client
            .base_url
            .join(&format!("api/v1/fs/{}/{}", self.dir_id, path))?;
        self.send_request_binary(Method::DELETE, url, vec![], None)
            .await?;
        Ok(())
    }

    pub async fn info(&self, path: &str) -> Result<Metadata> {
        let url = self
            .client
            .base_url
            .join(&format!("api/v1/fs/{}/{}", self.dir_id, path))?;
        let (resp, sig) = self
            .send_request_binary(Method::GET, url, vec![], None)
            .await?;
        let json_val = self.parse_json_response(resp, sig.as_deref()).await?;
        Ok(serde_json::from_value(json_val)?)
    }

    pub async fn list(&self, path: Option<&str>) -> Result<Vec<Metadata>> {
        let url_path = if let Some(p) = path {
            format!("api/v1/fs/{}/{}", self.dir_id, p)
        } else {
            format!("api/v1/fs/{}", self.dir_id)
        };
        let url = self.client.base_url.join(&url_path)?;
        let (resp, sig) = self
            .send_request_binary(Method::GET, url, vec![], None)
            .await?;

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
                let json_bytes = crate::stream::decrypt_json_response(token, sig_str, encoded)
                    .map_err(|e| {
                        Error::Api(
                            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Decryption failed: {}", e),
                        )
                    })?;
                return Ok(serde_json::from_slice(&json_bytes)?);
            }
        Ok(resp.json().await?)
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
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string();
            let non = format!("{:016x}", rand::random::<u64>());
            let sig = if let Some(token) = &self.token {
                self.calculate_signature(token, &ts, &non, &method, &url)?
            } else {
                "".to_string()
            };
            (ts, non, sig)
        };

        let used_sig: Option<String> = if self.token.is_some() {
            Some(signature.clone())
        } else {
            None
        };

        let mut rb = self.client.client.request(method.clone(), url.clone());

        if self.token.is_some() {
            rb = rb
                .header("X-Signature", signature)
                .header("X-Timestamp", timestamp)
                .header("X-Nonce", &nonce);
        }

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
                return Err(Error::Hmac);
            }
        }
        Ok((resp, used_sig))
    }

    fn calculate_signature(
        &self,
        token: &str,
        timestamp: &str,
        nonce: &str,
        method: &Method,
        url: &url::Url,
    ) -> Result<String> {
        let full_path = url.path();
        let query = url.query();
        let uri_to_sign = if let Some(q) = query {
            format!("{}?{}", full_path, q)
        } else {
            full_path.to_string()
        };

        let mut mac = HmacSha256::new_from_slice(token.as_bytes()).map_err(|_| Error::Hmac)?;
        mac.update(timestamp.as_bytes());
        mac.update(nonce.as_bytes());
        mac.update(method.as_str().as_bytes());
        mac.update(uri_to_sign.as_bytes());

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
