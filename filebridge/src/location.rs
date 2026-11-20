use crate::Result;
use crate::client::FileBridgeClient;
use crate::error::Error;
use crate::models::{Metadata, Permissions};
use crate::stream::Reply;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

fn unix_timestamp() -> Result<String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            Error::Api(
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                "System clock error".into(),
            )
        })?
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
    /// Destination path, only sent by rename.
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    length: Option<u64>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    extensive: bool,
}

impl<'a> RequestEnvelope<'a> {
    /// Envelope for the single-path operations (read, write, delete, info, list).
    fn for_path(path: &'a str, offset: Option<u64>, length: Option<u64>, extensive: bool) -> Self {
        Self {
            path,
            target: None,
            offset,
            length,
            extensive,
        }
    }
}

/// A signed token-mode request that has not been sent yet.
struct SignedRequest {
    builder: reqwest::RequestBuilder,
    /// Hex signature of the request. Every key of the exchange is derived
    /// from it.
    signature: String,
    nonce: String,
}

impl SignedRequest {
    fn accept(mut self, value: &'static str) -> Self {
        self.builder = self.builder.header("Accept", value);
        self
    }

    fn content_type(mut self, value: &'static str) -> Self {
        self.builder = self.builder.header("Content-Type", value);
        self
    }

    fn body(mut self, body: impl Into<reqwest::Body>) -> Self {
        self.builder = self.builder.body(body);
        self
    }

    /// Set the encrypted `envelope` as the request body.
    fn envelope(self, token: &str, envelope: &RequestEnvelope<'_>) -> Result<Self> {
        let body = encrypt_envelope(token, &self.signature, envelope)?;
        Ok(self
            .content_type("application/vnd.filebridge.request")
            .body(body))
    }
}

/// Encrypt a request envelope for the request with signature `sig`.
fn encrypt_envelope(token: &str, sig: &str, envelope: &RequestEnvelope<'_>) -> Result<String> {
    let json_bytes = serde_json::to_vec(envelope)?;
    Ok(crate::stream::encrypt_json(
        token,
        sig,
        &json_bytes,
        crate::stream::JsonDirection::Request,
    )?)
}

/// Verified response of a location with a token.
enum TokenResponse {
    /// An encrypted file stream. Its frames are verified as they are decrypted.
    Stream {
        response: reqwest::Response,
        signature: String,
    },
    /// A decrypted reply with a success status.
    Reply(Reply),
}

impl TokenResponse {
    fn into_reply(self) -> Result<Reply> {
        match self {
            Self::Reply(reply) => Ok(reply),
            // Nothing of a stream is verified before its frames are
            // decrypted, and nobody is going to decrypt this one.
            Self::Stream { response, .. } => Err(Error::Unverified(
                response.status(),
                "file stream in place of an encrypted response".to_string(),
            )),
        }
    }
}

trait ReplyExt {
    /// The JSON result of the reply.
    fn into_body(self) -> Result<serde_json::Value>;
}

impl ReplyExt for Reply {
    fn into_body(self) -> Result<serde_json::Value> {
        self.body.ok_or_else(|| {
            Error::Api(
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                "Missing result in response".to_string(),
            )
        })
    }
}

/// Longest part of an unverified response body that is put into an error.
const EXCERPT_LEN: usize = 200;

/// The start of an unverified response body, for an error message.
///
/// Anybody on the path can have written this text and it may end up on a
/// terminal, so control characters are replaced.
fn excerpt(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let mut chars = text
        .trim()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c });
    let mut excerpt: String = chars.by_ref().take(EXCERPT_LEN).collect();
    if chars.next().is_some() {
        excerpt.push_str("...");
    }
    excerpt
}

/// Turn the error response of a location without a token into an error.
async fn check_plain_status(resp: reqwest::Response) -> Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    Err(Error::Api(status, text))
}

fn is_json(resp: &reqwest::Response) -> bool {
    resp.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|t| t.contains("application/json"))
}

/// The error for a read that was answered with JSON: the path is a directory,
/// or the server sent metadata where file content was asked for.
fn not_file_content_json(json: &serde_json::Value) -> Error {
    if json.get("items").is_some() {
        return Error::IsDirectory;
    }
    Error::Api(
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "Unexpected JSON metadata instead of file content".to_string(),
    )
}

fn not_file_content(reply: &Reply) -> Error {
    not_file_content_json(reply.body.as_ref().unwrap_or(&serde_json::Value::Null))
}

fn missing_stop() -> Error {
    Error::Stream(crate::stream::StreamError::Truncated)
}

/// Decrypt a complete stream response body (DATA frames and the STOP frame).
///
/// Every DATA frame is authenticated on its own, so a body cut off after any
/// frame still decrypts. Only the STOP frame shows that the stream is whole.
fn decrypt_stream_content(token: &str, sig: &str, data: &[u8]) -> Result<Vec<u8>> {
    let mut aead = crate::stream::StreamAead::new(token, sig)?;
    let mut decoder = crate::stream::StreamDecoder::new();
    decoder.push(data);

    let mut result = Vec::new();
    loop {
        match decoder.next_frame()? {
            None => return Err(missing_stop()),
            Some(crate::stream::StreamFrame::Meta { .. }) => {}
            Some(crate::stream::StreamFrame::Data { payload }) => {
                let mut buf = payload.to_vec();
                aead.decrypt(&mut buf)?;
                result.extend_from_slice(&buf);
            }
            Some(crate::stream::StreamFrame::Stop { signature }) => {
                let stop = signature.ok_or_else(missing_stop)?;
                aead.verify_stop(&stop)?;
                return Ok(result);
            }
        }
    }
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

    /// Reads the entire file at `path` and returns its contents.
    pub async fn read(&self, path: &str) -> Result<Vec<u8>> {
        self._read(path, None, None).await
    }

    /// Reads a byte range from the file at `path`.
    pub async fn read_range(&self, path: &str, offset: u64, length: u64) -> Result<Vec<u8>> {
        self._read(path, Some(offset), Some(length)).await
    }

    async fn _read(&self, path: &str, offset: Option<u64>, length: Option<u64>) -> Result<Vec<u8>> {
        if let Some(token) = &self.token {
            let envelope = RequestEnvelope::for_path(path, offset, length, false);
            let request = self
                .signed(token, Method::GET)?
                .accept("application/vnd.filebridge.stream, application/json")
                .envelope(token, &envelope)?;
            return match self.send_signed(token, request).await? {
                TokenResponse::Stream {
                    response,
                    signature,
                } => {
                    let body = response.bytes().await?;
                    decrypt_stream_content(token, &signature, &body)
                }
                TokenResponse::Reply(reply) => Err(not_file_content(&reply)),
            };
        }

        // No token: path in URL
        let mut url = self.path_url(path)?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(off) = offset {
                query.append_pair("offset", &off.to_string());
            }
            if let Some(len) = length {
                query.append_pair("length", &len.to_string());
            }
        }

        let resp = self
            .client
            .client
            .request(Method::GET, url)
            .header("Accept", "application/octet-stream, application/json")
            .send()
            .await?;
        let resp = check_plain_status(resp).await?;

        if is_json(&resp) {
            return Err(not_file_content_json(&resp.json().await?));
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
        use tokio::io::AsyncWriteExt;

        let Some(token) = &self.token else {
            // No token: use plain octet-stream; stream framing adds no value without encryption
            // and avoids triggering the server's Content-Length calculation for framed responses.
            let resp = self
                .client
                .client
                .request(Method::GET, self.path_url(path)?)
                .header("Accept", "application/octet-stream, application/json")
                .send()
                .await?;
            let mut resp = check_plain_status(resp).await?;

            if is_json(&resp) {
                return Err(not_file_content_json(&resp.json().await?));
            }
            while let Some(chunk) = resp.chunk().await? {
                writer.write_all(&chunk).await?;
            }
            return Ok(None);
        };

        let envelope = RequestEnvelope::for_path(path, None, None, false);
        let request = self
            .signed(token, Method::GET)?
            .accept("application/vnd.filebridge.stream")
            .envelope(token, &envelope)?;
        let (mut resp, signature) = match self.send_signed(token, request).await? {
            TokenResponse::Stream {
                response,
                signature,
            } => (response, signature),
            TokenResponse::Reply(reply) => return Err(not_file_content(&reply)),
        };

        use crate::stream::{StreamDecoder, StreamFrame};

        let mut aead = crate::stream::StreamAead::new(token, &signature)?;
        let mut decoder = StreamDecoder::new();
        let mut server_stop: Option<String> = None;
        let mut decrypt_buf: Vec<u8> = Vec::with_capacity(64 * 1024 + 16 + 1);

        while let Some(chunk) = resp.chunk().await? {
            decoder.push(&chunk);

            while let Some(frame) = decoder.next_frame()? {
                match frame {
                    StreamFrame::Meta { .. } => {
                        // META frames are not expected in read responses
                    }
                    StreamFrame::Data { payload } => {
                        decrypt_buf.clear();
                        decrypt_buf.extend_from_slice(&payload);
                        aead.decrypt(&mut decrypt_buf)?;
                        writer.write_all(&decrypt_buf).await?;
                    }
                    StreamFrame::Stop { signature } => {
                        server_stop = signature;
                    }
                }
            }
        }

        let Some(stop) = server_stop else {
            return Err(missing_stop());
        };
        aead.verify_stop(&stop)?;
        Ok(Some(stop))
    }

    /// Streams data from the provided async reader into a file at `path`.
    pub async fn write_stream<R: tokio::io::AsyncRead + std::marker::Unpin + Send + 'static>(
        &self,
        path: &str,
        mut reader: R,
    ) -> Result<()> {
        let Some(token) = &self.token else {
            let stream = async_stream::stream! {
                let mut buf = vec![0; 64 * 1024];
                use tokio::io::AsyncReadExt;
                loop {
                    match reader.read(&mut buf).await {
                        Ok(0) => {
                            yield Ok::<_, std::io::Error>(bytes::Bytes::from(crate::stream::encode_stop(None)));
                            break;
                        }
                        Ok(n) => {
                            yield Ok::<_, std::io::Error>(bytes::Bytes::from(crate::stream::encode_data(&buf[..n])));
                        }
                        Err(e) => {
                            yield Err(e);
                            break;
                        }
                    }
                }
            };
            let resp = self
                .client
                .client
                .request(Method::PUT, self.path_url(path)?)
                .header("Content-Type", "application/vnd.filebridge.stream")
                .body(reqwest::Body::wrap_stream(stream))
                .send()
                .await?;
            check_plain_status(resp).await?;
            return Ok(());
        };

        // Token mode: URL is just /api/v1/fs/{dir_id}, path in the META frame
        let request = self.signed(token, Method::PUT)?;
        let meta = encrypt_envelope(
            token,
            &request.signature,
            &RequestEnvelope::for_path(path, None, None, false),
        )?;
        let mut aead = crate::stream::StreamAead::new(token, &request.signature)?;

        let stream = async_stream::stream! {
            yield Ok::<_, std::io::Error>(bytes::Bytes::from(crate::stream::encode_meta(meta.as_bytes())));

            let mut buf = vec![0; 64 * 1024];
            let mut chunk: Vec<u8> = Vec::with_capacity(64 * 1024 + 16 + 1);
            use tokio::io::AsyncReadExt;
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => {
                        match aead.finalize() {
                            Ok(stop) => yield Ok(bytes::Bytes::from(crate::stream::encode_stop(Some(&stop)))),
                            Err(_) => yield Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Encryption failed")),
                        }
                        break;
                    }
                    Ok(n) => {
                        chunk.clear();
                        chunk.extend_from_slice(&buf[..n]);
                        if aead.encrypt(&mut chunk).is_err() {
                            yield Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Encryption failed"));
                            break;
                        }
                        yield Ok(bytes::Bytes::from(crate::stream::encode_data(&chunk)));
                    }
                    Err(e) => {
                        yield Err(e);
                        break;
                    }
                }
            }
        };

        let request = request
            .content_type("application/vnd.filebridge.stream")
            .body(reqwest::Body::wrap_stream(stream));
        self.send_signed(token, request).await?.into_reply()?;
        Ok(())
    }

    /// Writes `data` to the file at `path`, optionally starting at `offset`.
    pub async fn write(&self, path: &str, data: &[u8], offset: Option<u64>) -> Result<()> {
        let Some(token) = &self.token else {
            // No token: path in URL
            let mut url = self.path_url(path)?;
            if let Some(off) = offset {
                url.query_pairs_mut()
                    .append_pair("offset", &off.to_string());
            }
            self.send_plain(Method::PUT, url, data.to_vec()).await?;
            return Ok(());
        };

        // Token mode: use stream format with META frame, path in encrypted body
        let request = self.signed(token, Method::PUT)?;
        let meta = encrypt_envelope(
            token,
            &request.signature,
            &RequestEnvelope::for_path(path, offset, None, false),
        )?;

        // Build stream body: META + DATA chunks + STOP
        let mut body_buf = Vec::new();
        body_buf.extend_from_slice(&crate::stream::encode_meta(meta.as_bytes()));

        let mut aead = crate::stream::StreamAead::new(token, &request.signature)?;
        const CHUNK_SIZE: usize = 64 * 1024;
        for chunk in data.chunks(CHUNK_SIZE) {
            let mut chunk = chunk.to_vec();
            aead.encrypt(&mut chunk)?;
            body_buf.extend_from_slice(&crate::stream::encode_data(&chunk));
        }
        let stop_sig = aead.finalize()?;
        body_buf.extend_from_slice(&crate::stream::encode_stop(Some(&stop_sig)));

        let request = request
            .content_type("application/vnd.filebridge.stream")
            .body(body_buf);
        self.send_signed(token, request).await?.into_reply()?;
        Ok(())
    }

    /// Deletes the file at `path`.
    pub async fn delete(&self, path: &str) -> Result<()> {
        if self.token.is_some() {
            self.send_envelope(
                Method::DELETE,
                RequestEnvelope::for_path(path, None, None, false),
            )
            .await?;
        } else {
            self.send_plain(Method::DELETE, self.path_url(path)?, vec![])
                .await?;
        }
        Ok(())
    }

    /// Renames (moves) the file at `from` to `to` within this location.
    ///
    /// Both paths are relative to the location root; moving across locations is
    /// not supported. Only regular files can be renamed — directories are
    /// rejected by the server.
    ///
    /// An existing target is replaced, which the location must permit via
    /// `allow_replace`. The operation itself needs `allow_create` and
    /// `allow_delete`.
    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        if self.token.is_some() {
            self.send_envelope(
                Method::POST,
                RequestEnvelope {
                    path: from,
                    target: Some(to),
                    offset: None,
                    length: None,
                    extensive: false,
                },
            )
            .await?;
        } else {
            let mut url = self.path_url(from)?;
            url.query_pairs_mut().append_pair("target", to);
            self.send_plain(Method::POST, url, vec![]).await?;
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
        Ok(serde_json::from_value(
            self.get_json(path, extensive).await?,
        )?)
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
        let json_val = self.get_json(path.unwrap_or(""), extensive).await?;
        if json_val.get("items").is_some() {
            let list_resp: ListResponse = serde_json::from_value(json_val)?;
            Ok(list_resp.items)
        } else {
            let meta: Metadata = serde_json::from_value(json_val)?;
            Ok(vec![meta])
        }
    }

    /// Fetch the JSON the server has for `path`: the metadata of a file or
    /// the listing of a directory.
    async fn get_json(&self, path: &str, extensive: bool) -> Result<serde_json::Value> {
        if self.token.is_some() {
            return self
                .send_envelope(
                    Method::GET,
                    RequestEnvelope::for_path(path, None, None, extensive),
                )
                .await?
                .into_body();
        }

        let mut url = if path.is_empty() {
            self.base_url()?
        } else {
            self.path_url(path)?
        };
        if extensive {
            url.query_pairs_mut().append_pair("extensive", "true");
        }
        Ok(self
            .send_plain(Method::GET, url, vec![])
            .await?
            .json()
            .await?)
    }

    /// URL of `path` in this location (used without a token).
    fn path_url(&self, path: &str) -> Result<url::Url> {
        Ok(self
            .client
            .base_url
            .join(&format!("api/v1/fs/{}/{}", self.dir_id, path))?)
    }

    /// Start a token-mode request: sign it and set the authentication headers.
    fn signed(&self, token: &str, method: Method) -> Result<SignedRequest> {
        let url = self.base_url()?;
        let timestamp = unix_timestamp()?;
        let nonce = format!("{:016x}", rand::random::<u64>());
        let signature = self.calculate_signature(token, &timestamp, &nonce, &method, &url)?;
        let builder = self
            .client
            .client
            .request(method, url)
            .header("X-Signature", &signature)
            .header("X-Timestamp", timestamp)
            .header("X-Nonce", &nonce);
        Ok(SignedRequest {
            builder,
            signature,
            nonce,
        })
    }

    /// Send a token-mode request and verify the response.
    ///
    /// Returns only what the server provably sent in answer to this request:
    /// an encrypted file stream, whose frames the caller still has to decrypt,
    /// or a decrypted reply with a success status. A reply with an error
    /// status becomes [`Error::Api`], anything else [`Error::Unverified`].
    async fn send_signed(&self, token: &str, request: SignedRequest) -> Result<TokenResponse> {
        let SignedRequest {
            builder,
            signature,
            nonce,
        } = request;
        let response = builder.send().await?;

        let status = response.status();
        let nonce_matches = response
            .headers()
            .get("X-Nonce")
            .and_then(|h| h.to_str().ok())
            == Some(nonce.as_str());
        let is_stream = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|t| t.contains("application/vnd.filebridge.stream"));

        if status.is_success() && is_stream {
            if !nonce_matches {
                return Err(Error::NonceMismatch);
            }
            return Ok(TokenResponse::Stream {
                response,
                signature,
            });
        }

        let body = response.bytes().await?;
        let Ok(reply) = crate::stream::open_reply(token, &signature, &body) else {
            return Err(Error::Unverified(status, excerpt(&body)));
        };
        if !nonce_matches {
            return Err(Error::NonceMismatch);
        }
        if reply.status >= 400 {
            return Err(Error::Api(
                reqwest::StatusCode::from_u16(reply.status)
                    .unwrap_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
                reply.error.unwrap_or_default(),
            ));
        }
        Ok(TokenResponse::Reply(reply))
    }

    /// Send a request with path and parameters in the encrypted body
    /// (token-mode only) and return the server's reply.
    async fn send_envelope(&self, method: Method, envelope: RequestEnvelope<'_>) -> Result<Reply> {
        let token = self.token.as_deref().ok_or(Error::TokenRequired)?;
        let request = self.signed(token, method)?.envelope(token, &envelope)?;
        self.send_signed(token, request).await?.into_reply()
    }

    /// Send a request to a location without a token.
    async fn send_plain(
        &self,
        method: Method,
        url: url::Url,
        body_bytes: Vec<u8>,
    ) -> Result<reqwest::Response> {
        let mut rb = self.client.client.request(method, url);
        if !body_bytes.is_empty() {
            rb = rb
                .header("Content-Type", "application/octet-stream")
                .body(body_bytes);
        }
        check_plain_status(rb.send().await?).await
    }

    fn calculate_signature(
        &self,
        token: &str,
        timestamp: &str,
        nonce: &str,
        method: &Method,
        url: &url::Url,
    ) -> Result<String> {
        let mut uri = url.path().to_owned();
        if let Some(q) = url.query() {
            uri.push('?');
            uri.push_str(q);
        }
        let signature =
            crate::stream::request_signature(token, timestamp, nonce, method.as_str(), &uri)
                .map_err(|_| Error::Hmac)?;
        Ok(hex::encode(signature))
    }

    /// Returns the set of permissions the server grants for this location.
    ///
    /// The values reflect the server-side configuration at the time of the
    /// call. They are advisory — operations will still be checked against
    /// the server's current state — but the client can use them to skip
    /// operations it isn't allowed to perform.
    pub async fn permissions(&self) -> Result<Permissions> {
        let json_val: serde_json::Value = if let Some(token) = &self.token {
            let request = self.signed(token, Method::OPTIONS)?;
            self.send_signed(token, request)
                .await?
                .into_reply()?
                .into_body()?
        } else {
            self.send_plain(Method::OPTIONS, self.base_url()?, vec![])
                .await?
                .json()
                .await?
        };
        let perms = json_val.get("permissions").ok_or_else(|| {
            Error::Api(
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                "missing 'permissions' field in response".to_string(),
            )
        })?;
        Ok(serde_json::from_value(perms.clone())?)
    }

    /// Match remote files against a glob pattern.
    ///
    /// Supports `*`, `?`, `[seq]`, and recursive `**` patterns.  The pattern
    /// is resolved relative to this location's root directory.
    pub async fn glob(&self, pattern: &str) -> Result<Vec<crate::glob::GlobEntry>> {
        crate::glob::glob(self, pattern).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::FileBridgeClient;

    #[test]
    fn test_excerpt() {
        assert_eq!(excerpt(b"  invalid signature\n"), "invalid signature");
        assert_eq!(excerpt(b"a\x1b[31mb\r\nc"), "a [31mb  c");
        assert_eq!(excerpt(b""), "");

        let long = excerpt("\u{e4}".repeat(EXCERPT_LEN + 1).as_bytes());
        assert_eq!(long.chars().count(), EXCERPT_LEN + 3);
        assert!(long.ends_with("..."));
        assert_eq!(
            excerpt("x".repeat(EXCERPT_LEN).as_bytes()).len(),
            EXCERPT_LEN
        );
    }
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    type HmacSha256 = Hmac<Sha256>;

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
        mac.update(crate::stream::SIGNATURE_CONTEXT);
        mac.update(b"123456789\n1234567890abcdef\nGET\n");
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
        mac.update(crate::stream::SIGNATURE_CONTEXT);
        mac.update(b"123456789\n1234567890abcdef\nGET\n");
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
