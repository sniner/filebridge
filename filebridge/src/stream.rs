//! Streaming protocol and encryption primitives for the Filebridge wire format.

use bytes::{Buf, Bytes, BytesMut};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

/// Maximum accepted payload length for a single stream frame.
///
/// Legitimate frames never exceed the 64 KiB chunk size plus the 16-byte AEAD
/// tag; META envelopes and STOP tags are far smaller. The 1 MiB ceiling leaves
/// generous headroom while preventing a malicious 32-bit length field from
/// making the decoder buffer up to 4 GiB before a single frame completes.
pub const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum StreamError {
    #[error("Invalid stream frame tag: {0:?}")]
    InvalidTag([u8; 4]),
    #[error("Stream frame too large: {0} bytes (max {MAX_FRAME_PAYLOAD})")]
    FrameTooLarge(usize),
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    #[error("HKDF error: {0}")]
    Hkdf(&'static str),
    #[error("Malformed encrypted response: {0}")]
    MalformedReply(String),
    #[error("Stream ended before its STOP frame")]
    Truncated,
    #[error("Decompressed request larger than {MAX_REQUEST_JSON} bytes")]
    RequestTooLarge,
}

/// Largest decompressed request envelope that is accepted.
///
/// An envelope holds one or two paths and a few numbers. The limit keeps a
/// small compressed request from growing into gigabytes when the server
/// unpacks it. Responses have no such limit: a directory listing can be large,
/// and a client only unpacks what the server it trusts with the token sent.
pub const MAX_REQUEST_JSON: usize = 1024 * 1024;

/// First input of the request signature.
///
/// It names the release that introduced the current token-mode wire format. A
/// client and a server that disagree on the format compute different
/// signatures, so the server refuses the request with `401` and neither side
/// gets to misread a message of the other format. Every key is derived from the
/// signature, so the formats share no key either.
pub const SIGNATURE_CONTEXT: &[u8] = b"filebridge-0.5\n";

/// Compute the signature of a token-mode request.
///
/// `uri` is the URL path, followed by `?` and the query if there is one.
///
/// The fields are signed one per line. None of them can contain a line break,
/// so two different requests never produce the same signed data. That matters
/// beyond authentication: the keys of the response are derived from the
/// signature, and a second request with the same signature would get a second
/// response under the same key and nonce.
///
/// # Errors
///
/// [`StreamError::CryptoError`] if `token` is refused as an HMAC key. HMAC
/// takes a key of any length, so no token is.
pub fn request_signature(
    token: &str,
    timestamp: &str,
    nonce: &str,
    method: &str,
    uri: &str,
) -> Result<[u8; 32], StreamError> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(token.as_bytes())
        .map_err(|_| StreamError::CryptoError("HMAC key setup failed".to_string()))?;
    mac.update(SIGNATURE_CONTEXT);
    for field in [timestamp, nonce, method] {
        mac.update(field.as_bytes());
        mac.update(b"\n");
    }
    mac.update(uri.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

pub enum StreamFrame {
    Meta { payload: Bytes },
    Data { payload: Bytes },
    Stop { signature: Option<String> }, // signature is the final AEAD tag hex
}

/// The length field of a frame with this payload.
///
/// A frame cannot hold more than `u32::MAX` bytes, and a cast would write a
/// length that does not belong to the payload.
fn frame_len(payload: &[u8]) -> [u8; 4] {
    u32::try_from(payload.len())
        .expect("frame payload longer than u32::MAX bytes")
        .to_be_bytes()
}

/// Encodes a META frame.
///
/// # Panics
///
/// If `payload` is longer than `u32::MAX` bytes. A decoder refuses a frame
/// above [`MAX_FRAME_PAYLOAD`] anyway.
#[must_use]
pub fn encode_meta(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(8 + payload.len());
    frame.extend_from_slice(b"META");
    frame.extend_from_slice(&frame_len(payload));
    frame.extend_from_slice(payload);
    frame
}

/// Encodes a DATA frame.
///
/// # Panics
///
/// If `payload` is longer than `u32::MAX` bytes. A decoder refuses a frame
/// above [`MAX_FRAME_PAYLOAD`] anyway.
#[must_use]
pub fn encode_data(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(8 + payload.len());
    frame.extend_from_slice(b"DATA");
    frame.extend_from_slice(&frame_len(payload));
    frame.extend_from_slice(payload);
    frame
}

/// Encodes a STOP frame, with the signature of the stream if it is encrypted.
#[must_use]
pub fn encode_stop(signature: Option<&str>) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(b"STOP");
    if let Some(sig) = signature {
        let sig_bytes = sig.as_bytes();
        frame.extend_from_slice(&frame_len(sig_bytes));
        frame.extend_from_slice(sig_bytes);
    } else {
        frame.extend_from_slice(&(0u32).to_be_bytes());
    }
    frame
}

pub struct StreamDecoder {
    buffer: BytesMut,
}

impl Default for StreamDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
        }
    }

    pub fn push(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
    }

    /// Return any remaining unprocessed bytes in the buffer.
    #[must_use]
    pub fn remaining(&self) -> &[u8] {
        &self.buffer
    }

    /// Takes the next complete frame out of the buffer. Returns `None` if the
    /// buffer does not hold a whole frame yet.
    ///
    /// # Errors
    ///
    /// [`StreamError::FrameTooLarge`] for a frame that announces more than
    /// [`MAX_FRAME_PAYLOAD`] bytes, [`StreamError::InvalidTag`] for a frame of
    /// an unknown kind, and [`StreamError::CryptoError`] for a STOP frame
    /// whose signature is not text.
    pub fn next_frame(&mut self) -> Result<Option<StreamFrame>, StreamError> {
        if self.buffer.len() < 8 {
            return Ok(None);
        }

        let mut tag = [0u8; 4];
        tag.copy_from_slice(&self.buffer[0..4]);

        let length = u32::from_be_bytes([
            self.buffer[4],
            self.buffer[5],
            self.buffer[6],
            self.buffer[7],
        ]) as usize;

        // Reject oversized frames before buffering, so a bogus length field
        // cannot drive unbounded memory growth.
        if length > MAX_FRAME_PAYLOAD {
            return Err(StreamError::FrameTooLarge(length));
        }

        if self.buffer.len() < 8 + length {
            return Ok(None);
        }

        self.buffer.advance(8);
        let payload = self.buffer.split_to(length);

        match &tag {
            b"META" => Ok(Some(StreamFrame::Meta {
                payload: payload.freeze(),
            })),
            b"DATA" => Ok(Some(StreamFrame::Data {
                payload: payload.freeze(),
            })),
            b"STOP" => {
                let sig = if length > 0 {
                    Some(String::from_utf8(payload.to_vec()).map_err(|_| {
                        StreamError::CryptoError(
                            "Invalid UTF-8 in STOP frame signature".to_string(),
                        )
                    })?)
                } else {
                    None
                };
                Ok(Some(StreamFrame::Stop { signature: sig }))
            }
            _ => Err(StreamError::InvalidTag(tag)),
        }
    }
}

/// Derive key and nonce base for stream AEAD encryption/decryption.
fn derive_stream_key_nonce(token: &str, iv_hex: &str) -> Result<([u8; 32], [u8; 12]), StreamError> {
    if iv_hex.is_empty() {
        return Err(StreamError::Hkdf("iv_hex must not be empty"));
    }
    let hk = Hkdf::<Sha256>::new(Some(iv_hex.as_bytes()), token.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"filebridge-stream-key", &mut key)
        .map_err(|_| StreamError::Hkdf("expand failed for stream key"))?;
    let mut nonce_base = [0u8; 12];
    hk.expand(b"filebridge-stream-nonce", &mut nonce_base)
        .map_err(|_| StreamError::Hkdf("expand failed for stream nonce"))?;
    Ok((key, nonce_base))
}

/// Direction of an encrypted JSON payload.
///
/// Request envelopes (client → server) and JSON responses (server → client)
/// are encrypted under the same `(token, signature)` pair. Deriving a separate
/// key and nonce per direction guarantees each derived `(key, nonce)` encrypts
/// at most one message, ruling out nonce reuse across the two directions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonDirection {
    /// Client → server request envelope.
    Request,
    /// Server → client JSON response.
    Response,
}

impl JsonDirection {
    fn hkdf_infos(self) -> (&'static [u8], &'static [u8]) {
        match self {
            Self::Request => (
                b"filebridge-json-request-key",
                b"filebridge-json-request-nonce",
            ),
            Self::Response => (
                b"filebridge-json-response-key",
                b"filebridge-json-response-nonce",
            ),
        }
    }
}

/// Derive key and nonce for encrypted JSON payloads.
/// Uses different info strings than stream AEAD for purpose separation, and
/// different info strings per direction to prevent nonce reuse.
fn derive_json_key_nonce(
    token: &str,
    iv_hex: &str,
    direction: JsonDirection,
) -> Result<([u8; 32], [u8; 12]), StreamError> {
    if iv_hex.is_empty() {
        return Err(StreamError::Hkdf("iv_hex must not be empty"));
    }
    let (key_info, nonce_info) = direction.hkdf_infos();
    let hk = Hkdf::<Sha256>::new(Some(iv_hex.as_bytes()), token.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(key_info, &mut key)
        .map_err(|_| StreamError::Hkdf("expand failed for JSON key"))?;
    let mut nonce = [0u8; 12];
    hk.expand(nonce_info, &mut nonce)
        .map_err(|_| StreamError::Hkdf("expand failed for JSON nonce"))?;
    Ok((key, nonce))
}

pub struct StreamAead {
    cipher: ChaCha20Poly1305,
    nonce_base: [u8; 12],
    counter: u64,
}

impl StreamAead {
    /// Derives the cipher of a file stream from the token and the signature
    /// of the request, `iv_hex`.
    ///
    /// # Errors
    ///
    /// [`StreamError::Hkdf`] if `iv_hex` is empty.
    pub fn new(token: &str, iv_hex: &str) -> Result<Self, StreamError> {
        let (key, nonce_base) = derive_stream_key_nonce(token, iv_hex)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

        Ok(Self {
            cipher,
            nonce_base,
            counter: 0,
        })
    }

    fn current_nonce(&self) -> [u8; 12] {
        let mut nonce_bytes = self.nonce_base;
        let counter_bytes = self.counter.to_be_bytes(); // 8 bytes
        for i in 0..8 {
            nonce_bytes[4 + i] ^= counter_bytes[i];
        }
        nonce_bytes
    }

    /// Encrypts `data` in place as the next frame of the stream and appends
    /// its authentication tag.
    ///
    /// # Errors
    ///
    /// [`StreamError::CryptoError`] if the cipher refuses `data`.
    pub fn encrypt(&mut self, data: &mut Vec<u8>) -> Result<(), StreamError> {
        let binding = self.current_nonce();
        let nonce = Nonce::from_slice(&binding);
        self.cipher
            .encrypt_in_place(nonce, b"", data)
            .map_err(|e| StreamError::CryptoError(format!("Encryption failed: {e}")))?;
        self.counter += 1;
        Ok(())
    }

    /// Decrypts `data` in place as the next frame of the stream and removes
    /// its authentication tag.
    ///
    /// # Errors
    ///
    /// [`StreamError::CryptoError`] if `data` is not the next frame of this
    /// stream: it was altered, or a frame before it is missing or out of
    /// order.
    pub fn decrypt(&mut self, data: &mut Vec<u8>) -> Result<(), StreamError> {
        let binding = self.current_nonce();
        let nonce = Nonce::from_slice(&binding);
        self.cipher
            .decrypt_in_place(nonce, b"", data)
            .map_err(|e| StreamError::CryptoError(format!("Decryption failed: {e}")))?;
        self.counter += 1;
        Ok(())
    }

    /// Returns the signature for the STOP frame as hex. It covers the number
    /// of frames encrypted so far.
    ///
    /// # Errors
    ///
    /// [`StreamError::CryptoError`] if the cipher fails.
    pub fn finalize(&mut self) -> Result<String, StreamError> {
        let mut final_block = Vec::new();
        self.encrypt(&mut final_block)?;
        Ok(hex::encode(final_block))
    }

    /// Checks the signature of a STOP frame against the frames decrypted so
    /// far.
    ///
    /// # Errors
    ///
    /// [`StreamError::CryptoError`] if `hex_sig` is not hex or does not belong
    /// to this stream at this point, as when frames are missing at the end.
    pub fn verify_stop(&mut self, hex_sig: &str) -> Result<(), StreamError> {
        let mut final_block = hex::decode(hex_sig)
            .map_err(|e| StreamError::CryptoError(format!("Invalid hex in stop signature: {e}")))?;
        self.decrypt(&mut final_block)?;
        Ok(())
    }
}

/// Encrypted JSON payloads are padded to a multiple of this many bytes.
///
/// Without padding the length of a request shows the length of its path, and
/// the length of a response shows which of the short replies it is: an error,
/// an acknowledgement or the metadata of a file.
const PAD_BLOCK: usize = 256;

/// Pad `data` to a multiple of [`PAD_BLOCK`] with a `0x80` byte followed by
/// zero bytes (ISO/IEC 7816-4).
fn pad(data: &mut Vec<u8>) {
    data.push(0x80);
    data.resize(data.len().next_multiple_of(PAD_BLOCK), 0);
}

fn unpad(data: &mut Vec<u8>) -> Result<(), StreamError> {
    match data.iter().rposition(|&b| b != 0) {
        Some(end) if data[end] == 0x80 => {
            data.truncate(end);
            Ok(())
        }
        _ => Err(StreamError::CryptoError("Invalid padding".to_string())),
    }
}

/// Encrypt JSON bytes for the given direction: compress → pad → encrypt → base64.
///
/// # Errors
///
/// [`StreamError::Hkdf`] if `iv_hex` is empty, [`StreamError::CryptoError`] if
/// compression or encryption fails.
pub fn encrypt_json(
    token: &str,
    iv_hex: &str,
    json_bytes: &[u8],
    direction: JsonDirection,
) -> Result<String, StreamError> {
    use base64::Engine as _;

    let mut encoder = zstd::Encoder::new(Vec::new(), 3)
        .map_err(|e| StreamError::CryptoError(format!("Compression failed: {e}")))?;
    encoder
        .include_contentsize(true)
        .map_err(|e| StreamError::CryptoError(format!("Compression setup failed: {e}")))?;
    encoder
        .set_pledged_src_size(Some(json_bytes.len() as u64))
        .map_err(|e| StreamError::CryptoError(format!("Compression setup failed: {e}")))?;
    {
        use std::io::Write;
        encoder
            .write_all(json_bytes)
            .map_err(|e| StreamError::CryptoError(format!("Compression write failed: {e}")))?;
    }
    let compressed = encoder
        .finish()
        .map_err(|e| StreamError::CryptoError(format!("Compression finish failed: {e}")))?;

    let (key, nonce_bytes) = derive_json_key_nonce(token, iv_hex, direction)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut data = compressed;
    pad(&mut data);
    cipher
        .encrypt_in_place(nonce, b"", &mut data)
        .map_err(|e| StreamError::CryptoError(format!("Encryption failed: {e}")))?;

    Ok(base64::engine::general_purpose::STANDARD.encode(&data))
}

/// Decrypt an encrypted JSON payload: base64-decode → decrypt → unpad → decompress.
///
/// # Errors
///
/// [`StreamError::CryptoError`] if `encoded` was not made by [`encrypt_json`]
/// with the same token, `iv_hex` and direction, or was altered since.
/// [`StreamError::RequestTooLarge`] for a request that unpacks to more than
/// [`MAX_REQUEST_JSON`] bytes, [`StreamError::Hkdf`] if `iv_hex` is empty.
pub fn decrypt_json(
    token: &str,
    iv_hex: &str,
    encoded: &str,
    direction: JsonDirection,
) -> Result<Vec<u8>, StreamError> {
    use base64::Engine as _;

    let mut data = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| StreamError::CryptoError(format!("Base64 decode failed: {e}")))?;

    let (key, nonce_bytes) = derive_json_key_nonce(token, iv_hex, direction)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt_in_place(nonce, b"", &mut data)
        .map_err(|e| StreamError::CryptoError(format!("Decryption failed: {e}")))?;
    unpad(&mut data)?;

    let failed = |e| StreamError::CryptoError(format!("Decompression failed: {e}"));
    match direction {
        JsonDirection::Response => zstd::decode_all(data.as_slice()).map_err(failed),
        JsonDirection::Request => {
            use std::io::Read as _;
            let mut json = Vec::new();
            zstd::stream::read::Decoder::new(data.as_slice())
                .map_err(failed)?
                .take(MAX_REQUEST_JSON as u64 + 1)
                .read_to_end(&mut json)
                .map_err(failed)?;
            if json.len() > MAX_REQUEST_JSON {
                return Err(StreamError::RequestTooLarge);
            }
            Ok(json)
        }
    }
}

/// Plaintext of the encrypted response of a token-protected location.
///
/// Every response to an authenticated request is either an encrypted file
/// stream or one of these. The HTTP status line says `200` in both cases; the
/// status of the operation is `status`, so that it is covered by the
/// authentication tag and hidden from an observer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reply {
    /// HTTP status code of the operation.
    pub status: u16,
    /// The server's message, when `status` is an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The JSON result, for an operation that has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

/// Encrypt a [`Reply`] and return the HTTP response body that carries it.
///
/// At most one reply may be encrypted per `(token, iv_hex)`: key and nonce are
/// derived from that pair alone.
///
/// # Errors
///
/// [`StreamError::MalformedReply`] if `reply` cannot be written as JSON, and
/// the errors of [`encrypt_json`].
pub fn seal_reply(token: &str, iv_hex: &str, reply: &Reply) -> Result<Vec<u8>, StreamError> {
    let json = serde_json::to_vec(reply).map_err(|e| StreamError::MalformedReply(e.to_string()))?;
    let message = encrypt_json(token, iv_hex, &json, JsonDirection::Response)?;
    serde_json::to_vec(&serde_json::json!({ "message": message }))
        .map_err(|e| StreamError::MalformedReply(e.to_string()))
}

/// Decrypt and verify an HTTP response body made by [`seal_reply`].
///
/// Fails for anything else, such as a plain-text error or a response that was
/// altered in transit.
///
/// # Errors
///
/// [`StreamError::MalformedReply`] if `body` is not the JSON that
/// [`seal_reply`] writes, and the errors of [`decrypt_json`].
pub fn open_reply(token: &str, iv_hex: &str, body: &[u8]) -> Result<Reply, StreamError> {
    #[derive(Deserialize)]
    struct Outer {
        message: String,
    }

    let outer: Outer =
        serde_json::from_slice(body).map_err(|e| StreamError::MalformedReply(e.to_string()))?;
    let json = decrypt_json(token, iv_hex, &outer.message, JsonDirection::Response)?;
    serde_json::from_slice(&json).map_err(|e| StreamError::MalformedReply(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_roundtrip() {
        for len in [0, 1, 254, 255, 256, 257, 1000] {
            let original = vec![0xAB; len];
            let mut data = original.clone();
            pad(&mut data);
            assert_eq!(data.len() % PAD_BLOCK, 0, "len {len}");
            assert!(data.len() > len, "len {len}");
            unpad(&mut data).unwrap();
            assert_eq!(data, original, "len {len}");
        }

        // Data that ends in zero bytes or in the marker byte itself.
        for original in [vec![1, 0, 0], vec![0x80], vec![0x80, 0, 0]] {
            let mut data = original.clone();
            pad(&mut data);
            unpad(&mut data).unwrap();
            assert_eq!(data, original);
        }

        assert!(unpad(&mut vec![0; PAD_BLOCK]).is_err());
        assert!(unpad(&mut vec![1, 2, 3]).is_err());
        assert!(unpad(&mut Vec::new()).is_err());
    }

    #[test]
    fn test_short_replies_have_the_same_length() {
        // An observer must not tell an error from an acknowledgement or from
        // the metadata of a file by the size of the response.
        let token = "test-secret";
        let iv_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let replies = [
            Reply {
                status: 204,
                error: None,
                body: None,
            },
            Reply {
                status: 404,
                error: Some("path not found".to_string()),
                body: None,
            },
            Reply {
                status: 200,
                error: None,
                body: Some(serde_json::json!({
                    "name": "reports/2031/q3-summary.txt",
                    "is_dir": false,
                    "size": 123_456,
                    "mtime": "2031-01-01T00:00:00Z",
                    "sha256": "ab".repeat(32),
                })),
            },
        ];
        let lengths: Vec<usize> = replies
            .iter()
            .map(|reply| seal_reply(token, iv_hex, reply).unwrap().len())
            .collect();
        assert!(lengths.iter().all(|len| *len == lengths[0]), "{lengths:?}");
    }

    #[test]
    fn test_reply_roundtrip() {
        let token = "test-secret";
        let iv_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let reply = Reply {
            status: 404,
            error: Some("path not found".to_string()),
            body: None,
        };
        let sealed = seal_reply(token, iv_hex, &reply).unwrap();
        assert_eq!(open_reply(token, iv_hex, &sealed).unwrap(), reply);

        assert!(open_reply("wrong-token", iv_hex, &sealed).is_err());
        assert!(open_reply(token, "0000", &sealed).is_err());
    }

    #[test]
    fn test_open_reply_rejects_plain_bodies() {
        let token = "test-secret";
        let iv_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        for body in [
            &b""[..],
            b"path not found",
            br#"{"status":204}"#,
            br#"{"message":"bm90IGEgY2lwaGVydGV4dA=="}"#,
        ] {
            assert!(open_reply(token, iv_hex, body).is_err(), "{body:?}");
        }
    }

    #[test]
    fn test_open_reply_requires_a_status() {
        // What a server before 0.5 sends: the JSON result itself, encrypted.
        let token = "test-secret";
        let iv_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let message = encrypt_json(
            token,
            iv_hex,
            br#"{"name":"a.txt","is_dir":false}"#,
            JsonDirection::Response,
        )
        .unwrap();
        let body = serde_json::to_vec(&serde_json::json!({ "message": message })).unwrap();
        assert!(open_reply(token, iv_hex, &body).is_err());
    }

    #[test]
    fn test_request_is_not_unpacked_beyond_its_limit() {
        let token = "test-secret";
        let iv_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        // Compresses to a few hundred bytes.
        let large = vec![b' '; MAX_REQUEST_JSON + 1];

        let request = encrypt_json(token, iv_hex, &large, JsonDirection::Request).unwrap();
        assert!(request.len() < 1024);
        assert!(matches!(
            decrypt_json(token, iv_hex, &request, JsonDirection::Request),
            Err(StreamError::RequestTooLarge)
        ));

        let at_limit = &large[..MAX_REQUEST_JSON];
        let request = encrypt_json(token, iv_hex, at_limit, JsonDirection::Request).unwrap();
        let unpacked = decrypt_json(token, iv_hex, &request, JsonDirection::Request).unwrap();
        assert_eq!(unpacked.len(), MAX_REQUEST_JSON);

        // A response may be as large as the listing it carries.
        let response = encrypt_json(token, iv_hex, &large, JsonDirection::Response).unwrap();
        let unpacked = decrypt_json(token, iv_hex, &response, JsonDirection::Response).unwrap();
        assert_eq!(unpacked.len(), large.len());
    }

    #[test]
    fn test_reply_cross_language_vectors() {
        // One reply sealed by each implementation. Both test suites open both
        // (test_reply_cross_language_vectors in filebridge-py/tests/test_stream.py).
        // The tests only open them: the compressed bytes may differ between
        // zstd versions, so sealing has no fixed output.
        let token = "test-secret";
        let iv_hex = "f6e0d9c62c10768618fabd2ebbefd533ccf44aebf68d89434a3caaf0c56d7114";

        let from_rust = br#"{"message":"oAXDTz9SrkcLZZzVGteEZjX3X9SogZ2YFLCFG3wkdPjewMWzqAvok+IpumuBfDHZ+VWDlqUvR7CEq2eKMsl4SW1wVm+Od0um2FQjyccfUZ4Vnmmlqh6edIB4VovgDWpjy3FdShwXq/wCII1isM3REQ+kAMLTqBoX+ZbbcGbDdADXNBCqjP1ce/PL6EU5XgCB2qN+J7Cnl3iUZoJ30B53YCOL5tcWCVfb/3FHTBvfUvEIVi6LR9QPKsV9eT7WIrV5OmvP0zXOA/e0w19yO4Hbx/rU4iKFsHHyGu7ytiCIkCRuzaJ6sfXVjHeiQz3zYAjfWuQi2SXRtK6t/I043EWyqJGzwhQwlBiLRUGWJwigUoM="}"#;
        assert_eq!(
            open_reply(token, iv_hex, from_rust).unwrap(),
            Reply {
                status: 404,
                error: Some("path not found".to_string()),
                body: None,
            }
        );

        let from_python = br#"{"message": "oAXDTz8zgkQLfDqpeSa1fsa1DGsogPbSGMaBK1IdlGlHXebV42g5gOKmuLfoAq2LcEQZ+F4ZXFD55GMZGRZ5AUQebSh+KtJjDf8jSccfUZ4Vnmmlqh6edIB4VovgDWpjy3FdShwXq/wCII1isM3REQ+kAMLTqBoX+ZbbcGbDdADXNBCqjP1ce/PL6EU5XgCB2qN+J7Cnl3iUZoJ30B53YCOL5tcWCVfb/3FHTBvfUvEIVi6LR9QPKsV9eT7WIrV5OmvP0zXOA/e0w19yO4Hbx/rU4iKFsHHyGu7ytiCIkCRuzaJ6sfXVjHeiQz3zYAjfWuQi2SXRtK6t/I043EWyqL3/lbc8oxZz8Exvkv9g3nw="}"#;
        assert_eq!(
            open_reply(token, iv_hex, from_python).unwrap(),
            Reply {
                status: 200,
                error: None,
                body: Some(serde_json::json!({"name": "a.txt", "is_dir": false, "size": 5})),
            }
        );
    }

    #[test]
    fn test_request_signature_cross_language_vector() {
        // This value must match the Python implementation exactly.
        let sig = request_signature(
            "test-secret",
            "1700000000",
            "0011223344556677",
            "GET",
            "/api/v1/fs/demo",
        )
        .unwrap();
        assert_eq!(
            hex::encode(sig),
            "f6e0d9c62c10768618fabd2ebbefd533ccf44aebf68d89434a3caaf0c56d7114"
        );
    }

    #[test]
    fn test_json_roundtrip_both_directions() {
        let token = "test-secret";
        let iv_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let json = br#"{"items":[{"name":"foo.txt","is_dir":false}]}"#;

        for direction in [JsonDirection::Request, JsonDirection::Response] {
            let encoded = encrypt_json(token, iv_hex, json, direction).unwrap();
            let decoded = decrypt_json(token, iv_hex, &encoded, direction).unwrap();
            assert_eq!(decoded, json);
        }
    }

    #[test]
    fn test_json_wrong_token_fails() {
        let token = "test-secret";
        let iv_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let json = br#"{"name":"test.txt","is_dir":false}"#;

        let encoded = encrypt_json(token, iv_hex, json, JsonDirection::Request).unwrap();
        assert!(decrypt_json("wrong-token", iv_hex, &encoded, JsonDirection::Request).is_err());
    }

    #[test]
    fn test_json_directions_are_cryptographically_separate() {
        // Regression test for C1 (nonce reuse): request and response under the
        // same (token, sig) must use distinct keys/nonces, so a ciphertext from
        // one direction must not decrypt in the other.
        let token = "test-secret";
        let iv_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let (req_key, req_nonce) =
            derive_json_key_nonce(token, iv_hex, JsonDirection::Request).unwrap();
        let (resp_key, resp_nonce) =
            derive_json_key_nonce(token, iv_hex, JsonDirection::Response).unwrap();
        assert_ne!(req_key, resp_key);
        assert_ne!(req_nonce, resp_nonce);

        let json = br#"{"path":"foo.txt"}"#;
        let encoded = encrypt_json(token, iv_hex, json, JsonDirection::Request).unwrap();
        assert!(decrypt_json(token, iv_hex, &encoded, JsonDirection::Response).is_err());
    }

    #[test]
    fn test_hkdf_cross_language_vectors() {
        // These values must match the Python implementation exactly
        let token = "test-secret";
        let iv_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let (sk, sn) = derive_stream_key_nonce(token, iv_hex).unwrap();
        assert_eq!(
            hex::encode(sk),
            "4e1f082bb3d869ec18ee2f8a06fcf9cd8741f2d847fd443a1b6a0d761a7405e7"
        );
        assert_eq!(hex::encode(sn), "fd55d161ad566053ff2d2a0d");

        let (req_key, req_nonce) =
            derive_json_key_nonce(token, iv_hex, JsonDirection::Request).unwrap();
        assert_eq!(
            hex::encode(req_key),
            "1ec0e019cb826536296459785c0681fefd1b325049409a7abc4f091cd29665f2"
        );
        assert_eq!(hex::encode(req_nonce), "d5bfeb81da44fd83eb5d7f91");

        let (resp_key, resp_nonce) =
            derive_json_key_nonce(token, iv_hex, JsonDirection::Response).unwrap();
        assert_eq!(
            hex::encode(resp_key),
            "e4ca88541d1b3086ea6f4c4eeefa346a2cbcb7c56f6ec3b6d768e371f8f24219"
        );
        assert_eq!(hex::encode(resp_nonce), "77587e1217cfdec101632a65");
    }

    #[test]
    fn test_decoder_rejects_oversized_frame() {
        let mut decoder = StreamDecoder::new();
        // DATA tag + a length field just above the allowed maximum.
        let mut frame = Vec::new();
        frame.extend_from_slice(b"DATA");
        let too_long = u32::try_from(MAX_FRAME_PAYLOAD + 1).unwrap();
        frame.extend_from_slice(&too_long.to_be_bytes());
        decoder.push(&frame);
        match decoder.next_frame() {
            Err(StreamError::FrameTooLarge(n)) => assert_eq!(n, MAX_FRAME_PAYLOAD + 1),
            Err(e) => panic!("expected FrameTooLarge, got {e:?}"),
            Ok(_) => panic!("expected FrameTooLarge, got Ok"),
        }
    }

    #[test]
    fn test_stream_aead_roundtrip() {
        let token = "test-secret";
        let iv_hex = "abcdef1234567890";

        let mut enc = StreamAead::new(token, iv_hex).unwrap();
        let mut chunk1 = b"hello world".to_vec();
        enc.encrypt(&mut chunk1).unwrap();
        let mut chunk2 = b"second chunk".to_vec();
        enc.encrypt(&mut chunk2).unwrap();
        let stop = enc.finalize().unwrap();

        let mut dec = StreamAead::new(token, iv_hex).unwrap();
        dec.decrypt(&mut chunk1).unwrap();
        assert_eq!(chunk1, b"hello world");
        dec.decrypt(&mut chunk2).unwrap();
        assert_eq!(chunk2, b"second chunk");
        dec.verify_stop(&stop).unwrap();
    }
}
