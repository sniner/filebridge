//! Streaming protocol and encryption primitives for the Filebridge wire format.

use bytes::{Buf, Bytes, BytesMut};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
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
}

pub enum StreamFrame {
    Meta { payload: Bytes },
    Data { payload: Bytes },
    Stop { signature: Option<String> }, // signature is the final AEAD tag hex
}

pub fn encode_meta(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(8 + payload.len());
    frame.extend_from_slice(b"META");
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub fn encode_data(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(8 + payload.len());
    frame.extend_from_slice(b"DATA");
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub fn encode_stop(signature: Option<&str>) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(b"STOP");
    if let Some(sig) = signature {
        let sig_bytes = sig.as_bytes();
        frame.extend_from_slice(&(sig_bytes.len() as u32).to_be_bytes());
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
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
        }
    }

    pub fn push(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
    }

    /// Return any remaining unprocessed bytes in the buffer.
    pub fn remaining(&self) -> &[u8] {
        &self.buffer
    }

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
                    Some(
                        String::from_utf8(payload.to_vec())
                            .map_err(|_| StreamError::CryptoError("Invalid UTF-8 in STOP frame signature".to_string()))?,
                    )
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

    pub fn encrypt(&mut self, data: &mut Vec<u8>) -> Result<(), StreamError> {
        let binding = self.current_nonce();
        let nonce = Nonce::from_slice(&binding);
        self.cipher
            .encrypt_in_place(nonce, b"", data)
            .map_err(|e| StreamError::CryptoError(format!("Encryption failed: {}", e)))?;
        self.counter += 1;
        Ok(())
    }

    pub fn decrypt(&mut self, data: &mut Vec<u8>) -> Result<(), StreamError> {
        let binding = self.current_nonce();
        let nonce = Nonce::from_slice(&binding);
        self.cipher
            .decrypt_in_place(nonce, b"", data)
            .map_err(|e| StreamError::CryptoError(format!("Decryption failed: {}", e)))?;
        self.counter += 1;
        Ok(())
    }

    pub fn finalize(&mut self) -> Result<String, StreamError> {
        let mut final_block = Vec::new();
        self.encrypt(&mut final_block)?;
        Ok(hex::encode(final_block))
    }

    pub fn verify_stop(&mut self, hex_sig: &str) -> Result<(), StreamError> {
        let mut final_block = hex::decode(hex_sig)
            .map_err(|e| StreamError::CryptoError(format!("Invalid hex in stop signature: {}", e)))?;
        self.decrypt(&mut final_block)?;
        Ok(())
    }
}

/// Encrypt JSON bytes for the given direction: compress → encrypt → base64.
pub fn encrypt_json(
    token: &str,
    iv_hex: &str,
    json_bytes: &[u8],
    direction: JsonDirection,
) -> Result<String, StreamError> {
    use base64::Engine as _;

    let mut encoder = zstd::Encoder::new(Vec::new(), 3)
        .map_err(|e| StreamError::CryptoError(format!("Compression failed: {}", e)))?;
    encoder
        .include_contentsize(true)
        .map_err(|e| StreamError::CryptoError(format!("Compression setup failed: {}", e)))?;
    encoder
        .set_pledged_src_size(Some(json_bytes.len() as u64))
        .map_err(|e| StreamError::CryptoError(format!("Compression setup failed: {}", e)))?;
    {
        use std::io::Write;
        encoder
            .write_all(json_bytes)
            .map_err(|e| StreamError::CryptoError(format!("Compression write failed: {}", e)))?;
    }
    let compressed = encoder
        .finish()
        .map_err(|e| StreamError::CryptoError(format!("Compression finish failed: {}", e)))?;

    let (key, nonce_bytes) = derive_json_key_nonce(token, iv_hex, direction)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut data = compressed;
    cipher
        .encrypt_in_place(nonce, b"", &mut data)
        .map_err(|e| StreamError::CryptoError(format!("Encryption failed: {}", e)))?;

    Ok(base64::engine::general_purpose::STANDARD.encode(&data))
}

/// Decrypt an encrypted JSON payload: base64-decode → decrypt → decompress.
pub fn decrypt_json(
    token: &str,
    iv_hex: &str,
    encoded: &str,
    direction: JsonDirection,
) -> Result<Vec<u8>, StreamError> {
    use base64::Engine as _;

    let mut data = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| StreamError::CryptoError(format!("Base64 decode failed: {}", e)))?;

    let (key, nonce_bytes) = derive_json_key_nonce(token, iv_hex, direction)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt_in_place(nonce, b"", &mut data)
        .map_err(|e| StreamError::CryptoError(format!("Decryption failed: {}", e)))?;

    zstd::decode_all(data.as_slice())
        .map_err(|e| StreamError::CryptoError(format!("Decompression failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(hex::encode(sk), "4e1f082bb3d869ec18ee2f8a06fcf9cd8741f2d847fd443a1b6a0d761a7405e7");
        assert_eq!(hex::encode(sn), "fd55d161ad566053ff2d2a0d");

        let (req_key, req_nonce) =
            derive_json_key_nonce(token, iv_hex, JsonDirection::Request).unwrap();
        assert_eq!(hex::encode(req_key), "1ec0e019cb826536296459785c0681fefd1b325049409a7abc4f091cd29665f2");
        assert_eq!(hex::encode(req_nonce), "d5bfeb81da44fd83eb5d7f91");

        let (resp_key, resp_nonce) =
            derive_json_key_nonce(token, iv_hex, JsonDirection::Response).unwrap();
        assert_eq!(hex::encode(resp_key), "e4ca88541d1b3086ea6f4c4eeefa346a2cbcb7c56f6ec3b6d768e371f8f24219");
        assert_eq!(hex::encode(resp_nonce), "77587e1217cfdec101632a65");
    }

    #[test]
    fn test_decoder_rejects_oversized_frame() {
        let mut decoder = StreamDecoder::new();
        // DATA tag + a length field just above the allowed maximum.
        let mut frame = Vec::new();
        frame.extend_from_slice(b"DATA");
        frame.extend_from_slice(&((MAX_FRAME_PAYLOAD as u32) + 1).to_be_bytes());
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
