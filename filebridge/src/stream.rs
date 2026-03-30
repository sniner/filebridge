//! Streaming protocol and encryption primitives for the Filebridge wire format.

use bytes::{Buf, Bytes, BytesMut};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StreamError {
    #[error("Invalid stream frame tag: {0:?}")]
    InvalidTag([u8; 4]),
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

/// Derive key and nonce for JSON response encryption/decryption.
/// Uses different info strings than stream AEAD for purpose separation.
fn derive_json_key_nonce(token: &str, iv_hex: &str) -> Result<([u8; 32], [u8; 12]), StreamError> {
    if iv_hex.is_empty() {
        return Err(StreamError::Hkdf("iv_hex must not be empty"));
    }
    let hk = Hkdf::<Sha256>::new(Some(iv_hex.as_bytes()), token.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"filebridge-json-key", &mut key)
        .map_err(|_| StreamError::Hkdf("expand failed for JSON key"))?;
    let mut nonce = [0u8; 12];
    hk.expand(b"filebridge-json-nonce", &mut nonce)
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

/// Encrypt JSON bytes for a response: compress → encrypt → base64.
/// Uses the same key/nonce derivation as `StreamAead` with counter=0.
pub fn encrypt_json_response(token: &str, iv_hex: &str, json_bytes: &[u8]) -> Result<String, StreamError> {
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

    let (key, nonce_bytes) = derive_json_key_nonce(token, iv_hex)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut data = compressed;
    cipher
        .encrypt_in_place(nonce, b"", &mut data)
        .map_err(|e| StreamError::CryptoError(format!("Encryption failed: {}", e)))?;

    Ok(base64::engine::general_purpose::STANDARD.encode(&data))
}

/// Decrypt a JSON response: base64-decode → decrypt → decompress.
pub fn decrypt_json_response(token: &str, iv_hex: &str, encoded: &str) -> Result<Vec<u8>, StreamError> {
    use base64::Engine as _;

    let mut data = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| StreamError::CryptoError(format!("Base64 decode failed: {}", e)))?;

    let (key, nonce_bytes) = derive_json_key_nonce(token, iv_hex)?;
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
    fn test_json_response_roundtrip() {
        let token = "test-secret";
        let iv_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let json = br#"{"items":[{"name":"foo.txt","is_dir":false}]}"#;

        let encoded = encrypt_json_response(token, iv_hex, json).unwrap();
        let decoded = decrypt_json_response(token, iv_hex, &encoded).unwrap();
        assert_eq!(decoded, json);
    }

    #[test]
    fn test_json_response_wrong_token_fails() {
        let token = "test-secret";
        let iv_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let json = br#"{"name":"test.txt","is_dir":false}"#;

        let encoded = encrypt_json_response(token, iv_hex, json).unwrap();
        assert!(decrypt_json_response("wrong-token", iv_hex, &encoded).is_err());
    }

    #[test]
    fn test_hkdf_cross_language_vectors() {
        // These values must match the Python implementation exactly
        let token = "test-secret";
        let iv_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let (sk, sn) = derive_stream_key_nonce(token, iv_hex).unwrap();
        assert_eq!(hex::encode(sk), "4e1f082bb3d869ec18ee2f8a06fcf9cd8741f2d847fd443a1b6a0d761a7405e7");
        assert_eq!(hex::encode(sn), "fd55d161ad566053ff2d2a0d");

        let (jk, jn) = derive_json_key_nonce(token, iv_hex).unwrap();
        assert_eq!(hex::encode(jk), "5325c7eb06e53ce49800fb593a2aadc6b77453a03c0e1e99c843ef094deb3f42");
        assert_eq!(hex::encode(jn), "666c2f925009050d9f0c4069");
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
