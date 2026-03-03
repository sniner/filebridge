use bytes::{Buf, Bytes, BytesMut};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StreamError {
    #[error("Invalid stream frame tag: {0:?}")]
    InvalidTag([u8; 4]),
    #[error("Cryptographic Error: {0}")]
    CryptoError(String),
}

pub enum StreamFrame {
    Data { payload: Bytes },
    Stop { signature: Option<String> }, // signature is the final AEAD tag hex
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
            b"DATA" => Ok(Some(StreamFrame::Data {
                payload: payload.freeze(),
            })),
            b"STOP" => {
                let sig = if length > 0 {
                    Some(String::from_utf8_lossy(&payload).into_owned())
                } else {
                    None
                };
                Ok(Some(StreamFrame::Stop { signature: sig }))
            }
            _ => Err(StreamError::InvalidTag(tag)),
        }
    }
}

pub struct StreamAead {
    cipher: ChaCha20Poly1305,
    nonce_base: [u8; 12],
    counter: u64,
}

impl StreamAead {
    pub fn new(token: &str, iv_hex: &str) -> Result<Self, String> {
        let key_hash = Sha256::digest(token.as_bytes());
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_hash));

        let mut iv_hasher = Sha256::new();
        iv_hasher.update(token.as_bytes());
        iv_hasher.update(iv_hex.as_bytes());
        let iv_hash = iv_hasher.finalize();

        let mut nonce_base = [0u8; 12];
        nonce_base.copy_from_slice(&iv_hash[..12]);

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

    pub fn encrypt(&mut self, data: &mut Vec<u8>) -> Result<(), String> {
        let binding = self.current_nonce();
        let nonce = Nonce::from_slice(&binding);
        self.cipher
            .encrypt_in_place(nonce, b"", data)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        self.counter += 1;
        Ok(())
    }

    pub fn decrypt(&mut self, data: &mut Vec<u8>) -> Result<(), String> {
        let binding = self.current_nonce();
        let nonce = Nonce::from_slice(&binding);
        self.cipher
            .decrypt_in_place(nonce, b"", data)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        self.counter += 1;
        Ok(())
    }

    pub fn finalize(&mut self) -> Result<String, String> {
        let mut final_block = Vec::new();
        self.encrypt(&mut final_block)?; // Encrypts empty slice -> produces 16 byte tag
        Ok(hex::encode(final_block))
    }

    pub fn verify_stop(&mut self, hex_sig: &str) -> Result<(), String> {
        let mut final_block =
            hex::decode(hex_sig).map_err(|e| format!("Invalid hex in stop signature: {}", e))?;
        self.decrypt(&mut final_block)?;
        Ok(())
    }
}

/// Encrypt JSON bytes for a response: compress → encrypt → base64.
/// Uses the same key/nonce derivation as `StreamAead` with counter=0.
pub fn encrypt_json_response(token: &str, iv_hex: &str, json_bytes: &[u8]) -> Result<String, String> {
    use base64::Engine as _;

    let compressed = zstd::encode_all(json_bytes, 3)
        .map_err(|e| format!("Compression failed: {}", e))?;

    let key_hash = Sha256::digest(token.as_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_hash));

    let mut iv_hasher = Sha256::new();
    iv_hasher.update(token.as_bytes());
    iv_hasher.update(iv_hex.as_bytes());
    let iv_hash = iv_hasher.finalize();

    let nonce = Nonce::from_slice(&iv_hash[..12]);

    let mut data = compressed;
    cipher
        .encrypt_in_place(nonce, b"", &mut data)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok(base64::engine::general_purpose::STANDARD.encode(&data))
}

/// Decrypt a JSON response: base64-decode → decrypt → decompress.
pub fn decrypt_json_response(token: &str, iv_hex: &str, encoded: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;

    let mut data = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    let key_hash = Sha256::digest(token.as_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_hash));

    let mut iv_hasher = Sha256::new();
    iv_hasher.update(token.as_bytes());
    iv_hasher.update(iv_hex.as_bytes());
    let iv_hash = iv_hasher.finalize();

    let nonce = Nonce::from_slice(&iv_hash[..12]);

    cipher
        .decrypt_in_place(nonce, b"", &mut data)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    zstd::decode_all(data.as_slice())
        .map_err(|e| format!("Decompression failed: {}", e))
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
}
