use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use sha2::{Digest, Sha256};
use rand::RngCore;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("invalid key length")]
    InvalidKey,
}

/// 32-byte session key used for agent ↔ server traffic.
#[derive(Debug, Clone)]
pub struct SessionKey(pub [u8; 32]);

impl SessionKey {
    pub fn random() -> Self {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        Self(k)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        b.try_into()
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }

    pub fn from_passphrase(pass: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pass.as_bytes());
        let result = hasher.finalize();
        let mut k = [0u8; 32];
        k.copy_from_slice(&result);
        Self(k)
    }
}

/// Encrypt plaintext with AES-256-GCM. Returns nonce || ciphertext.
pub fn encrypt(key: &SessionKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::EncryptFailed)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt nonce || ciphertext produced by `encrypt`.
pub fn decrypt(key: &SessionKey, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 12 {
        return Err(CryptoError::DecryptFailed);
    }
    let (nonce_bytes, ct) = data.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| CryptoError::DecryptFailed)
}

/// XOR a buffer with a repeating key — used for quick payload config obfuscation.
pub fn xor_encode(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

pub fn xor_decode(data: &[u8], key: &[u8]) -> Vec<u8> {
    xor_encode(data, key) // XOR is symmetric
}

/// Generate a random N-byte key.
pub fn random_key(n: usize) -> Vec<u8> {
    let mut k = vec![0u8; n];
    OsRng.fill_bytes(&mut k);
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = SessionKey::random();
        let pt = b"hello ghoststrike";
        let ct = encrypt(&key, pt).unwrap();
        let dec = decrypt(&key, &ct).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn xor_round_trip() {
        let key = b"deadbeef";
        let data = b"payload config blob";
        let enc = xor_encode(data, key);
        let dec = xor_decode(&enc, key);
        assert_eq!(dec, data);
    }
}
