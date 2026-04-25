use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use aes_gcm::aead::rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BaselineError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Encryption error")]
    Encryption,
    #[error("Decryption error")]
    Decryption,
    #[error("Invalid data")]
    InvalidData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineProfile {
    pub feature_means: Vec<f64>,
    pub feature_stds: Vec<f64>,
    pub enrollment_count: usize,
    pub ema_alpha: f64,
}

impl BaselineProfile {
    pub fn new(feature_dim: usize, ema_alpha: f64) -> Self {
        Self {
            feature_means: vec![0.0; feature_dim],
            feature_stds: vec![1.0; feature_dim],
            enrollment_count: 0,
            ema_alpha,
        }
    }

    pub fn update(&mut self, features: &[f64]) {
        let alpha = self.ema_alpha;
        for (i, &x) in features.iter().enumerate() {
            if i >= self.feature_means.len() {
                break;
            }
            let old_mean = self.feature_means[i];
            let new_mean = alpha * x + (1.0 - alpha) * old_mean;
            self.feature_means[i] = new_mean;

            // EMA variance update
            let diff = x - old_mean;
            let old_std = self.feature_stds[i];
            let old_var = old_std * old_std;
            let new_var = (1.0 - alpha) * (old_var + alpha * diff * diff);
            self.feature_stds[i] = new_var.sqrt().max(1e-6);
        }
        self.enrollment_count += features.len();
    }

    pub fn is_enrolled(&self, min_keystrokes: usize) -> bool {
        self.enrollment_count >= min_keystrokes
    }

    pub fn to_encrypted_bytes(&self, key: &[u8; 32]) -> Result<Vec<u8>, BaselineError> {
        let plaintext = serde_json::to_vec(self)?;
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| BaselineError::Encryption)?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).map_err(|_| BaselineError::Encryption)?;
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn from_encrypted_bytes(data: &[u8], key: &[u8; 32]) -> Result<Self, BaselineError> {
        if data.len() < 12 {
            return Err(BaselineError::InvalidData);
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| BaselineError::Decryption)?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| BaselineError::Decryption)?;
        let profile: Self = serde_json::from_slice(&plaintext)?;
        Ok(profile)
    }

    pub fn save(&self, path: &str, key: &[u8; 32]) -> Result<(), BaselineError> {
        let bytes = self.to_encrypted_bytes(key)?;
        fs::write(path, bytes)?;
        Ok(())
    }

    pub fn load(path: &str, key: &[u8; 32]) -> Result<Self, BaselineError> {
        let data = fs::read(path)?;
        Self::from_encrypted_bytes(&data, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_changes_means() {
        let mut profile = BaselineProfile::new(3, 0.1);
        profile.update(&[10.0, 20.0, 30.0]);
        // After one update with alpha=0.1: mean = 0.1*x + 0.9*0 = 0.1*x
        assert!((profile.feature_means[0] - 1.0).abs() < 0.01);
        assert!((profile.feature_means[1] - 2.0).abs() < 0.01);
        assert!((profile.feature_means[2] - 3.0).abs() < 0.01);
    }

    #[test]
    fn test_is_enrolled() {
        let mut profile = BaselineProfile::new(3, 0.1);
        assert!(!profile.is_enrolled(10));
        profile.update(&[1.0, 2.0, 3.0]);
        // enrollment_count increases by features.len() = 3
        assert!(!profile.is_enrolled(10));
        // update 3 more times: 4*3 = 12 >= 10
        profile.update(&[1.0, 2.0, 3.0]);
        profile.update(&[1.0, 2.0, 3.0]);
        profile.update(&[1.0, 2.0, 3.0]);
        assert!(profile.is_enrolled(10));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let mut profile = BaselineProfile::new(3, 0.05);
        profile.update(&[100.0, 50.0, 30.0]);
        let encrypted = profile.to_encrypted_bytes(&key).unwrap();
        let decrypted = BaselineProfile::from_encrypted_bytes(&encrypted, &key).unwrap();
        assert_eq!(profile.feature_means.len(), decrypted.feature_means.len());
        for (a, b) in profile.feature_means.iter().zip(decrypted.feature_means.iter()) {
            assert!((a - b).abs() < 1e-9);
        }
    }
}
