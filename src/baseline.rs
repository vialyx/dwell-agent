use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileLoadSource {
    Primary,
    Backup,
    Fresh,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileLoadReport {
    pub source: ProfileLoadSource,
    pub primary_failed: bool,
    pub backup_failed: bool,
    pub recovered_from_backup: bool,
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

    /// Update the EMA model with a new feature vector.
    ///
    /// `keystroke_count` should be the number of `KeyDown` events that produced
    /// this feature vector.  It is added to `enrollment_count` so that
    /// `is_enrolled()` compares against real keystroke counts rather than the
    /// (fixed) feature-vector dimension.
    pub fn update(&mut self, features: &[f64], keystroke_count: usize) {
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
        self.enrollment_count += keystroke_count;
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
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| BaselineError::Encryption)?;
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
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| BaselineError::Decryption)?;
        let profile: Self = serde_json::from_slice(&plaintext)?;
        Ok(profile)
    }

    pub fn save(&self, path: &str, key: &[u8; 32]) -> Result<(), BaselineError> {
        let bytes = self.to_encrypted_bytes(key)?;
        let target = Path::new(path);
        let parent = target.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;

        let file_name = target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("profile.enc");
        let tmp_name = format!(
            ".{}.tmp-{}-{}",
            file_name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let tmp_path: PathBuf = parent.join(tmp_name);

        let write_result = (|| -> Result<(), BaselineError> {
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp_path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&tmp_path, target)?;
            Ok(())
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }

        write_result?;

        let backup_path = backup_path_for(path);
        let _ = fs::copy(target, &backup_path);

        // Best effort: fsync parent directory so the rename is durable.
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    pub fn load(path: &str, key: &[u8; 32]) -> Result<Self, BaselineError> {
        let data = fs::read(path)?;
        Self::from_encrypted_bytes(&data, key)
    }

    pub fn load_with_recovery(
        path: &str,
        key: &[u8; 32],
        feature_dim: usize,
        ema_alpha: f64,
    ) -> Result<(Self, ProfileLoadReport), BaselineError> {
        match Self::load(path, key) {
            Ok(profile) => Ok((
                profile,
                ProfileLoadReport {
                    source: ProfileLoadSource::Primary,
                    primary_failed: false,
                    backup_failed: false,
                    recovered_from_backup: false,
                },
            )),
            Err(BaselineError::Io(io_err)) if io_err.kind() == std::io::ErrorKind::NotFound => {
                let backup_path = backup_path_for(path);
                if backup_path.exists() {
                    match Self::load(backup_path.to_string_lossy().as_ref(), key) {
                        Ok(profile) => {
                            let _ = profile.save(path, key);
                            return Ok((
                                profile,
                                ProfileLoadReport {
                                    source: ProfileLoadSource::Backup,
                                    primary_failed: false,
                                    backup_failed: false,
                                    recovered_from_backup: true,
                                },
                            ));
                        }
                        Err(_) => {
                            let _ = quarantine_file(&backup_path);
                        }
                    }
                }

                Ok((
                    Self::new(feature_dim, ema_alpha),
                    ProfileLoadReport {
                        source: ProfileLoadSource::Fresh,
                        primary_failed: false,
                        backup_failed: false,
                        recovered_from_backup: false,
                    },
                ))
            }
            Err(_) => {
                let _ = quarantine_file(Path::new(path));
                let backup_path = backup_path_for(path);
                if backup_path.exists() {
                    match Self::load(backup_path.to_string_lossy().as_ref(), key) {
                        Ok(profile) => {
                            let _ = profile.save(path, key);
                            return Ok((
                                profile,
                                ProfileLoadReport {
                                    source: ProfileLoadSource::Backup,
                                    primary_failed: true,
                                    backup_failed: false,
                                    recovered_from_backup: true,
                                },
                            ));
                        }
                        Err(_) => {
                            let _ = quarantine_file(&backup_path);
                            return Ok((
                                Self::new(feature_dim, ema_alpha),
                                ProfileLoadReport {
                                    source: ProfileLoadSource::Fresh,
                                    primary_failed: true,
                                    backup_failed: true,
                                    recovered_from_backup: false,
                                },
                            ));
                        }
                    }
                }

                Ok((
                    Self::new(feature_dim, ema_alpha),
                    ProfileLoadReport {
                        source: ProfileLoadSource::Fresh,
                        primary_failed: true,
                        backup_failed: false,
                        recovered_from_backup: false,
                    },
                ))
            }
        }
    }
}

fn backup_path_for(path: &str) -> PathBuf {
    PathBuf::from(format!("{path}.bak"))
}

fn quarantine_file(path: &Path) -> Result<(), std::io::Error> {
    if !path.exists() {
        return Ok(());
    }

    let quarantine_name = format!(
        "{}.quarantine-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("profile"),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let quarantine_path = path.with_file_name(quarantine_name);
    fs::rename(path, quarantine_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn unique_path(label: &str) -> String {
        let id = &Uuid::new_v4().as_simple().to_string()[..10];
        format!("/tmp/dw-{label}-{id}.enc")
    }

    #[test]
    fn test_update_changes_means() {
        let mut profile = BaselineProfile::new(3, 0.1);
        profile.update(&[10.0, 20.0, 30.0], 3);
        // After one update with alpha=0.1: mean = 0.1*x + 0.9*0 = 0.1*x
        assert!((profile.feature_means[0] - 1.0).abs() < 0.01);
        assert!((profile.feature_means[1] - 2.0).abs() < 0.01);
        assert!((profile.feature_means[2] - 3.0).abs() < 0.01);
    }

    #[test]
    fn test_is_enrolled_tracks_keystroke_count_not_feature_dim() {
        let mut profile = BaselineProfile::new(3, 0.1);
        assert!(!profile.is_enrolled(100));
        // Pass keystroke_count=40 — still below threshold
        profile.update(&[1.0, 2.0, 3.0], 40);
        assert!(!profile.is_enrolled(100));
        // Another 60 → total 100 >= 100
        profile.update(&[1.0, 2.0, 3.0], 60);
        assert!(profile.is_enrolled(100));
        // Verify the count is exactly 100, not inflated by feature_dim (3)
        assert_eq!(profile.enrollment_count, 100);
    }

    #[test]
    fn test_enrollment_count_reflects_keystrokes_not_feature_dim() {
        // Feature vector has dim 9; each update should add real keystroke count
        let mut profile = BaselineProfile::new(9, 0.05);
        profile.update(&[0.0; 9], 50);
        profile.update(&[0.0; 9], 50);
        // Should be 100, not 9*2=18
        assert_eq!(profile.enrollment_count, 100);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let mut profile = BaselineProfile::new(3, 0.05);
        profile.update(&[100.0, 50.0, 30.0], 50);
        let encrypted = profile.to_encrypted_bytes(&key).unwrap();
        let decrypted = BaselineProfile::from_encrypted_bytes(&encrypted, &key).unwrap();
        assert_eq!(profile.feature_means.len(), decrypted.feature_means.len());
        for (a, b) in profile
            .feature_means
            .iter()
            .zip(decrypted.feature_means.iter())
        {
            assert!((a - b).abs() < 1e-9);
        }
    }

    #[test]
    fn test_invalid_data_too_short() {
        let key = [1u8; 32];
        let result = BaselineProfile::from_encrypted_bytes(&[0u8; 4], &key);
        assert!(matches!(result, Err(BaselineError::InvalidData)));
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key_a = [0xABu8; 32];
        let key_b = [0xCDu8; 32];
        let profile = BaselineProfile::new(3, 0.05);
        let encrypted = profile.to_encrypted_bytes(&key_a).unwrap();
        assert!(matches!(
            BaselineProfile::from_encrypted_bytes(&encrypted, &key_b),
            Err(BaselineError::Decryption)
        ));
    }

    #[test]
    fn test_save_creates_backup_copy() {
        let key = [7u8; 32];
        let path = unique_path("backup");
        let backup = backup_path_for(&path);
        let profile = BaselineProfile::new(3, 0.05);

        profile.save(&path, &key).unwrap();
        assert!(Path::new(&path).exists());
        assert!(backup.exists());

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup);
    }

    #[test]
    fn test_load_with_recovery_uses_backup_when_primary_is_corrupt() {
        let key = [9u8; 32];
        let path = unique_path("recovery");
        let backup = backup_path_for(&path);
        let mut profile = BaselineProfile::new(3, 0.05);
        profile.update(&[1.0, 2.0, 3.0], 10);
        profile.save(&path, &key).unwrap();
        assert!(backup.exists());

        fs::write(&path, b"corrupt").unwrap();
        let (loaded, report) = BaselineProfile::load_with_recovery(&path, &key, 3, 0.05).unwrap();

        assert_eq!(report.source, ProfileLoadSource::Backup);
        assert!(report.primary_failed);
        assert!(report.recovered_from_backup);
        assert_eq!(loaded.enrollment_count, 10);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(backup);
    }
}
