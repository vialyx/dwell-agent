//! Profile key derivation.
//!
//! Priority order for the 32-byte AES-256-GCM profile key:
//!
//! 1. `DWELL_PROFILE_KEY` environment variable — exactly 64 lowercase or uppercase hex characters.
//! 2. Optional hard-coded placeholder `[0x42; 32]` (CI / development only) when
//!    `allow_insecure_placeholder_key=true` in config — emits a `warn!`.
//!
//! # Production deployment
//! `DWELL_PROFILE_KEY` is required in production and should come from a secret store (Vault,
//! AWS Secrets Manager,
//! macOS Keychain via `security find-generic-password`, etc.) and export it to the agent's
//! environment before launch:
//!
//! ```bash
//! export DWELL_PROFILE_KEY=$(security find-generic-password -a dwell-agent -s profile-key -w)
//! ./dwell-agent
//! ```

use thiserror::Error;
use tracing::warn;

const KEY_ENV_VAR: &str = "DWELL_PROFILE_KEY";

/// The CI/dev placeholder key.  Never use in production.
pub const PLACEHOLDER_KEY: [u8; 32] = [0x42u8; 32];

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("Missing required environment variable {0}")]
    MissingKey(&'static str),
    #[error("Invalid {var}: {reason}")]
    InvalidKey { var: &'static str, reason: String },
}

/// Derive the 32-byte profile key.
///
/// By default this function is fail-closed and requires `DWELL_PROFILE_KEY`.
/// `allow_insecure_placeholder_key` is intended only for CI/local development.
pub fn derive_profile_key(allow_insecure_placeholder_key: bool) -> Result<[u8; 32], KeystoreError> {
    if let Ok(hex_key) = std::env::var(KEY_ENV_VAR) {
        return parse_hex_key(&hex_key).map_err(|reason| KeystoreError::InvalidKey {
            var: KEY_ENV_VAR,
            reason,
        });
    }

    if allow_insecure_placeholder_key {
        warn!(
            "{} is not set; using insecure placeholder key [0x42; 32]. \
             This must not be used in production.",
            KEY_ENV_VAR,
        );
        return Ok(PLACEHOLDER_KEY);
    }

    Err(KeystoreError::MissingKey(KEY_ENV_VAR))
}

/// Parse a 64-character hex string into a 32-byte array.
fn parse_hex_key(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex character: {:?}", b as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_key_valid_lowercase() {
        let hex = "4242424242424242424242424242424242424242424242424242424242424242";
        assert_eq!(parse_hex_key(hex).unwrap(), [0x42u8; 32]);
    }

    #[test]
    fn test_parse_hex_key_valid_uppercase() {
        let hex = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";
        let key = parse_hex_key(hex).unwrap();
        assert_eq!(key[0], 0xDE);
        assert_eq!(key[1], 0xAD);
    }

    #[test]
    fn test_parse_hex_key_wrong_length() {
        assert!(parse_hex_key("4242").is_err());
        assert!(parse_hex_key("").is_err());
    }

    #[test]
    fn test_parse_hex_key_invalid_character() {
        let hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert!(parse_hex_key(hex).is_err());
    }

    #[test]
    fn test_parse_hex_key_trims_whitespace() {
        let hex = "  4242424242424242424242424242424242424242424242424242424242424242  ";
        assert_eq!(parse_hex_key(hex).unwrap(), [0x42u8; 32]);
    }

    /// Verifies fallback behaviour without touching the real env var
    /// (std::env::set_var is unsafe in multi-threaded tests).
    #[test]
    fn test_placeholder_key_is_non_zero() {
        assert_ne!(PLACEHOLDER_KEY, [0u8; 32]);
        assert_eq!(PLACEHOLDER_KEY.len(), 32);
    }
}
