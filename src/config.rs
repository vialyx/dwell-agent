use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use thiserror::Error;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ActionHooksConfig {
    pub emit_siem_tag: Option<Vec<String>>,
    pub trigger_re_verification: Option<Vec<String>>,
    pub trigger_step_up: Option<Vec<String>>,
    pub terminate_session: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentConfig {
    pub window_size: usize,
    pub emit_interval_secs: u64,
    pub min_enrollment_keystrokes: usize,
    pub ema_alpha: f64,
    pub risk_threshold: f64,
    pub risk_k: f64,
    pub policy_file: String,
    pub profile_path: String,
    pub profile_autosave_secs: u64,
    pub log_level: String,
    pub ipc_socket: String,
    pub ipc_tcp_bind: String,
    pub ipc_require_same_user: bool,
    pub management_bind: String,
    pub allow_insecure_placeholder_key: bool,
    pub webhook_url: Option<String>,
    pub webhook_spool_dir: String,
    pub webhook_min_risk_score: u8,
    pub webhook_timeout_secs: u64,
    pub metrics_log_interval_secs: u64,
    #[serde(default)]
    pub action_hooks: ActionHooksConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            window_size: 50,
            emit_interval_secs: 30,
            min_enrollment_keystrokes: 2000,
            ema_alpha: 0.05,
            risk_threshold: 5.0,
            risk_k: 1.0,
            policy_file: "policy.toml".to_string(),
            profile_path: "profile.enc".to_string(),
            profile_autosave_secs: 300,
            log_level: "info".to_string(),
            ipc_socket: "/tmp/dwell-agent/dwell-agent.sock".to_string(),
            ipc_tcp_bind: "127.0.0.1:9465".to_string(),
            ipc_require_same_user: true,
            management_bind: "127.0.0.1:9464".to_string(),
            allow_insecure_placeholder_key: false,
            webhook_url: None,
            webhook_spool_dir: "webhook-spool".to_string(),
            webhook_min_risk_score: 0,
            webhook_timeout_secs: 5,
            metrics_log_interval_secs: 60,
            action_hooks: ActionHooksConfig::default(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to load configuration: {0}")]
    Load(Box<figment::Error>),
    #[error("Invalid configuration: {0}")]
    Validation(String),
}

impl AgentConfig {
    fn validate_command_hook(label: &str, hook: &Option<Vec<String>>) -> Result<(), ConfigError> {
        if let Some(parts) = hook {
            if parts.is_empty() || parts[0].trim().is_empty() {
                return Err(ConfigError::Validation(format!(
                    "action hook '{label}' must contain a non-empty executable"
                )));
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.window_size == 0 {
            return Err(ConfigError::Validation(
                "window_size must be > 0".to_string(),
            ));
        }
        if self.emit_interval_secs == 0 {
            return Err(ConfigError::Validation(
                "emit_interval_secs must be > 0".to_string(),
            ));
        }
        if self.min_enrollment_keystrokes < self.window_size {
            return Err(ConfigError::Validation(
                "min_enrollment_keystrokes must be >= window_size".to_string(),
            ));
        }
        if !(0.0..=1.0).contains(&self.ema_alpha) || self.ema_alpha == 0.0 {
            return Err(ConfigError::Validation(
                "ema_alpha must be in (0, 1]".to_string(),
            ));
        }
        if self.risk_k <= 0.0 {
            return Err(ConfigError::Validation("risk_k must be > 0".to_string()));
        }
        if self.profile_path.trim().is_empty() {
            return Err(ConfigError::Validation(
                "profile_path must not be empty".to_string(),
            ));
        }
        if self.policy_file.trim().is_empty() {
            return Err(ConfigError::Validation(
                "policy_file must not be empty".to_string(),
            ));
        }
        if self.profile_autosave_secs == 0 {
            return Err(ConfigError::Validation(
                "profile_autosave_secs must be > 0".to_string(),
            ));
        }
        if self.webhook_timeout_secs == 0 {
            return Err(ConfigError::Validation(
                "webhook_timeout_secs must be > 0".to_string(),
            ));
        }
        if self.metrics_log_interval_secs == 0 {
            return Err(ConfigError::Validation(
                "metrics_log_interval_secs must be > 0".to_string(),
            ));
        }
        if self.ipc_socket.trim().is_empty() {
            return Err(ConfigError::Validation(
                "ipc_socket must not be empty".to_string(),
            ));
        }
        if self.ipc_socket.len() > 100 {
            return Err(ConfigError::Validation(
                "ipc_socket is too long for a portable Unix-domain socket path".to_string(),
            ));
        }
        if self.ipc_tcp_bind.trim().is_empty() {
            return Err(ConfigError::Validation(
                "ipc_tcp_bind must not be empty".to_string(),
            ));
        }
        let ipc_tcp_addr: SocketAddr = self
            .ipc_tcp_bind
            .parse()
            .map_err(|e| ConfigError::Validation(format!("ipc_tcp_bind must be host:port: {e}")))?;
        if !ipc_tcp_addr.ip().is_loopback() {
            return Err(ConfigError::Validation(
                "ipc_tcp_bind must use a loopback address".to_string(),
            ));
        }
        if self.management_bind.trim().is_empty() {
            return Err(ConfigError::Validation(
                "management_bind must not be empty".to_string(),
            ));
        }
        let management_addr: SocketAddr = self.management_bind.parse().map_err(|e| {
            ConfigError::Validation(format!("management_bind must be host:port: {e}"))
        })?;
        if !management_addr.ip().is_loopback() {
            return Err(ConfigError::Validation(
                "management_bind must use a loopback address".to_string(),
            ));
        }
        if self.webhook_spool_dir.trim().is_empty() {
            return Err(ConfigError::Validation(
                "webhook_spool_dir must not be empty".to_string(),
            ));
        }
        if let Some(url) = self.webhook_url.as_deref().map(str::trim) {
            if !url.is_empty() {
                let parsed = reqwest::Url::parse(url)
                    .map_err(|e| ConfigError::Validation(format!("webhook_url is invalid: {e}")))?;
                match parsed.scheme() {
                    "http" | "https" => {}
                    other => {
                        return Err(ConfigError::Validation(format!(
                            "webhook_url scheme must be http or https, got {other}"
                        )));
                    }
                }
            }
        }

        Self::validate_command_hook("emit_siem_tag", &self.action_hooks.emit_siem_tag)?;
        Self::validate_command_hook(
            "trigger_re_verification",
            &self.action_hooks.trigger_re_verification,
        )?;
        Self::validate_command_hook("trigger_step_up", &self.action_hooks.trigger_step_up)?;
        Self::validate_command_hook("terminate_session", &self.action_hooks.terminate_session)?;
        Ok(())
    }
}

pub fn load_config() -> Result<AgentConfig, ConfigError> {
    use figment::{
        providers::{Env, Format, Serialized, Toml},
        Figment,
    };
    let cfg: AgentConfig = Figment::from(Serialized::defaults(AgentConfig::default()))
        .merge(Toml::file("dwell-agent.toml"))
        .merge(Env::prefixed("DWELL_"))
        .extract()
        .map_err(|e| ConfigError::Load(Box::new(e)))?;
    cfg.validate()?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values_are_sane() {
        let cfg = AgentConfig::default();
        assert!(cfg.window_size > 0);
        assert!(cfg.emit_interval_secs > 0);
        assert!(cfg.min_enrollment_keystrokes >= cfg.window_size);
        assert!((0.0..=1.0).contains(&cfg.ema_alpha));
        assert!(cfg.risk_k > 0.0);
        assert!(!cfg.policy_file.is_empty());
        assert!(!cfg.profile_path.is_empty());
        assert!(!cfg.ipc_socket.is_empty());
        assert!(!cfg.ipc_tcp_bind.is_empty());
        assert!(!cfg.management_bind.is_empty());
        assert!(cfg.ipc_require_same_user);
        assert!(!cfg.allow_insecure_placeholder_key);
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let cfg = AgentConfig::default();
        let encoded = serde_json::to_string(&cfg).expect("serialize config");
        let decoded: AgentConfig = serde_json::from_str(&encoded).expect("deserialize config");
        assert_eq!(decoded.window_size, cfg.window_size);
        assert_eq!(decoded.emit_interval_secs, cfg.emit_interval_secs);
        assert_eq!(decoded.policy_file, cfg.policy_file);
        assert_eq!(decoded.profile_path, cfg.profile_path);
        assert_eq!(decoded.profile_autosave_secs, cfg.profile_autosave_secs);
        assert_eq!(decoded.ipc_tcp_bind, cfg.ipc_tcp_bind);
        assert_eq!(decoded.management_bind, cfg.management_bind);
        assert_eq!(decoded.webhook_spool_dir, cfg.webhook_spool_dir);
        assert_eq!(
            decoded.metrics_log_interval_secs,
            cfg.metrics_log_interval_secs
        );
    }

    #[test]
    fn test_invalid_management_bind_is_rejected() {
        let cfg = AgentConfig {
            management_bind: "0.0.0.0:9464".to_string(),
            ..AgentConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_invalid_ipc_tcp_bind_is_rejected() {
        let cfg = AgentConfig {
            ipc_tcp_bind: "0.0.0.0:9465".to_string(),
            ..AgentConfig::default()
        };
        assert!(cfg.validate().is_err());
    }
}
