use serde::{Deserialize, Serialize};

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
    pub log_level: String,
    pub ipc_socket: String,
    pub webhook_url: Option<String>,
    pub webhook_min_risk_score: u8,
    pub webhook_timeout_secs: u64,
    pub metrics_log_interval_secs: u64,
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
            log_level: "info".to_string(),
            ipc_socket: "/tmp/dwell-agent.sock".to_string(),
            webhook_url: None,
            webhook_min_risk_score: 0,
            webhook_timeout_secs: 5,
            metrics_log_interval_secs: 60,
        }
    }
}

pub fn load_config() -> AgentConfig {
    use figment::{
        providers::{Env, Format, Serialized, Toml},
        Figment,
    };
    Figment::from(Serialized::defaults(AgentConfig::default()))
        .merge(Toml::file("dwell-agent.toml"))
        .merge(Env::prefixed("DWELL_"))
        .extract()
        .unwrap_or_default()
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
        assert_eq!(
            decoded.metrics_log_interval_secs,
            cfg.metrics_log_interval_secs
        );
    }
}
