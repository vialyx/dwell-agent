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
        }
    }
}

pub fn load_config() -> AgentConfig {
    use figment::{providers::{Env, Format, Serialized, Toml}, Figment};
    Figment::from(Serialized::defaults(AgentConfig::default()))
        .merge(Toml::file("dwell-agent.toml"))
        .merge(Env::prefixed("DWELL_"))
        .extract()
        .unwrap_or_default()
}
