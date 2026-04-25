use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::{error, info};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("Watcher error: {0}")]
    Watcher(#[from] notify::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskTier {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    Log,
    EmitSiemTag,
    TriggerReVerification,
    TriggerStepUp,
    TerminateSession,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TierConfig {
    pub low_max: u8,
    pub med_max: u8,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActionsConfig {
    pub low: Vec<String>,
    pub med: Vec<String>,
    pub high: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConfig {
    pub tiers: TierConfig,
    pub actions: ActionsConfig,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            tiers: TierConfig {
                low_max: 40,
                med_max: 70,
            },
            actions: ActionsConfig {
                low: vec!["log".to_string()],
                med: vec![
                    "log".to_string(),
                    "emit_siem_tag".to_string(),
                    "trigger_re_verification".to_string(),
                ],
                high: vec![
                    "log".to_string(),
                    "emit_siem_tag".to_string(),
                    "trigger_step_up".to_string(),
                    "terminate_session".to_string(),
                ],
            },
        }
    }
}

fn parse_action(s: &str) -> Option<PolicyAction> {
    match s {
        "log" => Some(PolicyAction::Log),
        "emit_siem_tag" => Some(PolicyAction::EmitSiemTag),
        "trigger_re_verification" => Some(PolicyAction::TriggerReVerification),
        "trigger_step_up" => Some(PolicyAction::TriggerStepUp),
        "terminate_session" => Some(PolicyAction::TerminateSession),
        _ => None,
    }
}

pub struct PolicyEngine {
    config: Arc<RwLock<PolicyConfig>>,
    _watcher: Option<RecommendedWatcher>,
}

impl PolicyEngine {
    pub fn new(policy_file: &str) -> Result<Self, PolicyError> {
        let config = load_policy_config(policy_file).unwrap_or_default();
        let config = Arc::new(RwLock::new(config));
        let config_clone = config.clone();
        let policy_file_owned = policy_file.to_string();

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            match res {
                Ok(event) => {
                    if event.kind.is_modify() || event.kind.is_create() {
                        match load_policy_config(&policy_file_owned) {
                            Ok(new_config) => {
                                if let Ok(mut w) = config_clone.write() {
                                    *w = new_config;
                                    info!("Policy reloaded from {}", policy_file_owned);
                                }
                            }
                            Err(e) => {
                                error!("Failed to reload policy: {}", e);
                            }
                        }
                    }
                }
                Err(e) => error!("Watch error: {}", e),
            }
        })?;

        if Path::new(policy_file).exists() {
            watcher.watch(Path::new(policy_file), RecursiveMode::NonRecursive)?;
        }

        Ok(Self {
            config,
            _watcher: Some(watcher),
        })
    }

    pub fn new_default() -> Self {
        Self {
            config: Arc::new(RwLock::new(PolicyConfig::default())),
            _watcher: None,
        }
    }

    pub fn evaluate(&self, risk_score: u8) -> Vec<PolicyAction> {
        let config = self.config.read().unwrap();
        let tier = if risk_score <= config.tiers.low_max {
            RiskTier::Low
        } else if risk_score <= config.tiers.med_max {
            RiskTier::Medium
        } else {
            RiskTier::High
        };

        let action_strings = match tier {
            RiskTier::Low => &config.actions.low,
            RiskTier::Medium => &config.actions.med,
            RiskTier::High => &config.actions.high,
        };

        action_strings
            .iter()
            .filter_map(|s| parse_action(s))
            .collect()
    }

    pub fn reload(&self, policy_file: &str) -> Result<(), PolicyError> {
        let new_config = load_policy_config(policy_file)?;
        if let Ok(mut w) = self.config.write() {
            *w = new_config;
        }
        Ok(())
    }
}

fn load_policy_config(path: &str) -> Result<PolicyConfig, PolicyError> {
    let content = std::fs::read_to_string(path)?;
    let config: PolicyConfig = toml::from_str(&content)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_engine() -> PolicyEngine {
        PolicyEngine {
            config: Arc::new(RwLock::new(PolicyConfig::default())),
            _watcher: None,
        }
    }

    #[test]
    fn test_low_risk_actions() {
        let engine = default_engine();
        let actions = engine.evaluate(20);
        assert_eq!(actions, vec![PolicyAction::Log]);
    }

    #[test]
    fn test_medium_risk_actions() {
        let engine = default_engine();
        let actions = engine.evaluate(55);
        assert!(actions.contains(&PolicyAction::Log));
        assert!(actions.contains(&PolicyAction::EmitSiemTag));
        assert!(actions.contains(&PolicyAction::TriggerReVerification));
    }

    #[test]
    fn test_high_risk_actions() {
        let engine = default_engine();
        let actions = engine.evaluate(90);
        assert!(actions.contains(&PolicyAction::Log));
        assert!(actions.contains(&PolicyAction::EmitSiemTag));
        assert!(actions.contains(&PolicyAction::TriggerStepUp));
        assert!(actions.contains(&PolicyAction::TerminateSession));
    }

    #[test]
    fn test_boundary_low_max() {
        let engine = default_engine();
        let actions = engine.evaluate(40);
        assert_eq!(actions, vec![PolicyAction::Log]);
    }

    #[test]
    fn test_boundary_med_max() {
        let engine = default_engine();
        let actions = engine.evaluate(70);
        assert!(actions.contains(&PolicyAction::TriggerReVerification));
    }

    #[test]
    fn test_boundary_high() {
        let engine = default_engine();
        let actions = engine.evaluate(71);
        assert!(actions.contains(&PolicyAction::TriggerStepUp));
        assert!(actions.contains(&PolicyAction::TerminateSession));
    }
}
