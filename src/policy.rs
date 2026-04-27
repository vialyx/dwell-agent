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
    #[error("Validation error: {0}")]
    Validation(String),
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

#[derive(Debug, Clone)]
struct CompiledPolicy {
    tiers: TierConfig,
    low: Vec<PolicyAction>,
    med: Vec<PolicyAction>,
    high: Vec<PolicyAction>,
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

fn parse_action(s: &str) -> Result<PolicyAction, PolicyError> {
    match s {
        "log" => Ok(PolicyAction::Log),
        "emit_siem_tag" => Ok(PolicyAction::EmitSiemTag),
        "trigger_re_verification" => Ok(PolicyAction::TriggerReVerification),
        "trigger_step_up" => Ok(PolicyAction::TriggerStepUp),
        "terminate_session" => Ok(PolicyAction::TerminateSession),
        _ => Err(PolicyError::Validation(format!(
            "unknown action '{s}' in policy",
        ))),
    }
}

fn compile_policy(config: PolicyConfig) -> Result<CompiledPolicy, PolicyError> {
    if config.tiers.low_max > config.tiers.med_max {
        return Err(PolicyError::Validation(
            "tiers.low_max must be <= tiers.med_max".to_string(),
        ));
    }

    let low = config
        .actions
        .low
        .iter()
        .map(|s| parse_action(s))
        .collect::<Result<Vec<_>, _>>()?;
    let med = config
        .actions
        .med
        .iter()
        .map(|s| parse_action(s))
        .collect::<Result<Vec<_>, _>>()?;
    let high = config
        .actions
        .high
        .iter()
        .map(|s| parse_action(s))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CompiledPolicy {
        tiers: config.tiers,
        low,
        med,
        high,
    })
}

pub struct PolicyEngine {
    config: Arc<RwLock<CompiledPolicy>>,
    _watcher: Option<RecommendedWatcher>,
}

impl PolicyEngine {
    pub fn new(policy_file: &str) -> Result<Self, PolicyError> {
        let config = compile_policy(load_policy_config(policy_file)?)?;
        let config = Arc::new(RwLock::new(config));
        let config_clone = config.clone();
        let policy_file_owned = policy_file.to_string();

        let mut watcher =
            notify::recommended_watcher(move |res: notify::Result<Event>| match res {
                Ok(event) => {
                    if event.kind.is_modify() || event.kind.is_create() {
                        match load_policy_config(&policy_file_owned) {
                            Ok(new_config) => match compile_policy(new_config) {
                                Ok(compiled) => {
                                    if let Ok(mut w) = config_clone.write() {
                                        *w = compiled;
                                        info!("Policy reloaded from {}", policy_file_owned);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to validate reloaded policy: {}", e);
                                }
                            },
                            Err(e) => {
                                error!("Failed to reload policy: {}", e);
                            }
                        }
                    }
                }
                Err(e) => error!("Watch error: {}", e),
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
            config: Arc::new(RwLock::new(
                compile_policy(PolicyConfig::default()).expect("default policy must compile"),
            )),
            _watcher: None,
        }
    }

    pub fn evaluate(&self, risk_score: u8) -> Vec<PolicyAction> {
        // unwrap_or_else: recover from a poisoned lock by using the inner value
        let config = self.config.read().unwrap_or_else(|p| p.into_inner());
        let tier = if risk_score <= config.tiers.low_max {
            RiskTier::Low
        } else if risk_score <= config.tiers.med_max {
            RiskTier::Medium
        } else {
            RiskTier::High
        };

        match tier {
            RiskTier::Low => config.low.clone(),
            RiskTier::Medium => config.med.clone(),
            RiskTier::High => config.high.clone(),
        }
    }

    pub fn reload(&self, policy_file: &str) -> Result<(), PolicyError> {
        let new_config = compile_policy(load_policy_config(policy_file)?)?;
        let mut w = self.config.write().unwrap_or_else(|p| p.into_inner());
        *w = new_config;
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
    use std::time::{SystemTime, UNIX_EPOCH};

    fn default_engine() -> PolicyEngine {
        PolicyEngine {
            config: Arc::new(RwLock::new(
                compile_policy(PolicyConfig::default()).unwrap(),
            )),
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

    #[test]
    fn test_parse_action_unknown_returns_error() {
        assert!(parse_action("unknown_action").is_err());
    }

    #[test]
    fn test_compile_policy_invalid_tier_order() {
        let cfg = PolicyConfig {
            tiers: TierConfig {
                low_max: 80,
                med_max: 70,
            },
            actions: ActionsConfig {
                low: vec!["log".to_string()],
                med: vec!["log".to_string()],
                high: vec!["log".to_string()],
            },
        };
        assert!(compile_policy(cfg).is_err());
    }

    #[test]
    fn test_reload_policy_from_file() {
        let mut path = std::env::temp_dir();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        path.push(format!("dwell-agent-policy-{suffix}.toml"));

        let policy = r#"
[tiers]
low_max = 10
med_max = 20

[actions]
low = ["log"]
med = ["log", "emit_siem_tag"]
high = ["terminate_session"]
"#;

        std::fs::write(&path, policy).expect("write temp policy");

        let engine = default_engine();
        engine
            .reload(path.to_str().expect("utf8 path"))
            .expect("reload policy");

        let medium_actions = engine.evaluate(15);
        assert!(medium_actions.contains(&PolicyAction::EmitSiemTag));
        let high_actions = engine.evaluate(30);
        assert_eq!(high_actions, vec![PolicyAction::TerminateSession]);

        let _ = std::fs::remove_file(path);
    }
}
