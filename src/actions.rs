use std::sync::Arc;

use tokio::process::Command;
use tracing::{info, warn};

use crate::config::ActionHooksConfig;
use crate::monitoring::RuntimeStats;
use crate::policy::PolicyAction;
use crate::risk::RiskEvent;

#[derive(Clone)]
pub struct ActionExecutor {
    hooks: ActionHooksConfig,
    stats: Arc<RuntimeStats>,
}

impl ActionExecutor {
    pub fn new(hooks: ActionHooksConfig, stats: Arc<RuntimeStats>) -> Self {
        Self { hooks, stats }
    }

    pub async fn execute_all(&self, actions: &[PolicyAction], event: &RiskEvent) {
        for action in actions {
            self.execute(action, event).await;
        }
    }

    async fn execute(&self, action: &PolicyAction, event: &RiskEvent) {
        match action {
            PolicyAction::Log => {
                info!(
                    action = action_label(action),
                    risk_score = event.risk_score,
                    confidence = event.confidence,
                    session_id = %event.session_id,
                    "Executed policy log action"
                );
                self.stats.inc_action_successes();
            }
            _ => self.execute_command(action, event).await,
        }
    }

    async fn execute_command(&self, action: &PolicyAction, event: &RiskEvent) {
        let Some(command_parts) = self.command_for_action(action) else {
            warn!(
                action = action_label(action),
                "No action hook configured; skipping policy action"
            );
            self.stats.inc_action_skipped();
            return;
        };

        if command_parts.is_empty() || command_parts[0].trim().is_empty() {
            warn!(
                action = action_label(action),
                "Configured action hook is empty; skipping policy action"
            );
            self.stats.inc_action_skipped();
            return;
        }

        let mut command = Command::new(&command_parts[0]);
        if command_parts.len() > 1 {
            command.args(&command_parts[1..]);
        }

        let event_json = serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string());
        command
            .kill_on_drop(true)
            .env("DWELL_ACTION", action_label(action))
            .env("DWELL_SESSION_ID", event.session_id.to_string())
            .env("DWELL_RISK_SCORE", event.risk_score.to_string())
            .env("DWELL_CONFIDENCE", event.confidence.to_string())
            .env("DWELL_RISK_EVENT", event_json);

        match command.status().await {
            Ok(status) if status.success() => {
                info!(
                    action = action_label(action),
                    exit_code = status.code(),
                    risk_score = event.risk_score,
                    "Policy action hook completed successfully"
                );
                self.stats.inc_action_successes();
            }
            Ok(status) => {
                warn!(
                    action = action_label(action),
                    exit_code = status.code(),
                    risk_score = event.risk_score,
                    "Policy action hook exited unsuccessfully"
                );
                self.stats.inc_action_failures();
            }
            Err(e) => {
                warn!(
                    action = action_label(action),
                    error = %e,
                    risk_score = event.risk_score,
                    "Policy action hook failed to start"
                );
                self.stats.inc_action_failures();
            }
        }
    }

    fn command_for_action(&self, action: &PolicyAction) -> Option<&Vec<String>> {
        match action {
            PolicyAction::Log => None,
            PolicyAction::EmitSiemTag => self.hooks.emit_siem_tag.as_ref(),
            PolicyAction::TriggerReVerification => self.hooks.trigger_re_verification.as_ref(),
            PolicyAction::TriggerStepUp => self.hooks.trigger_step_up.as_ref(),
            PolicyAction::TerminateSession => self.hooks.terminate_session.as_ref(),
        }
    }
}

fn action_label(action: &PolicyAction) -> &'static str {
    match action {
        PolicyAction::Log => "log",
        PolicyAction::EmitSiemTag => "emit_siem_tag",
        PolicyAction::TriggerReVerification => "trigger_re_verification",
        PolicyAction::TriggerStepUp => "trigger_step_up",
        PolicyAction::TerminateSession => "terminate_session",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ActionHooksConfig;
    use crate::features::FeatureName;
    use crate::policy::PolicyAction;
    use uuid::Uuid;

    fn sample_event() -> RiskEvent {
        RiskEvent {
            session_id: Uuid::nil(),
            timestamp_utc: "2026-01-01T00:00:00Z".to_string(),
            risk_score: 82,
            confidence: 0.91,
            anomalous_features: vec![FeatureName::Wpm],
            window_keystrokes: 64,
            model_version: "1.0.0".to_string(),
        }
    }

    #[tokio::test]
    async fn test_log_action_counts_as_success() {
        let stats = Arc::new(RuntimeStats::new());
        let executor = ActionExecutor::new(ActionHooksConfig::default(), stats.clone());
        executor
            .execute_all(&[PolicyAction::Log], &sample_event())
            .await;

        let snap = stats.snapshot();
        assert_eq!(snap.action_successes, 1);
        assert_eq!(snap.action_failures, 0);
    }

    #[tokio::test]
    async fn test_missing_hook_is_skipped() {
        let stats = Arc::new(RuntimeStats::new());
        let executor = ActionExecutor::new(ActionHooksConfig::default(), stats.clone());
        executor
            .execute_all(&[PolicyAction::TriggerStepUp], &sample_event())
            .await;

        let snap = stats.snapshot();
        assert_eq!(snap.action_skipped, 1);
        assert_eq!(snap.action_successes, 0);
    }

    #[tokio::test]
    async fn test_hook_success_and_failure_are_counted() {
        let stats = Arc::new(RuntimeStats::new());
        let hooks = ActionHooksConfig {
            trigger_step_up: Some(vec!["true".to_string()]),
            terminate_session: Some(vec!["definitely-not-a-real-command".to_string()]),
            ..ActionHooksConfig::default()
        };
        let executor = ActionExecutor::new(hooks, stats.clone());
        executor
            .execute_all(
                &[PolicyAction::TriggerStepUp, PolicyAction::TerminateSession],
                &sample_event(),
            )
            .await;

        let snap = stats.snapshot();
        assert_eq!(snap.action_successes, 1);
        assert_eq!(snap.action_failures, 1);
    }
}
