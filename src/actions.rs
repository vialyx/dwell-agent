use std::sync::Arc;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::config::ActionHooksConfig;
use crate::monitoring::RuntimeStats;
use crate::policy::PolicyAction;
use crate::risk::RiskEvent;

#[derive(Clone)]
pub struct ActionExecutor {
    hooks: ActionHooksConfig,
    action_hook_timeout_secs: u64,
    stats: Arc<RuntimeStats>,
}

impl ActionExecutor {
    pub fn new(
        hooks: ActionHooksConfig,
        action_hook_timeout_secs: u64,
        stats: Arc<RuntimeStats>,
    ) -> Self {
        Self {
            hooks,
            action_hook_timeout_secs,
            stats,
        }
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

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                warn!(
                    action = action_label(action),
                    error = %e,
                    risk_score = event.risk_score,
                    "Policy action hook failed to start"
                );
                self.stats.inc_action_failures();
                return;
            }
        };

        match timeout(
            Duration::from_secs(self.action_hook_timeout_secs),
            child.wait(),
        )
        .await
        {
            Ok(Ok(status)) if status.success() => {
                info!(
                    action = action_label(action),
                    exit_code = status.code(),
                    risk_score = event.risk_score,
                    "Policy action hook completed successfully"
                );
                self.stats.inc_action_successes();
            }
            Ok(Ok(status)) => {
                warn!(
                    action = action_label(action),
                    exit_code = status.code(),
                    risk_score = event.risk_score,
                    "Policy action hook exited unsuccessfully"
                );
                self.stats.inc_action_failures();
            }
            Ok(Err(e)) => {
                warn!(
                    action = action_label(action),
                    error = %e,
                    risk_score = event.risk_score,
                    "Policy action hook failed while running"
                );
                self.stats.inc_action_failures();
            }
            Err(_) => {
                if let Err(e) = child.kill().await {
                    warn!(
                        action = action_label(action),
                        error = %e,
                        "Timed-out policy action hook kill failed"
                    );
                }
                warn!(
                    action = action_label(action),
                    timeout_secs = self.action_hook_timeout_secs,
                    risk_score = event.risk_score,
                    "Policy action hook timed out"
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
        let executor = ActionExecutor::new(ActionHooksConfig::default(), 5, stats.clone());
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
        let executor = ActionExecutor::new(ActionHooksConfig::default(), 5, stats.clone());
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
        #[cfg(unix)]
        let success_hook = vec!["true".to_string()];
        #[cfg(windows)]
        let success_hook = vec!["cmd".to_string(), "/C".to_string(), "exit 0".to_string()];

        let hooks = ActionHooksConfig {
            trigger_step_up: Some(success_hook),
            terminate_session: Some(vec!["definitely-not-a-real-command".to_string()]),
            ..ActionHooksConfig::default()
        };
        let executor = ActionExecutor::new(hooks, 5, stats.clone());
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

    #[tokio::test]
    async fn test_timed_out_hook_is_counted_as_failure() {
        let stats = Arc::new(RuntimeStats::new());
        #[cfg(unix)]
        let timeout_hook = vec!["sleep".to_string(), "2".to_string()];
        #[cfg(windows)]
        let timeout_hook = vec![
            "powershell".to_string(),
            "-NoProfile".to_string(),
            "-Command".to_string(),
            "Start-Sleep -Seconds 2".to_string(),
        ];

        let hooks = ActionHooksConfig {
            terminate_session: Some(timeout_hook),
            ..ActionHooksConfig::default()
        };
        let executor = ActionExecutor::new(hooks, 1, stats.clone());
        executor
            .execute_all(&[PolicyAction::TerminateSession], &sample_event())
            .await;

        let snap = stats.snapshot();
        assert_eq!(snap.action_failures, 1);
    }
}
