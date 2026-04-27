use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Debug)]
pub struct RuntimeStats {
    started_at: Instant,
    keystrokes_seen: AtomicU64,
    risk_events_emitted: AtomicU64,
    policy_evaluations: AtomicU64,
    commands_received: AtomicU64,
    webhook_deliveries: AtomicU64,
    webhook_failures: AtomicU64,
    webhook_events_queued: AtomicU64,
    webhook_queue_depth: AtomicU64,
    action_successes: AtomicU64,
    action_failures: AtomicU64,
    action_skipped: AtomicU64,
    profile_saves: AtomicU64,
    profile_save_failures: AtomicU64,
    profile_load_failures: AtomicU64,
    profile_recoveries: AtomicU64,
    capture_start_failures: AtomicU64,
    policy_reload_successes: AtomicU64,
    policy_reload_failures: AtomicU64,
    management_requests: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStatsSnapshot {
    pub uptime_secs: u64,
    pub keystrokes_seen: u64,
    pub risk_events_emitted: u64,
    pub policy_evaluations: u64,
    pub commands_received: u64,
    pub webhook_deliveries: u64,
    pub webhook_failures: u64,
    pub webhook_events_queued: u64,
    pub webhook_queue_depth: u64,
    pub action_successes: u64,
    pub action_failures: u64,
    pub action_skipped: u64,
    pub profile_saves: u64,
    pub profile_save_failures: u64,
    pub profile_load_failures: u64,
    pub profile_recoveries: u64,
    pub capture_start_failures: u64,
    pub policy_reload_successes: u64,
    pub policy_reload_failures: u64,
    pub management_requests: u64,
}

impl RuntimeStats {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            keystrokes_seen: AtomicU64::new(0),
            risk_events_emitted: AtomicU64::new(0),
            policy_evaluations: AtomicU64::new(0),
            commands_received: AtomicU64::new(0),
            webhook_deliveries: AtomicU64::new(0),
            webhook_failures: AtomicU64::new(0),
            webhook_events_queued: AtomicU64::new(0),
            webhook_queue_depth: AtomicU64::new(0),
            action_successes: AtomicU64::new(0),
            action_failures: AtomicU64::new(0),
            action_skipped: AtomicU64::new(0),
            profile_saves: AtomicU64::new(0),
            profile_save_failures: AtomicU64::new(0),
            profile_load_failures: AtomicU64::new(0),
            profile_recoveries: AtomicU64::new(0),
            capture_start_failures: AtomicU64::new(0),
            policy_reload_successes: AtomicU64::new(0),
            policy_reload_failures: AtomicU64::new(0),
            management_requests: AtomicU64::new(0),
        }
    }

    pub fn inc_keystrokes_seen(&self) {
        self.keystrokes_seen.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_risk_events_emitted(&self) {
        self.risk_events_emitted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_policy_evaluations(&self) {
        self.policy_evaluations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_commands_received(&self) {
        self.commands_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_webhook_deliveries(&self) {
        self.webhook_deliveries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_webhook_failures(&self) {
        self.webhook_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_webhook_events_queued(&self) {
        self.webhook_events_queued.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_webhook_queue_depth(&self) {
        self.webhook_queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_webhook_queue_depth(&self) {
        let _ =
            self.webhook_queue_depth
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some(value.saturating_sub(1))
                });
    }

    pub fn set_webhook_queue_depth(&self, depth: u64) {
        self.webhook_queue_depth.store(depth, Ordering::Relaxed);
    }

    pub fn inc_action_successes(&self) {
        self.action_successes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_action_failures(&self) {
        self.action_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_action_skipped(&self) {
        self.action_skipped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_profile_saves(&self) {
        self.profile_saves.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_profile_save_failures(&self) {
        self.profile_save_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_profile_load_failures(&self) {
        self.profile_load_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_profile_recoveries(&self) {
        self.profile_recoveries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_capture_start_failures(&self) {
        self.capture_start_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_policy_reload_successes(&self) {
        self.policy_reload_successes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_policy_reload_failures(&self) {
        self.policy_reload_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_management_requests(&self) {
        self.management_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> RuntimeStatsSnapshot {
        RuntimeStatsSnapshot {
            uptime_secs: self.started_at.elapsed().as_secs(),
            keystrokes_seen: self.keystrokes_seen.load(Ordering::Relaxed),
            risk_events_emitted: self.risk_events_emitted.load(Ordering::Relaxed),
            policy_evaluations: self.policy_evaluations.load(Ordering::Relaxed),
            commands_received: self.commands_received.load(Ordering::Relaxed),
            webhook_deliveries: self.webhook_deliveries.load(Ordering::Relaxed),
            webhook_failures: self.webhook_failures.load(Ordering::Relaxed),
            webhook_events_queued: self.webhook_events_queued.load(Ordering::Relaxed),
            webhook_queue_depth: self.webhook_queue_depth.load(Ordering::Relaxed),
            action_successes: self.action_successes.load(Ordering::Relaxed),
            action_failures: self.action_failures.load(Ordering::Relaxed),
            action_skipped: self.action_skipped.load(Ordering::Relaxed),
            profile_saves: self.profile_saves.load(Ordering::Relaxed),
            profile_save_failures: self.profile_save_failures.load(Ordering::Relaxed),
            profile_load_failures: self.profile_load_failures.load(Ordering::Relaxed),
            profile_recoveries: self.profile_recoveries.load(Ordering::Relaxed),
            capture_start_failures: self.capture_start_failures.load(Ordering::Relaxed),
            policy_reload_successes: self.policy_reload_successes.load(Ordering::Relaxed),
            policy_reload_failures: self.policy_reload_failures.load(Ordering::Relaxed),
            management_requests: self.management_requests.load(Ordering::Relaxed),
        }
    }
}

impl Default for RuntimeStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_counters_increment() {
        let stats = RuntimeStats::new();
        stats.inc_keystrokes_seen();
        stats.inc_keystrokes_seen();
        stats.inc_risk_events_emitted();
        stats.inc_policy_evaluations();
        stats.inc_commands_received();
        stats.inc_webhook_deliveries();
        stats.inc_webhook_failures();
        stats.inc_webhook_events_queued();
        stats.inc_webhook_queue_depth();
        stats.inc_action_successes();
        stats.inc_action_failures();
        stats.inc_action_skipped();
        stats.inc_profile_saves();
        stats.inc_profile_save_failures();
        stats.inc_profile_load_failures();
        stats.inc_profile_recoveries();
        stats.inc_capture_start_failures();
        stats.inc_policy_reload_successes();
        stats.inc_policy_reload_failures();
        stats.inc_management_requests();

        let snap = stats.snapshot();
        assert_eq!(snap.keystrokes_seen, 2);
        assert_eq!(snap.risk_events_emitted, 1);
        assert_eq!(snap.policy_evaluations, 1);
        assert_eq!(snap.commands_received, 1);
        assert_eq!(snap.webhook_deliveries, 1);
        assert_eq!(snap.webhook_failures, 1);
        assert_eq!(snap.webhook_events_queued, 1);
        assert_eq!(snap.webhook_queue_depth, 1);
        assert_eq!(snap.action_successes, 1);
        assert_eq!(snap.action_failures, 1);
        assert_eq!(snap.action_skipped, 1);
        assert_eq!(snap.profile_saves, 1);
        assert_eq!(snap.profile_save_failures, 1);
        assert_eq!(snap.profile_load_failures, 1);
        assert_eq!(snap.profile_recoveries, 1);
        assert_eq!(snap.capture_start_failures, 1);
        assert_eq!(snap.policy_reload_successes, 1);
        assert_eq!(snap.policy_reload_failures, 1);
        assert_eq!(snap.management_requests, 1);
    }

    #[test]
    fn test_uptime_is_non_negative() {
        let stats = RuntimeStats::new();
        let snap = stats.snapshot();
        assert!(snap.uptime_secs < 2);
    }

    #[test]
    fn test_queue_depth_saturates_on_decrement() {
        let stats = RuntimeStats::new();
        stats.dec_webhook_queue_depth();
        assert_eq!(stats.snapshot().webhook_queue_depth, 0);

        stats.inc_webhook_queue_depth();
        stats.dec_webhook_queue_depth();
        stats.dec_webhook_queue_depth();
        assert_eq!(stats.snapshot().webhook_queue_depth, 0);
    }
}
