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
}

#[derive(Debug, Clone)]
pub struct RuntimeStatsSnapshot {
    pub uptime_secs: u64,
    pub keystrokes_seen: u64,
    pub risk_events_emitted: u64,
    pub policy_evaluations: u64,
    pub commands_received: u64,
    pub webhook_deliveries: u64,
    pub webhook_failures: u64,
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

    pub fn snapshot(&self) -> RuntimeStatsSnapshot {
        RuntimeStatsSnapshot {
            uptime_secs: self.started_at.elapsed().as_secs(),
            keystrokes_seen: self.keystrokes_seen.load(Ordering::Relaxed),
            risk_events_emitted: self.risk_events_emitted.load(Ordering::Relaxed),
            policy_evaluations: self.policy_evaluations.load(Ordering::Relaxed),
            commands_received: self.commands_received.load(Ordering::Relaxed),
            webhook_deliveries: self.webhook_deliveries.load(Ordering::Relaxed),
            webhook_failures: self.webhook_failures.load(Ordering::Relaxed),
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

        let snap = stats.snapshot();
        assert_eq!(snap.keystrokes_seen, 2);
        assert_eq!(snap.risk_events_emitted, 1);
        assert_eq!(snap.policy_evaluations, 1);
        assert_eq!(snap.commands_received, 1);
        assert_eq!(snap.webhook_deliveries, 1);
        assert_eq!(snap.webhook_failures, 1);
    }

    #[test]
    fn test_uptime_is_non_negative() {
        let stats = RuntimeStats::new();
        let snap = stats.snapshot();
        assert!(snap.uptime_secs < 2);
    }
}
