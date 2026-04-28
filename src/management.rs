use std::sync::Arc;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::monitoring::{RuntimeStats, RuntimeStatsSnapshot};

pub async fn run_management_server(
    bind_addr: String,
    stats: Arc<RuntimeStats>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(&bind_addr).await?;
    let local_addr = listener.local_addr()?;
    info!(address = %local_addr, "Management server listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let stats = stats.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, stats).await {
                warn!(error = %e, "Management request failed");
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    stats: Arc<RuntimeStats>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or_default();
    let path = first_line.split_whitespace().nth(1).unwrap_or("/");

    stats.inc_management_requests();
    let response = build_response(path, &stats.snapshot());
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

fn build_response(path: &str, snapshot: &RuntimeStatsSnapshot) -> String {
    let ready = is_ready(snapshot);
    let (status_line, content_type, body) = match path {
        "/healthz" => (
            "HTTP/1.1 200 OK",
            "application/json",
            serde_json::to_string(&json!({
                "status": "ok",
                "degraded": is_degraded(snapshot),
                "stats": snapshot,
            }))
            .unwrap_or_else(|_| "{\"status\":\"ok\"}".to_string()),
        ),
        "/readyz" => {
            let status = if ready {
                "HTTP/1.1 200 OK"
            } else {
                "HTTP/1.1 503 Service Unavailable"
            };
            let body = serde_json::to_string(&json!({
                "ready": ready,
                "degraded": is_degraded(snapshot),
            }))
            .unwrap_or_else(|_| "{\"ready\":false}".to_string());
            (status, "application/json", body)
        }
        "/metrics" => (
            "HTTP/1.1 200 OK",
            "text/plain; version=0.0.4",
            render_prometheus_metrics(snapshot),
        ),
        _ => (
            "HTTP/1.1 404 Not Found",
            "application/json",
            "{\"error\":\"not found\"}".to_string(),
        ),
    };

    format!(
        "{status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn is_degraded(snapshot: &RuntimeStatsSnapshot) -> bool {
    snapshot.capture_start_failures > 0
        || snapshot.profile_load_failures > snapshot.profile_recoveries
        || snapshot.profile_save_failures > 0
        || snapshot.policy_reload_failures > 0
}

fn is_ready(snapshot: &RuntimeStatsSnapshot) -> bool {
    snapshot.profile_save_failures == 0
        && snapshot.profile_load_failures <= snapshot.profile_recoveries
        && snapshot.policy_reload_failures == 0
}

pub fn render_prometheus_metrics(snapshot: &RuntimeStatsSnapshot) -> String {
    let mut lines = Vec::with_capacity(48);
    push_metric(
        &mut lines,
        "gauge",
        "dwell_agent_uptime_seconds",
        snapshot.uptime_secs,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_keystrokes_seen_total",
        snapshot.keystrokes_seen,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_risk_events_emitted_total",
        snapshot.risk_events_emitted,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_policy_evaluations_total",
        snapshot.policy_evaluations,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_commands_received_total",
        snapshot.commands_received,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_webhook_deliveries_total",
        snapshot.webhook_deliveries,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_webhook_failures_total",
        snapshot.webhook_failures,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_webhook_events_queued_total",
        snapshot.webhook_events_queued,
    );
    push_metric(
        &mut lines,
        "gauge",
        "dwell_agent_webhook_queue_depth",
        snapshot.webhook_queue_depth,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_action_successes_total",
        snapshot.action_successes,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_action_failures_total",
        snapshot.action_failures,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_action_skipped_total",
        snapshot.action_skipped,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_profile_saves_total",
        snapshot.profile_saves,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_profile_save_failures_total",
        snapshot.profile_save_failures,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_profile_load_failures_total",
        snapshot.profile_load_failures,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_profile_recoveries_total",
        snapshot.profile_recoveries,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_capture_start_failures_total",
        snapshot.capture_start_failures,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_policy_reload_successes_total",
        snapshot.policy_reload_successes,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_policy_reload_failures_total",
        snapshot.policy_reload_failures,
    );
    push_metric(
        &mut lines,
        "counter",
        "dwell_agent_management_requests_total",
        snapshot.management_requests,
    );
    lines.join("\n") + "\n"
}

fn push_metric(lines: &mut Vec<String>, metric_type: &str, name: &str, value: u64) {
    lines.push(format!("# TYPE {name} {metric_type}"));
    lines.push(format!("{name} {value}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring::RuntimeStats;

    #[test]
    fn test_metrics_render_contains_expected_counters() {
        let stats = RuntimeStats::new();
        stats.inc_risk_events_emitted();
        stats.inc_webhook_queue_depth();
        stats.inc_action_successes();

        let metrics = render_prometheus_metrics(&stats.snapshot());
        assert!(metrics.contains("dwell_agent_risk_events_emitted_total 1"));
        assert!(metrics.contains("dwell_agent_webhook_queue_depth 1"));
        assert!(metrics.contains("dwell_agent_action_successes_total 1"));
    }

    #[test]
    fn test_build_response_for_health_and_not_found() {
        let snapshot = RuntimeStats::new().snapshot();
        let health = build_response("/healthz", &snapshot);
        assert!(health.contains("HTTP/1.1 200 OK"));
        assert!(health.contains("\"status\":\"ok\""));

        let ready = build_response("/readyz", &snapshot);
        assert!(ready.contains("HTTP/1.1 200 OK"));
        assert!(ready.contains("\"ready\":true"));

        let not_found = build_response("/does-not-exist", &snapshot);
        assert!(not_found.contains("HTTP/1.1 404 Not Found"));
    }

    #[test]
    fn test_readyz_returns_503_when_not_ready() {
        let stats = RuntimeStats::new();
        stats.inc_profile_save_failures();
        let not_ready = build_response("/readyz", &stats.snapshot());
        assert!(not_ready.contains("HTTP/1.1 503 Service Unavailable"));
        assert!(not_ready.contains("\"ready\":false"));
    }
}
