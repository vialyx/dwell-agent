//! End-to-end integration tests for dwell-agent.
//!
//! These tests wire up the real components without mocks and validate:
//! - full keystroke → feature extraction → baseline update → risk scoring pipeline
//! - correct enrollment accounting (keystroke counts, not feature-dim counts)
//! - policy evaluation tier mapping at realistic risk scores
//! - profile encrypt/persist/reload round-trip
//! - IPC server command delivery and risk-event streaming
//! - runtime statistics accumulation

#[cfg(unix)]
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use dwell_agent::baseline::BaselineProfile;
use dwell_agent::events::{EventType, KeystrokeEvent};
use dwell_agent::features::FeatureExtractor;
use dwell_agent::ipc::IpcServer;
use dwell_agent::keystore::PLACEHOLDER_KEY;
use dwell_agent::monitoring::RuntimeStats;
use dwell_agent::policy::{PolicyAction, PolicyEngine};
use dwell_agent::risk::{RiskEvent, RiskScorer};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::broadcast;
use tokio::time::{sleep, timeout};
use uuid::Uuid;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn make_event(key_code: u32, event_type: EventType, timestamp_ns: u64) -> KeystrokeEvent {
    KeystrokeEvent {
        key_code,
        event_type,
        timestamp_ns,
        session_id: Uuid::nil(),
    }
}

/// Build a realistic event window: `n_keys` distinct key presses with consistent timing.
fn synthetic_window(n_keys: usize, start_ns: u64) -> Vec<KeystrokeEvent> {
    let mut events = Vec::with_capacity(n_keys * 2);
    let mut ts = start_ns;
    for i in 0..n_keys {
        let key_code = 30 + (i as u32 % 20);
        events.push(make_event(key_code, EventType::KeyDown, ts));
        ts += 35_000_000; // 35 ms dwell
        events.push(make_event(key_code, EventType::KeyUp, ts));
        ts += 45_000_000; // 45 ms flight
    }
    events
}

fn key_down_count(events: &[KeystrokeEvent]) -> usize {
    events
        .iter()
        .filter(|e| e.event_type == EventType::KeyDown)
        .count()
}

fn unique_sock(label: &str) -> String {
    let id = &Uuid::new_v4().as_simple().to_string()[..10];
    format!("/tmp/dw-{label}-{id}.sock")
}

fn temp_file_path(label: &str, ext: &str) -> std::path::PathBuf {
    let id = &Uuid::new_v4().as_simple().to_string()[..10];
    std::env::temp_dir().join(format!("dw-{label}-{id}.{ext}"))
}

// ─── pipeline tests ───────────────────────────────────────────────────────────

/// Smoke-test: feature extraction does not panic on any realistic input.
#[test]
fn test_feature_extraction_smoke() {
    let window = synthetic_window(100, 0);
    let fv = FeatureExtractor::extract(&window);
    assert_eq!(fv.to_vec().len(), 9);
    for v in fv.to_vec() {
        assert!(v.is_finite(), "non-finite value {v}");
    }
}

/// Enrollment counting must reflect real keystroke counts, not feature-vector dimension (9).
#[test]
fn test_enrollment_count_uses_keystroke_count_not_feature_dim() {
    let mut profile = BaselineProfile::new(9, 0.05);
    let window = synthetic_window(50, 0);
    let kd = key_down_count(&window);
    let fv = FeatureExtractor::extract(&window);
    profile.update(&fv.to_vec(), kd);

    // Should be 50 (key-down events), not 9 (feature dim)
    assert_eq!(profile.enrollment_count, kd);
    assert_eq!(profile.enrollment_count, 50);
}

/// Full pipeline: drive baseline to enrolled state, then confirm low-risk output for
/// consistent typing.
#[test]
fn test_scoring_pipeline_end_to_end() {
    let mut profile = BaselineProfile::new(9, 0.05);
    let scorer = RiskScorer::new(5.0, 1.0);
    let session_id = Uuid::new_v4();
    let min_enrollment = 200; // use a small threshold for test speed

    let mut ts = 0u64;
    while !profile.is_enrolled(min_enrollment) {
        let window = synthetic_window(50, ts);
        ts += 50 * 80_000_000;
        let kd = key_down_count(&window);
        let fv = FeatureExtractor::extract(&window);
        profile.update(&fv.to_vec(), kd);
    }

    assert!(profile.is_enrolled(min_enrollment));

    // Scoring with the same typing rhythm → low risk
    let window = synthetic_window(50, ts);
    let kd = key_down_count(&window);
    let fv = FeatureExtractor::extract(&window);
    let event = scorer.score(session_id, &fv.to_vec(), &profile, kd as u32);

    assert!(
        event.risk_score < 60,
        "Expected low risk for consistent typing, got {}",
        event.risk_score
    );
    assert!((0.0..=1.0_f32).contains(&event.confidence));
}

/// Extreme deviation in feature space must yield a high risk score.
#[test]
fn test_anomalous_typing_produces_high_risk_score() {
    let mut profile = BaselineProfile::new(9, 0.05);
    let scorer = RiskScorer::new(2.0, 1.0);
    let session_id = Uuid::new_v4();

    for _ in 0..200 {
        profile.update(&[100.0, 10.0, 50.0, 5.0, 60.0, 8.0, 0.05, 0.3, 0.2], 50);
    }

    let event = scorer.score(
        session_id,
        &[1000.0, 500.0, 1000.0, 200.0, 5.0, 300.0, 0.9, 0.9, 0.9],
        &profile,
        50,
    );

    assert!(
        event.risk_score > 50,
        "Expected high risk for anomalous features, got {}",
        event.risk_score
    );
}

// ─── policy tests ─────────────────────────────────────────────────────────────

/// Policy engine routes risk scores to correct tiers with correct actions.
#[test]
fn test_policy_tier_routing() {
    let engine = PolicyEngine::new_default();

    // Low (0–40): only Log
    assert_eq!(engine.evaluate(0), vec![PolicyAction::Log]);
    assert_eq!(engine.evaluate(40), vec![PolicyAction::Log]);

    // Medium (41–70): Log + SIEM + re-verification
    let med = engine.evaluate(55);
    assert!(med.contains(&PolicyAction::Log));
    assert!(med.contains(&PolicyAction::EmitSiemTag));
    assert!(med.contains(&PolicyAction::TriggerReVerification));

    // High (71–100): includes step-up and session termination
    let high = engine.evaluate(85);
    assert!(high.contains(&PolicyAction::TriggerStepUp));
    assert!(high.contains(&PolicyAction::TerminateSession));
}

/// Policy hot-reload applies new TOML tiers immediately.
#[test]
fn test_policy_hot_reload_changes_tier_boundaries() {
    let engine = PolicyEngine::new_default();

    // Default: 55 → medium
    assert!(engine.evaluate(55).contains(&PolicyAction::EmitSiemTag));

    // Write a custom policy with narrow tiers
    let path = temp_file_path("policy", "toml");
    std::fs::write(
        &path,
        "[tiers]\nlow_max = 5\nmed_max = 10\n\n[actions]\nlow = [\"log\"]\nmed = [\"emit_siem_tag\"]\nhigh = [\"terminate_session\"]\n",
    )
    .unwrap();

    engine
        .reload(path.to_str().expect("temp policy path must be valid UTF-8"))
        .expect("policy reload");
    // 55 → now High with the new tiers
    let actions = engine.evaluate(55);
    assert!(actions.contains(&PolicyAction::TerminateSession));
    let _ = std::fs::remove_file(path);
}

// ─── baseline persistence tests ───────────────────────────────────────────────

/// Encrypted profile survives a save/load round-trip without data loss.
#[test]
fn test_profile_save_and_reload_roundtrip() {
    let key = PLACEHOLDER_KEY;
    let path = temp_file_path("profile", "enc");

    let mut profile = BaselineProfile::new(9, 0.05);
    for _ in 0..5 {
        let window = synthetic_window(20, 0);
        let kd = key_down_count(&window);
        let fv = FeatureExtractor::extract(&window);
        profile.update(&fv.to_vec(), kd);
    }

    let path_str = path
        .to_str()
        .expect("temp profile path must be valid UTF-8");

    profile.save(path_str, &key).expect("save profile");
    let loaded = BaselineProfile::load(path_str, &key).expect("load profile");

    assert_eq!(loaded.enrollment_count, profile.enrollment_count);
    assert_eq!(loaded.feature_means.len(), profile.feature_means.len());
    for (a, b) in profile
        .feature_means
        .iter()
        .zip(loaded.feature_means.iter())
    {
        assert!((a - b).abs() < 1e-12, "mean mismatch: {a} vs {b}");
    }
    let _ = std::fs::remove_file(path);
}

/// Wrong key must fail to decrypt (authentication check).
#[test]
fn test_profile_wrong_key_fails_decryption() {
    let good_key = [0x11u8; 32];
    let bad_key = [0x22u8; 32];
    let path = temp_file_path("wrongkey", "enc");
    let path_str = path
        .to_str()
        .expect("temp wrong-key profile path must be valid UTF-8");

    let profile = BaselineProfile::new(3, 0.05);
    profile.save(path_str, &good_key).unwrap();
    assert!(BaselineProfile::load(path_str, &bad_key).is_err());
    let _ = std::fs::remove_file(path);
}

// ─── monitoring tests ─────────────────────────────────────────────────────────

/// RuntimeStats counters are updated correctly across concurrent increments.
#[test]
fn test_runtime_stats_pipeline_simulation() {
    let stats = Arc::new(RuntimeStats::new());

    // Simulate 10 keystroke events
    for _ in 0..10 {
        stats.inc_keystrokes_seen();
    }
    stats.inc_risk_events_emitted();
    stats.inc_risk_events_emitted();
    stats.inc_policy_evaluations();
    stats.inc_webhook_deliveries();
    stats.inc_webhook_failures();

    let snap = stats.snapshot();
    assert_eq!(snap.keystrokes_seen, 10);
    assert_eq!(snap.risk_events_emitted, 2);
    assert_eq!(snap.policy_evaluations, 1);
    assert_eq!(snap.webhook_deliveries, 1);
    assert_eq!(snap.webhook_failures, 1);
    assert!(snap.uptime_secs < 5);
}

// ─── IPC server integration tests ────────────────────────────────────────────

/// IpcServer::new must clean up a stale socket file before binding.
#[test]
#[cfg(unix)]
fn test_ipc_server_removes_stale_socket_on_init() {
    let path = unique_sock("stale");
    std::fs::write(&path, b"stale-data").unwrap();
    let _server = IpcServer::new(&path, true).expect("create IPC server");
    assert!(
        !Path::new(&path).exists(),
        "stale socket not removed on IpcServer::new"
    );
}

/// Full async IPC round-trip: management command forwarding and risk-event JSON streaming.
#[tokio::test]
#[cfg(unix)]
async fn test_ipc_command_and_risk_event_round_trip() {
    let socket_path = unique_sock("rt");
    let server = IpcServer::new(&socket_path, true).expect("create IPC server");

    let (risk_tx, risk_rx) = broadcast::channel::<RiskEvent>(16);
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<String>(8);

    let path_clone = socket_path.clone();
    let server_task = tokio::spawn(async move {
        let _ = server.run(risk_rx, cmd_tx).await;
    });

    // Poll until the socket file appears (listener ready)
    for _ in 0..40 {
        if Path::new(&path_clone).exists() {
            break;
        }
        sleep(Duration::from_millis(15)).await;
    }

    let stream = UnixStream::connect(&socket_path)
        .await
        .expect("connect to IPC socket");
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    // Send a management command
    write_half.write_all(b"status\n").await.unwrap();
    let received_cmd = timeout(Duration::from_secs(2), cmd_rx.recv())
        .await
        .expect("timed out waiting for command")
        .expect("command channel closed");
    assert_eq!(received_cmd, "status");

    // Broadcast a risk event; client should receive it as newline-delimited JSON
    let evt = RiskEvent {
        session_id: Uuid::nil(),
        timestamp_utc: "2026-04-27T00:00:00Z".to_string(),
        risk_score: 77,
        confidence: 0.88,
        anomalous_features: vec![],
        window_keystrokes: 42,
        model_version: "1.0.0".to_string(),
    };
    risk_tx.send(evt).expect("broadcast risk event");

    let line = timeout(Duration::from_secs(2), lines.next_line())
        .await
        .expect("timed out waiting for event line")
        .expect("readline error")
        .expect("connection closed before event");

    let parsed: RiskEvent = serde_json::from_str(&line).expect("parse JSON risk event");
    assert_eq!(parsed.risk_score, 77);
    assert!((parsed.confidence - 0.88).abs() < 0.001);

    server_task.abort();
}

/// Multiple concurrent IPC clients each receive broadcast events independently.
#[tokio::test]
#[cfg(unix)]
async fn test_ipc_multiple_clients_receive_events() {
    let socket_path = unique_sock("multi");
    let server = IpcServer::new(&socket_path, true).expect("create IPC server");

    let (risk_tx, risk_rx) = broadcast::channel::<RiskEvent>(16);
    let (cmd_tx, _cmd_rx) = tokio::sync::mpsc::channel::<String>(8);

    let path_clone = socket_path.clone();
    let server_task = tokio::spawn(async move {
        let _ = server.run(risk_rx, cmd_tx).await;
    });

    for _ in 0..40 {
        if Path::new(&path_clone).exists() {
            break;
        }
        sleep(Duration::from_millis(15)).await;
    }

    // Connect two clients and keep both halves alive so the server does not
    // observe EOF on the command stream and terminate the connection.
    let mut clients = Vec::new();
    let mut write_halves = Vec::new();
    for _ in 0..2 {
        let s = UnixStream::connect(&socket_path)
            .await
            .expect("connect client");
        let (rh, wh) = s.into_split();
        write_halves.push(wh);
        clients.push(BufReader::new(rh).lines());
    }

    let evt = RiskEvent {
        session_id: Uuid::nil(),
        timestamp_utc: "2026-04-27T00:00:00Z".to_string(),
        risk_score: 42,
        confidence: 0.5,
        anomalous_features: vec![],
        window_keystrokes: 10,
        model_version: "1.0.0".to_string(),
    };
    risk_tx.send(evt).expect("broadcast");

    // Both clients should receive the same event
    for client_lines in clients.iter_mut() {
        let line = timeout(Duration::from_secs(2), client_lines.next_line())
            .await
            .expect("timeout")
            .expect("readline error")
            .expect("closed");
        let parsed: RiskEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed.risk_score, 42);
    }

    drop(write_halves);

    server_task.abort();
}
