use dwell_agent::baseline::BaselineProfile;
use dwell_agent::capture::create_capture;
use dwell_agent::config::load_config;
use dwell_agent::events::{EventType, KeystrokeEvent};
use dwell_agent::features::FeatureExtractor;
use dwell_agent::ipc::IpcServer;
use dwell_agent::keystore;
use dwell_agent::monitoring::RuntimeStats;
use dwell_agent::policy::PolicyEngine;
use dwell_agent::risk;
use dwell_agent::risk::RiskScorer;
use dwell_agent::webhook;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};
use tracing_subscriber::fmt;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config();

    // Initialize tracing
    fmt()
        .json()
        .with_max_level(match config.log_level.as_str() {
            "debug" => tracing::Level::DEBUG,
            "warn" => tracing::Level::WARN,
            "error" => tracing::Level::ERROR,
            _ => tracing::Level::INFO,
        })
        .init();

    info!("Starting dwell-agent");

    let profile_key = keystore::derive_profile_key();

    let session_id = Uuid::new_v4();
    info!(?session_id, "Session started");
    let stats = Arc::new(RuntimeStats::new());

    // Load or create baseline profile
    let profile = match BaselineProfile::load(&config.profile_path, &profile_key) {
        Ok(p) => {
            info!(
                "Loaded existing profile with {} enrollment keystrokes",
                p.enrollment_count
            );
            p
        }
        Err(_) => {
            info!("Creating new baseline profile");
            BaselineProfile::new(9, config.ema_alpha)
        }
    };
    let profile = Arc::new(Mutex::new(profile));

    // Channel for raw keystroke events
    let (keystroke_tx, keystroke_rx) = crossbeam_channel::unbounded::<KeystrokeEvent>();

    // Channel for risk events (broadcast to IPC clients)
    let (risk_tx, risk_rx) = broadcast::channel::<risk::RiskEvent>(100);

    // Management command channel
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<String>(32);

    // Start capture
    let capture = create_capture();
    info!("Starting keystroke capture");
    if let Err(e) = capture.start(keystroke_tx.clone()).await {
        warn!(
            "Capture start failed: {} (this is expected in CI/non-interactive environments)",
            e
        );
    }

    // Feature extraction and risk scoring loop
    let profile_clone = profile.clone();
    let config_clone = config.clone();
    let risk_tx_clone = risk_tx.clone();
    let stats_clone = stats.clone();
    let window_size = config.window_size;
    let min_enrollment = config.min_enrollment_keystrokes;

    let risk_scorer = RiskScorer::new(config.risk_threshold, config.risk_k);

    let scoring_task = tokio::task::spawn_blocking(move || {
        let mut window: VecDeque<KeystrokeEvent> = VecDeque::new();
        let mut last_emit = std::time::Instant::now();
        let emit_interval = Duration::from_secs(config_clone.emit_interval_secs);

        loop {
            match keystroke_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(event) => {
                    stats_clone.inc_keystrokes_seen();
                    window.push_back(event);
                    if window.len() > window_size {
                        window.pop_front();
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            }

            if last_emit.elapsed() >= emit_interval && window.len() >= 10 {
                let events: Vec<KeystrokeEvent> = window.iter().cloned().collect();
                let fv = FeatureExtractor::extract(&events);
                let feature_vec = fv.to_vec();

                // Count actual KeyDown events for correct enrollment accounting
                let keystroke_count = events
                    .iter()
                    .filter(|e| e.event_type == EventType::KeyDown)
                    .count();

                let mut p = profile_clone.lock().unwrap_or_else(|p| p.into_inner());
                p.update(&feature_vec, keystroke_count);

                if p.is_enrolled(min_enrollment) {
                    let risk_event =
                        risk_scorer.score(session_id, &feature_vec, &p, events.len() as u32);
                    info!(
                        risk_score = risk_event.risk_score,
                        confidence = risk_event.confidence,
                        "Risk assessment"
                    );
                    let _ = risk_tx_clone.send(risk_event);
                    stats_clone.inc_risk_events_emitted();
                }

                last_emit = std::time::Instant::now();
            }
        }
    });

    // Policy engine
    let policy_engine = match PolicyEngine::new(&config.policy_file) {
        Ok(engine) => Arc::new(engine),
        Err(e) => {
            warn!("Policy engine init failed: {} - using defaults", e);
            Arc::new(PolicyEngine::new_default())
        }
    };

    // Policy evaluation task
    let policy_clone = policy_engine.clone();
    let policy_stats = stats.clone();
    let mut policy_risk_rx = risk_tx.subscribe();
    let policy_task = tokio::spawn(async move {
        loop {
            match policy_risk_rx.recv().await {
                Ok(event) => {
                    policy_stats.inc_policy_evaluations();
                    let actions = policy_clone.evaluate(event.risk_score);
                    info!(?actions, risk_score = event.risk_score, "Policy actions");
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("Policy receiver lagged by {} events", n);
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // IPC server
    let ipc_server = IpcServer::new(&config.ipc_socket);
    let ipc_task = tokio::spawn(async move {
        if let Err(e) = ipc_server.run(risk_rx, cmd_tx).await {
            error!("IPC server error: {}", e);
        }
    });

    // Optional webhook dispatcher
    let webhook_task = config
        .webhook_url
        .as_ref()
        .and_then(|u| {
            let trimmed = u.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .map(|url| {
            let webhook_risk_rx = risk_tx.subscribe();
            let webhook_stats = stats.clone();
            let min_risk = config.webhook_min_risk_score;
            let timeout_secs = config.webhook_timeout_secs;
            tokio::spawn(async move {
                webhook::run_webhook_dispatcher(
                    url,
                    min_risk,
                    timeout_secs,
                    webhook_risk_rx,
                    webhook_stats,
                )
                .await;
            })
        });

    // Periodic health/monitoring logs
    let health_stats = stats.clone();
    let metrics_log_interval_secs = config.metrics_log_interval_secs.max(1);
    let health_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(metrics_log_interval_secs));
        loop {
            interval.tick().await;
            let snapshot = health_stats.snapshot();
            info!(
                uptime_secs = snapshot.uptime_secs,
                keystrokes_seen = snapshot.keystrokes_seen,
                risk_events_emitted = snapshot.risk_events_emitted,
                policy_evaluations = snapshot.policy_evaluations,
                commands_received = snapshot.commands_received,
                webhook_deliveries = snapshot.webhook_deliveries,
                webhook_failures = snapshot.webhook_failures,
                "Runtime health"
            );
        }
    });

    // Command handler
    let profile_path = config.profile_path.clone();
    let policy_file_for_cmd = config.policy_file.clone();
    let policy_engine_for_cmd = policy_engine.clone();
    let stats_for_cmd = stats.clone();
    let cmd_task = tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            stats_for_cmd.inc_commands_received();
            match cmd.trim() {
                "status" => {
                    let snapshot = stats_for_cmd.snapshot();
                    info!(
                        uptime_secs = snapshot.uptime_secs,
                        keystrokes_seen = snapshot.keystrokes_seen,
                        risk_events_emitted = snapshot.risk_events_emitted,
                        policy_evaluations = snapshot.policy_evaluations,
                        commands_received = snapshot.commands_received,
                        webhook_deliveries = snapshot.webhook_deliveries,
                        webhook_failures = snapshot.webhook_failures,
                        "Status: running"
                    );
                }
                "reload-policy" => match policy_engine_for_cmd.reload(&policy_file_for_cmd) {
                    Ok(()) => info!("Policy reloaded from {}", policy_file_for_cmd),
                    Err(e) => warn!("Policy reload failed: {}", e),
                },
                _ => warn!("Unknown command: {}", cmd),
            }
        }
    });

    // SIGTERM handler
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    tokio::select! {
        _ = sigterm.recv() => {
            info!("Received SIGTERM, shutting down");
        }
        _ = sigint.recv() => {
            info!("Received SIGINT, shutting down");
        }
    }

    // Graceful shutdown: flush profile
    capture.stop();
    let p = profile.lock().unwrap_or_else(|p| p.into_inner());
    if let Err(e) = p.save(&profile_path, &profile_key) {
        error!("Failed to save profile: {}", e);
    } else {
        info!("Profile saved");
    }

    ipc_task.abort();
    policy_task.abort();
    cmd_task.abort();
    health_task.abort();
    if let Some(handle) = webhook_task {
        handle.abort();
    }
    scoring_task.abort();

    info!("dwell-agent stopped");
    Ok(())
}
