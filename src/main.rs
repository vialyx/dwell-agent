use dwell_agent::actions::ActionExecutor;
use dwell_agent::baseline::{BaselineProfile, ProfileLoadSource};
use dwell_agent::capture::create_capture;
use dwell_agent::config::load_config;
use dwell_agent::events::{EventType, KeystrokeEvent};
use dwell_agent::features::FeatureExtractor;
use dwell_agent::ipc::IpcServer;
use dwell_agent::keystore;
use dwell_agent::management;
use dwell_agent::monitoring::{RuntimeStats, RuntimeStatsSnapshot};
use dwell_agent::policy::PolicyEngine;
use dwell_agent::risk;
use dwell_agent::risk::RiskScorer;
use dwell_agent::webhook;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};
use tracing_subscriber::fmt;
use uuid::Uuid;

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::signal::unix::{signal, SignalKind};

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

    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> Result<(), Box<dyn std::error::Error>> {
    tokio::signal::ctrl_c().await?;
    info!("Received Ctrl+C, shutting down");
    Ok(())
}

async fn persist_profile_snapshot(
    profile: Arc<Mutex<BaselineProfile>>,
    profile_path: String,
    profile_key: [u8; 32],
    stats: Arc<RuntimeStats>,
    reason: &'static str,
) {
    let snapshot = {
        let guard = profile
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.clone()
    };

    match tokio::task::spawn_blocking(move || snapshot.save(&profile_path, &profile_key)).await {
        Ok(Ok(())) => {
            stats.inc_profile_saves();
            info!(reason, "Profile saved");
        }
        Ok(Err(e)) => {
            stats.inc_profile_save_failures();
            error!(reason, error = %e, "Failed to save profile");
        }
        Err(e) => {
            stats.inc_profile_save_failures();
            error!(reason, error = %e, "Profile save task failed");
        }
    }
}

fn log_runtime_snapshot(message: &str, snapshot: &RuntimeStatsSnapshot) {
    info!(
        message,
        uptime_secs = snapshot.uptime_secs,
        keystrokes_seen = snapshot.keystrokes_seen,
        risk_events_emitted = snapshot.risk_events_emitted,
        policy_evaluations = snapshot.policy_evaluations,
        commands_received = snapshot.commands_received,
        webhook_deliveries = snapshot.webhook_deliveries,
        webhook_failures = snapshot.webhook_failures,
        webhook_events_queued = snapshot.webhook_events_queued,
        webhook_queue_depth = snapshot.webhook_queue_depth,
        action_successes = snapshot.action_successes,
        action_failures = snapshot.action_failures,
        action_skipped = snapshot.action_skipped,
        profile_saves = snapshot.profile_saves,
        profile_save_failures = snapshot.profile_save_failures,
        profile_load_failures = snapshot.profile_load_failures,
        profile_recoveries = snapshot.profile_recoveries,
        capture_start_failures = snapshot.capture_start_failures,
        policy_reload_successes = snapshot.policy_reload_successes,
        policy_reload_failures = snapshot.policy_reload_failures,
        management_requests = snapshot.management_requests,
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config().map_err(|e| format!("configuration error: {e}"))?;

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

    let profile_key = keystore::derive_profile_key(config.allow_insecure_placeholder_key)
        .map_err(|e| format!("profile key error: {e}"))?;

    let session_id = Uuid::new_v4();
    info!(?session_id, "Session started");
    let stats = Arc::new(RuntimeStats::new());

    let (profile, profile_report) = BaselineProfile::load_with_recovery(
        &config.profile_path,
        &profile_key,
        9,
        config.ema_alpha,
    )?;
    if profile_report.primary_failed {
        stats.inc_profile_load_failures();
        warn!(path = %config.profile_path, "Primary profile failed to load and was quarantined");
    }
    if profile_report.backup_failed {
        stats.inc_profile_load_failures();
        warn!(path = %config.profile_path, "Backup profile failed to load and was quarantined");
    }
    if profile_report.recovered_from_backup {
        stats.inc_profile_recoveries();
    }
    match profile_report.source {
        ProfileLoadSource::Primary => {
            info!(
                enrollment_count = profile.enrollment_count,
                "Loaded existing profile"
            );
        }
        ProfileLoadSource::Backup => {
            warn!(
                enrollment_count = profile.enrollment_count,
                "Recovered profile from backup"
            );
        }
        ProfileLoadSource::Fresh => {
            info!("Creating new baseline profile");
        }
    }
    let profile = Arc::new(Mutex::new(profile));

    let (keystroke_tx, keystroke_rx) = crossbeam_channel::unbounded::<KeystrokeEvent>();
    let (risk_tx, risk_rx) = broadcast::channel::<risk::RiskEvent>(100);
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<String>(32);

    let capture = create_capture();
    info!("Starting keystroke capture");
    if let Err(e) = capture.start(keystroke_tx.clone()).await {
        stats.inc_capture_start_failures();
        warn!(
            error = %e,
            "Capture start failed (expected in CI/non-interactive environments)"
        );
    }

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
                let keystroke_count = events
                    .iter()
                    .filter(|e| e.event_type == EventType::KeyDown)
                    .count();

                let mut p = profile_clone
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
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

    let policy_engine =
        Arc::new(PolicyEngine::new(&config.policy_file).map_err(|e| format!("policy error: {e}"))?);
    let action_executor = Arc::new(ActionExecutor::new(
        config.action_hooks.clone(),
        stats.clone(),
    ));

    let policy_clone = policy_engine.clone();
    let policy_stats = stats.clone();
    let action_executor_clone = action_executor.clone();
    let mut policy_risk_rx = risk_tx.subscribe();
    let policy_task = tokio::spawn(async move {
        loop {
            match policy_risk_rx.recv().await {
                Ok(event) => {
                    policy_stats.inc_policy_evaluations();
                    let actions = policy_clone.evaluate(event.risk_score);
                    info!(
                        ?actions,
                        risk_score = event.risk_score,
                        "Policy actions selected"
                    );
                    action_executor_clone.execute_all(&actions, &event).await;
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("Policy receiver lagged by {} events", n);
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    #[cfg(unix)]
    let ipc_task = {
        let ipc_server = IpcServer::new(&config.ipc_socket, config.ipc_require_same_user)
            .map_err(|e| format!("IPC initialization error: {e}"))?;
        Some(tokio::spawn(async move {
            if let Err(e) = ipc_server.run(risk_rx, cmd_tx).await {
                error!("IPC server error: {}", e);
            }
        }))
    };

    #[cfg(not(unix))]
    let ipc_task = {
        let ipc_server = IpcServer::new(&config.ipc_tcp_bind, config.ipc_require_same_user)
            .map_err(|e| format!("IPC initialization error: {e}"))?;
        Some(tokio::spawn(async move {
            if let Err(e) = ipc_server.run(risk_rx, cmd_tx).await {
                error!("IPC server error: {}", e);
            }
        }))
    };

    let management_bind = config.management_bind.clone();
    let management_stats = stats.clone();
    let management_task = tokio::spawn(async move {
        if let Err(e) = management::run_management_server(management_bind, management_stats).await {
            error!(error = %e, "Management server error");
        }
    });

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
            let spool_dir = Some(config.webhook_spool_dir.clone());
            tokio::spawn(async move {
                webhook::run_webhook_dispatcher(
                    url,
                    min_risk,
                    timeout_secs,
                    webhook_risk_rx,
                    webhook_stats,
                    spool_dir,
                )
                .await;
            })
        });

    let health_stats = stats.clone();
    let metrics_log_interval_secs = config.metrics_log_interval_secs.max(1);
    let health_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(metrics_log_interval_secs));
        loop {
            interval.tick().await;
            let snapshot = health_stats.snapshot();
            log_runtime_snapshot("Runtime health", &snapshot);
        }
    });

    let autosave_profile = profile.clone();
    let autosave_path = config.profile_path.clone();
    let autosave_key = profile_key;
    let autosave_stats = stats.clone();
    let autosave_interval_secs = config.profile_autosave_secs.max(1);
    let autosave_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(autosave_interval_secs));
        interval.tick().await;
        loop {
            interval.tick().await;
            persist_profile_snapshot(
                autosave_profile.clone(),
                autosave_path.clone(),
                autosave_key,
                autosave_stats.clone(),
                "autosave",
            )
            .await;
        }
    });

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
                    log_runtime_snapshot("Status: running", &snapshot);
                }
                "reload-policy" => match policy_engine_for_cmd.reload(&policy_file_for_cmd) {
                    Ok(()) => {
                        stats_for_cmd.inc_policy_reload_successes();
                        info!("Policy reloaded from {}", policy_file_for_cmd);
                    }
                    Err(e) => {
                        stats_for_cmd.inc_policy_reload_failures();
                        warn!("Policy reload failed: {}", e);
                    }
                },
                _ => warn!("Unknown command: {}", cmd),
            }
        }
    });

    wait_for_shutdown_signal().await?;

    capture.stop();
    persist_profile_snapshot(
        profile.clone(),
        profile_path,
        profile_key,
        stats.clone(),
        "shutdown",
    )
    .await;

    if let Some(handle) = ipc_task {
        handle.abort();
    }
    policy_task.abort();
    cmd_task.abort();
    health_task.abort();
    autosave_task.abort();
    management_task.abort();
    if let Some(handle) = webhook_task {
        handle.abort();
    }
    scoring_task.abort();

    info!("dwell-agent stopped");
    Ok(())
}
