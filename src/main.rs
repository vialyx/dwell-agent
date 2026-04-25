mod baseline;
mod capture;
mod config;
mod events;
mod features;
mod ipc;
mod policy;
mod risk;

use baseline::BaselineProfile;
use capture::create_capture;
use config::load_config;
use events::KeystrokeEvent;
use features::FeatureExtractor;
use ipc::IpcServer;
use policy::PolicyEngine;
use risk::RiskScorer;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};
use tracing_subscriber::fmt;
use uuid::Uuid;

// Hardcoded key for demo - in production, derive from OS keychain
const PROFILE_KEY: [u8; 32] = [0x42u8; 32];

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

    let session_id = Uuid::new_v4();
    info!(?session_id, "Session started");

    // Load or create baseline profile
    let profile = match BaselineProfile::load(&config.profile_path, &PROFILE_KEY) {
        Ok(p) => {
            info!("Loaded existing profile with {} enrollment keystrokes", p.enrollment_count);
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
        warn!("Capture start failed: {} (this is expected in CI/non-interactive environments)", e);
    }

    // Feature extraction and risk scoring loop
    let profile_clone = profile.clone();
    let config_clone = config.clone();
    let risk_tx_clone = risk_tx.clone();
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

                let mut p = profile_clone.lock().unwrap();
                p.update(&feature_vec);

                if p.is_enrolled(min_enrollment) {
                    let risk_event = risk_scorer.score(
                        session_id,
                        &feature_vec,
                        &p,
                        events.len() as u32,
                    );
                    info!(
                        risk_score = risk_event.risk_score,
                        confidence = risk_event.confidence,
                        "Risk assessment"
                    );
                    let _ = risk_tx_clone.send(risk_event);
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
    let mut policy_risk_rx = risk_tx.subscribe();
    let policy_task = tokio::spawn(async move {
        loop {
            match policy_risk_rx.recv().await {
                Ok(event) => {
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

    // Command handler
    let _profile_cmd = profile.clone();
    let profile_path = config.profile_path.clone();
    let cmd_task = tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd.trim() {
                "status" => info!("Status: running"),
                "reload-policy" => info!("Policy reload requested"),
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
    let p = profile.lock().unwrap();
    if let Err(e) = p.save(&profile_path, &PROFILE_KEY) {
        error!("Failed to save profile: {}", e);
    } else {
        info!("Profile saved");
    }

    ipc_task.abort();
    policy_task.abort();
    cmd_task.abort();
    scoring_task.abort();

    info!("dwell-agent stopped");
    Ok(())
}
