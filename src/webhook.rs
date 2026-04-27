use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::monitoring::RuntimeStats;
use crate::risk::RiskEvent;

#[derive(Clone, Debug)]
pub struct WebhookSpool {
    dir: PathBuf,
}

#[derive(Debug)]
struct PendingWebhook {
    path: PathBuf,
    event: RiskEvent,
}

impl WebhookSpool {
    pub fn new(dir: &str) -> Result<Self, std::io::Error> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            dir: PathBuf::from(dir),
        })
    }

    pub fn enqueue(&self, event: &RiskEvent) -> Result<(), std::io::Error> {
        let file_name = format!(
            "{}-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            event.session_id
        );
        let path = self.dir.join(file_name);
        let tmp_path = self.dir.join(format!(
            "{}.tmp",
            path.file_name().unwrap().to_string_lossy()
        ));
        let payload = serde_json::to_vec(event).map_err(std::io::Error::other)?;

        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)?;
        file.write_all(&payload)?;
        file.sync_all()?;
        fs::rename(tmp_path, path)?;
        Ok(())
    }

    pub fn pending_count(&self) -> Result<u64, std::io::Error> {
        let mut count = 0u64;
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            if is_queue_file(&entry.path()) {
                count += 1;
            }
        }
        Ok(count)
    }

    fn next_pending(&self) -> Result<Option<PendingWebhook>, std::io::Error> {
        let mut entries: Vec<PathBuf> = fs::read_dir(&self.dir)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| is_queue_file(path))
            .collect();
        entries.sort();

        for path in entries {
            match fs::read(&path) {
                Ok(bytes) => match serde_json::from_slice::<RiskEvent>(&bytes) {
                    Ok(event) => return Ok(Some(PendingWebhook { path, event })),
                    Err(_) => {
                        let _ = quarantine_invalid_queue_file(&path);
                    }
                },
                Err(e) => return Err(e),
            }
        }

        Ok(None)
    }

    pub fn ack(&self, path: &Path) -> Result<(), std::io::Error> {
        fs::remove_file(path)
    }
}

pub async fn run_webhook_dispatcher(
    url: String,
    min_risk_score: u8,
    timeout_secs: u64,
    mut risk_rx: broadcast::Receiver<RiskEvent>,
    stats: Arc<RuntimeStats>,
    spool_dir: Option<String>,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            error!(error = %e, "Failed to initialize webhook HTTP client");
            return;
        }
    };

    let spool = spool_dir
        .as_deref()
        .map(str::trim)
        .filter(|dir| !dir.is_empty())
        .map(WebhookSpool::new)
        .transpose();

    let spool = match spool {
        Ok(spool) => spool,
        Err(e) => {
            error!(error = %e, "Failed to initialize durable webhook spool");
            return;
        }
    };

    if let Some(spool) = &spool {
        match spool.pending_count() {
            Ok(depth) => stats.set_webhook_queue_depth(depth),
            Err(e) => warn!(error = %e, "Failed to inspect webhook spool depth"),
        }
    }

    info!(
        webhook_url = %url,
        min_risk_score,
        timeout_secs,
        durable_spool = spool.is_some(),
        "Webhook dispatcher started"
    );

    let mut channel_closed = false;
    loop {
        if let Some(spool) = &spool {
            match spool.next_pending() {
                Ok(Some(pending)) => {
                    if deliver_event(&client, &url, &pending.event, &stats).await {
                        if let Err(e) = spool.ack(&pending.path) {
                            warn!(error = %e, path = %pending.path.display(), "Failed to remove delivered webhook spool item");
                        } else {
                            stats.dec_webhook_queue_depth();
                        }
                    } else {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    continue;
                }
                Ok(None) => {
                    if channel_closed {
                        info!("Webhook dispatcher stopped: risk channel closed and queue drained");
                        break;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to read durable webhook queue");
                }
            }
        } else if channel_closed {
            info!("Webhook dispatcher stopped: risk channel closed");
            break;
        }

        match tokio::time::timeout(Duration::from_millis(500), risk_rx.recv()).await {
            Ok(Ok(event)) => {
                if event.risk_score < min_risk_score {
                    continue;
                }

                if let Some(spool) = &spool {
                    match spool.enqueue(&event) {
                        Ok(()) => {
                            stats.inc_webhook_events_queued();
                            stats.inc_webhook_queue_depth();
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to enqueue webhook event; falling back to direct delivery");
                            let _ = deliver_event(&client, &url, &event, &stats).await;
                        }
                    }
                } else {
                    let _ = deliver_event(&client, &url, &event, &stats).await;
                }
            }
            Ok(Err(broadcast::error::RecvError::Lagged(n))) => {
                warn!(lagged_events = n, "Webhook receiver lagged");
            }
            Ok(Err(broadcast::error::RecvError::Closed)) => {
                channel_closed = true;
            }
            Err(_) => {}
        }
    }
}

async fn deliver_event(
    client: &reqwest::Client,
    url: &str,
    event: &RiskEvent,
    stats: &RuntimeStats,
) -> bool {
    let mut backoff_ms = 250u64;

    for attempt in 1..=3 {
        match client.post(url).json(event).send().await {
            Ok(resp) if resp.status().is_success() => {
                stats.inc_webhook_deliveries();
                return true;
            }
            Ok(resp) => {
                warn!(
                    attempt,
                    status = %resp.status(),
                    risk_score = event.risk_score,
                    "Webhook responded with non-success status"
                );
            }
            Err(e) => {
                warn!(
                    attempt,
                    error = %e,
                    risk_score = event.risk_score,
                    "Webhook request failed"
                );
            }
        }

        if attempt < 3 {
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            backoff_ms = backoff_ms.saturating_mul(2);
        }
    }

    stats.inc_webhook_failures();
    false
}

fn is_queue_file(path: &Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some("json")
}

fn quarantine_invalid_queue_file(path: &Path) -> Result<(), std::io::Error> {
    let bad_path = path.with_extension(format!(
        "bad-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::rename(path, bad_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::FeatureName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{sleep, timeout};
    use uuid::Uuid;

    fn sample_event(risk_score: u8) -> RiskEvent {
        RiskEvent {
            session_id: Uuid::nil(),
            timestamp_utc: "2026-01-01T00:00:00Z".to_string(),
            risk_score,
            confidence: 0.9,
            anomalous_features: vec![FeatureName::Wpm],
            window_keystrokes: 42,
            model_version: "1.0.0".to_string(),
        }
    }

    fn unique_spool_dir(label: &str) -> String {
        let id = &Uuid::new_v4().as_simple().to_string()[..10];
        format!("/tmp/dw-webhook-{label}-{id}")
    }

    #[tokio::test]
    async fn test_webhook_dispatcher_success() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });

        let spool_dir = unique_spool_dir("success");
        let (tx, rx) = broadcast::channel(8);
        let stats = Arc::new(RuntimeStats::new());
        let task = tokio::spawn(run_webhook_dispatcher(
            format!("http://{addr}"),
            10,
            2,
            rx,
            stats.clone(),
            Some(spool_dir.clone()),
        ));

        tx.send(sample_event(80)).expect("send risk event");
        sleep(Duration::from_millis(400)).await;
        drop(tx);

        timeout(Duration::from_secs(3), task)
            .await
            .expect("dispatcher join timeout")
            .expect("dispatcher task failed");

        let snap = stats.snapshot();
        assert_eq!(snap.webhook_deliveries, 1);
        assert_eq!(snap.webhook_failures, 0);
        assert_eq!(snap.webhook_queue_depth, 0);
        let _ = fs::remove_dir_all(spool_dir);
    }

    #[tokio::test]
    async fn test_webhook_dispatcher_failure_increments_counter() {
        let spool_dir = unique_spool_dir("failure");
        let (tx, rx) = broadcast::channel(8);
        let stats = Arc::new(RuntimeStats::new());
        let task = tokio::spawn(run_webhook_dispatcher(
            "http://127.0.0.1:9".to_string(),
            0,
            1,
            rx,
            stats.clone(),
            Some(spool_dir.clone()),
        ));

        tx.send(sample_event(90)).expect("send risk event");
        sleep(Duration::from_millis(1100)).await;
        drop(tx);
        task.abort();

        let snap = stats.snapshot();
        assert_eq!(snap.webhook_deliveries, 0);
        assert!(snap.webhook_failures >= 1);
        assert!(snap.webhook_queue_depth >= 1);
        let _ = fs::remove_dir_all(spool_dir);
    }

    #[tokio::test]
    async fn test_webhook_spool_replays_after_restart() {
        let spool_dir = unique_spool_dir("replay");
        let (tx, rx) = broadcast::channel(8);
        let stats = Arc::new(RuntimeStats::new());
        let failing_task = tokio::spawn(run_webhook_dispatcher(
            "http://127.0.0.1:9".to_string(),
            0,
            1,
            rx,
            stats.clone(),
            Some(spool_dir.clone()),
        ));

        tx.send(sample_event(77)).expect("send risk event");
        sleep(Duration::from_millis(600)).await;
        drop(tx);
        failing_task.abort();

        let spool = WebhookSpool::new(&spool_dir).expect("spool init");
        assert!(spool.pending_count().expect("pending count") >= 1);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });

        let (_tx2, rx2) = broadcast::channel(8);
        let replay_stats = Arc::new(RuntimeStats::new());
        let replay_task = tokio::spawn(run_webhook_dispatcher(
            format!("http://{addr}"),
            0,
            2,
            rx2,
            replay_stats.clone(),
            Some(spool_dir.clone()),
        ));
        sleep(Duration::from_millis(600)).await;
        replay_task.abort();

        assert_eq!(spool.pending_count().expect("pending count"), 0);
        assert_eq!(replay_stats.snapshot().webhook_deliveries, 1);
        let _ = fs::remove_dir_all(spool_dir);
    }
}
