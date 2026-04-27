use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::monitoring::RuntimeStats;
use crate::risk::RiskEvent;

pub async fn run_webhook_dispatcher(
    url: String,
    min_risk_score: u8,
    timeout_secs: u64,
    mut risk_rx: broadcast::Receiver<RiskEvent>,
    stats: Arc<RuntimeStats>,
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

    info!(
        webhook_url = %url,
        min_risk_score,
        timeout_secs,
        "Webhook dispatcher started"
    );

    loop {
        match risk_rx.recv().await {
            Ok(event) => {
                if event.risk_score < min_risk_score {
                    continue;
                }

                let mut delivered = false;
                let mut backoff_ms = 250u64;

                for attempt in 1..=3 {
                    match client.post(&url).json(&event).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            stats.inc_webhook_deliveries();
                            delivered = true;
                            break;
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

                if !delivered {
                    stats.inc_webhook_failures();
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(lagged_events = n, "Webhook receiver lagged");
            }
            Err(broadcast::error::RecvError::Closed) => {
                info!("Webhook dispatcher stopped: risk channel closed");
                break;
            }
        }
    }
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

        let (tx, rx) = broadcast::channel(8);
        let stats = Arc::new(RuntimeStats::new());
        let task = tokio::spawn(run_webhook_dispatcher(
            format!("http://{addr}"),
            10,
            2,
            rx,
            stats.clone(),
        ));

        tx.send(sample_event(80)).expect("send risk event");
        sleep(Duration::from_millis(300)).await;
        drop(tx);

        timeout(Duration::from_secs(2), task)
            .await
            .expect("dispatcher join timeout")
            .expect("dispatcher task failed");

        let snap = stats.snapshot();
        assert_eq!(snap.webhook_deliveries, 1);
        assert_eq!(snap.webhook_failures, 0);
    }

    #[tokio::test]
    async fn test_webhook_dispatcher_failure_increments_counter() {
        let (tx, rx) = broadcast::channel(8);
        let stats = Arc::new(RuntimeStats::new());
        let task = tokio::spawn(run_webhook_dispatcher(
            "http://127.0.0.1:9".to_string(),
            0,
            1,
            rx,
            stats.clone(),
        ));

        tx.send(sample_event(90)).expect("send risk event");
        sleep(Duration::from_millis(1100)).await;
        drop(tx);

        timeout(Duration::from_secs(3), task)
            .await
            .expect("dispatcher join timeout")
            .expect("dispatcher task failed");

        let snap = stats.snapshot();
        assert_eq!(snap.webhook_deliveries, 0);
        assert_eq!(snap.webhook_failures, 1);
    }
}
