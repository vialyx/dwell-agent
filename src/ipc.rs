use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info};

use crate::risk::RiskEvent;

pub struct IpcServer {
    socket_path: String,
}

impl IpcServer {
    pub fn new(socket_path: &str) -> Self {
        // Remove stale socket if exists
        if Path::new(socket_path).exists() {
            let _ = std::fs::remove_file(socket_path);
        }
        Self {
            socket_path: socket_path.to_string(),
        }
    }

    pub async fn run(
        &self,
        risk_rx: tokio::sync::broadcast::Receiver<RiskEvent>,
        cmd_tx: tokio::sync::mpsc::Sender<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = UnixListener::bind(&self.socket_path)?;
        info!("IPC server listening on {}", self.socket_path);

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            let risk_rx2 = risk_rx.resubscribe();
                            let cmd_tx2 = cmd_tx.clone();
                            tokio::spawn(handle_client(stream, risk_rx2, cmd_tx2));
                        }
                        Err(e) => {
                            error!("IPC accept error: {}", e);
                        }
                    }
                }
            }
        }
    }
}

async fn handle_client(
    stream: UnixStream,
    mut risk_rx: tokio::sync::broadcast::Receiver<RiskEvent>,
    cmd_tx: tokio::sync::mpsc::Sender<String>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    loop {
        tokio::select! {
            read_res = lines.next_line() => {
                match read_res {
                    Ok(Some(line)) => {
                        if cmd_tx.send(line).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        error!("IPC client read error: {}", e);
                        break;
                    }
                }
            }
            recv_res = risk_rx.recv() => {
                match recv_res {
                    Ok(event) => {
                        match serde_json::to_string(&event) {
                            Ok(json) => {
                                let line = format!("{}\n", json);
                                if write_half.write_all(line.as_bytes()).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => error!("Failed to serialize risk event: {}", e),
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::FeatureName;
    use crate::risk::RiskEvent;
    use std::time::Duration;
    use tokio::time::{sleep, timeout};
    use uuid::Uuid;

    fn sample_event(risk_score: u8) -> RiskEvent {
        RiskEvent {
            session_id: Uuid::nil(),
            timestamp_utc: "2026-01-01T00:00:00Z".to_string(),
            risk_score,
            confidence: 0.95,
            anomalous_features: vec![FeatureName::Wpm],
            window_keystrokes: 64,
            model_version: "1.0.0".to_string(),
        }
    }

    fn unique_socket_path() -> String {
        let short = Uuid::new_v4().as_simple().to_string();
        format!("/tmp/dw-{}.sock", &short[..12])
    }

    #[test]
    fn test_new_removes_stale_socket_file() {
        let path = unique_socket_path();
        std::fs::write(&path, b"stale").expect("create stale socket file");
        let _server = IpcServer::new(&path);
        assert!(!Path::new(&path).exists());
    }

    #[tokio::test]
    async fn test_ipc_forwards_commands_and_streams_risk_events() {
        let path = unique_socket_path();
        let server = IpcServer::new(&path);

        let (risk_tx, risk_rx) = tokio::sync::broadcast::channel::<RiskEvent>(16);
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<String>(8);

        let server_task = tokio::spawn(async move {
            let _ = server.run(risk_rx, cmd_tx).await;
        });

        // Wait for listener to appear.
        for _ in 0..20 {
            if Path::new(&path).exists() {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }

        let stream = UnixStream::connect(&path)
            .await
            .expect("connect to IPC socket");
        let (read_half, mut write_half) = stream.into_split();
        let mut lines = BufReader::new(read_half).lines();

        write_half
            .write_all(b"status\n")
            .await
            .expect("write command");

        let cmd = timeout(Duration::from_secs(1), cmd_rx.recv())
            .await
            .expect("command timeout")
            .expect("command channel closed");
        assert_eq!(cmd, "status");

        risk_tx
            .send(sample_event(77))
            .expect("send risk event over broadcast");

        let line = timeout(Duration::from_secs(1), lines.next_line())
            .await
            .expect("event read timeout")
            .expect("line read failed")
            .expect("stream closed before event");

        let parsed: RiskEvent = serde_json::from_str(&line).expect("parse risk event json");
        assert_eq!(parsed.risk_score, 77);

        server_task.abort();
    }
}
