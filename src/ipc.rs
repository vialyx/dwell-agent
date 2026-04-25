use std::path::Path;
use tokio::io::AsyncWriteExt;
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
    mut stream: UnixStream,
    mut risk_rx: tokio::sync::broadcast::Receiver<RiskEvent>,
    _cmd_tx: tokio::sync::mpsc::Sender<String>,
) {
    loop {
        tokio::select! {
            Ok(event) = risk_rx.recv() => {
                match serde_json::to_string(&event) {
                    Ok(json) => {
                        let line = format!("{}\n", json);
                        if stream.write_all(line.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => error!("Failed to serialize risk event: {}", e),
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
