#[cfg(not(unix))]
use std::net::SocketAddr;
#[cfg(unix)]
use std::path::Path;
#[cfg(not(unix))]
use std::sync::Arc;
#[cfg(unix)]
use std::sync::Arc;
#[cfg(not(unix))]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(not(unix))]
use tokio::net::{TcpListener, TcpStream};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(not(unix))]
use tracing::{error, info, warn};
#[cfg(unix)]
use tracing::{error, info, warn};

use crate::risk::RiskEvent;

#[cfg(unix)]
pub struct IpcServer {
    socket_path: String,
    require_same_user: bool,
    owner_uid: u32,
}

#[cfg(not(unix))]
pub struct IpcServer {
    bind_addr: String,
    require_same_user: bool,
}

#[cfg(unix)]
impl IpcServer {
    pub fn new(socket_path: &str, require_same_user: bool) -> Result<Self, std::io::Error> {
        prepare_socket_parent(socket_path)?;

        // Remove stale socket if exists
        if Path::new(socket_path).exists() {
            std::fs::remove_file(socket_path)?;
        }

        Ok(Self {
            socket_path: socket_path.to_string(),
            require_same_user,
            owner_uid: unsafe { libc::geteuid() as u32 },
        })
    }

    pub async fn run(
        &self,
        risk_rx: tokio::sync::broadcast::Receiver<RiskEvent>,
        cmd_tx: tokio::sync::mpsc::Sender<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = UnixListener::bind(&self.socket_path)?;
        set_socket_permissions(&self.socket_path)?;
        info!("IPC server listening on {}", self.socket_path);

        let owner_uid = self.owner_uid;
        let require_same_user = self.require_same_user;
        let cmd_tx = Arc::new(cmd_tx);

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            if require_same_user && !is_authorized_peer(&stream, owner_uid) {
                                warn!("Rejected IPC client with different uid");
                                continue;
                            }

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

#[cfg(not(unix))]
impl IpcServer {
    pub fn new(bind_addr: &str, require_same_user: bool) -> Result<Self, std::io::Error> {
        let parsed: SocketAddr = bind_addr.parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid IPC TCP bind address '{bind_addr}': {e}"),
            )
        })?;
        if !parsed.ip().is_loopback() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "IPC TCP bind address must be loopback on non-Unix platforms",
            ));
        }

        Ok(Self {
            bind_addr: bind_addr.to_string(),
            require_same_user,
        })
    }

    pub async fn run(
        &self,
        risk_rx: tokio::sync::broadcast::Receiver<RiskEvent>,
        cmd_tx: tokio::sync::mpsc::Sender<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.require_same_user {
            warn!(
                "ipc_require_same_user is not enforceable on this platform; relying on loopback-only IPC TCP bind"
            );
        }

        let listener = TcpListener::bind(&self.bind_addr).await?;
        info!("IPC server listening on tcp://{}", self.bind_addr);

        let cmd_tx = Arc::new(cmd_tx);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let risk_rx2 = risk_rx.resubscribe();
                    let cmd_tx2 = cmd_tx.clone();
                    tokio::spawn(handle_tcp_client(stream, risk_rx2, cmd_tx2));
                }
                Err(e) => {
                    error!("IPC TCP accept error: {}", e);
                }
            }
        }
    }
}

#[cfg(unix)]
async fn handle_client(
    stream: UnixStream,
    mut risk_rx: tokio::sync::broadcast::Receiver<RiskEvent>,
    cmd_tx: Arc<tokio::sync::mpsc::Sender<String>>,
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

#[cfg(not(unix))]
async fn handle_tcp_client(
    stream: TcpStream,
    mut risk_rx: tokio::sync::broadcast::Receiver<RiskEvent>,
    cmd_tx: Arc<tokio::sync::mpsc::Sender<String>>,
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
                        error!("IPC TCP client read error: {}", e);
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

#[cfg(unix)]
impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(unix)]
fn prepare_socket_parent(socket_path: &str) -> Result<(), std::io::Error> {
    let path = Path::new(socket_path);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let existed = parent.exists();
    std::fs::create_dir_all(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !existed {
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    Ok(())
}

#[cfg(unix)]
fn set_socket_permissions(socket_path: &str) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(unix)]
fn is_authorized_peer(stream: &UnixStream, owner_uid: u32) -> bool {
    match stream.peer_cred() {
        Ok(creds) => creds.uid() == owner_uid,
        Err(_) => false,
    }
}

#[cfg(all(test, unix))]
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
        let _server = IpcServer::new(&path, true).expect("init IPC server");
        assert!(!Path::new(&path).exists());
    }

    #[tokio::test]
    async fn test_ipc_forwards_commands_and_streams_risk_events() {
        let path = unique_socket_path();
        let server = IpcServer::new(&path, true).expect("init IPC server");

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
