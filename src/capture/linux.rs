use async_trait::async_trait;
use crossbeam_channel::Sender;
use evdev::{Device, EventType as EvdevEventType, InputEventKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{error, info};
use uuid::Uuid;

use crate::capture::{CaptureError, KeystrokeCapture};
use crate::events::{EventType, KeystrokeEvent};

pub struct LinuxCapture {
    running: Arc<AtomicBool>,
}

impl LinuxCapture {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

fn find_keyboard_devices() -> Vec<Device> {
    let mut keyboards = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/dev/input") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("event") {
                    if let Ok(device) = Device::open(&path) {
                        if device.supported_events().contains(EvdevEventType::KEY) {
                            info!("Found keyboard device: {:?}", path);
                            keyboards.push(device);
                        }
                    }
                }
            }
        }
    }
    keyboards
}

#[async_trait]
impl KeystrokeCapture for LinuxCapture {
    async fn start(&self, tx: Sender<KeystrokeEvent>) -> Result<(), CaptureError> {
        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let session_id = Uuid::new_v4();

        let mut devices = find_keyboard_devices();
        if devices.is_empty() {
            return Err(CaptureError::Device(
                "No keyboard devices found".to_string(),
            ));
        }

        std::thread::spawn(move || {
            // Use first keyboard device
            let device = &mut devices[0];
            while running.load(Ordering::SeqCst) {
                match device.fetch_events() {
                    Ok(events) => {
                        for ev in events {
                            if let InputEventKind::Key(key) = ev.kind() {
                                let event_type = match ev.value() {
                                    1 => EventType::KeyDown,
                                    0 => EventType::KeyUp,
                                    _ => continue,
                                };
                                let timestamp_ns = ev
                                    .timestamp()
                                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                                    .map(|d| d.as_nanos() as u64)
                                    .unwrap_or(0);
                                let keystroke = KeystrokeEvent {
                                    key_code: key.code() as u32,
                                    event_type,
                                    timestamp_ns,
                                    session_id,
                                };
                                if tx.send(keystroke).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error reading evdev events: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}
