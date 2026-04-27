use crate::events::KeystrokeEvent;
use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaptureError {
    /// Returned when no suitable input device is found (Linux only).
    #[allow(dead_code)]
    #[error("Device error: {0}")]
    Device(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[async_trait]
pub trait KeystrokeCapture: Send + Sync {
    async fn start(
        &self,
        tx: crossbeam_channel::Sender<KeystrokeEvent>,
    ) -> Result<(), CaptureError>;
    fn stop(&self);
}

pub fn create_capture() -> Box<dyn KeystrokeCapture> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxCapture::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacosCapture::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsCapture::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        compile_error!("Unsupported platform");
    }
}

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;
