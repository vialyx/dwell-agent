use async_trait::async_trait;
use crossbeam_channel::Sender;

use crate::capture::{CaptureError, KeystrokeCapture};
use crate::events::KeystrokeEvent;

pub struct WindowsCapture;

#[async_trait]
impl KeystrokeCapture for WindowsCapture {
    async fn start(&self, _tx: Sender<KeystrokeEvent>) -> Result<(), CaptureError> {
        Err(CaptureError::Unsupported)
    }

    fn stop(&self) {}
}
