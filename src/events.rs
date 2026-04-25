use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    KeyDown,
    KeyUp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeEvent {
    pub key_code: u32,
    pub event_type: EventType,
    pub timestamp_ns: u64,
    pub session_id: Uuid,
}
