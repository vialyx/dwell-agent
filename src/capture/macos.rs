use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use core_foundation::runloop::{kCFRunLoopCommonModes, CFRunLoop};
use core_graphics::event::{
    CGEventTap, CGEventTapLocation, CGEventTapOptions, CGEventTapPlacement, CGEventType, EventField,
};
use crossbeam_channel::Sender;
use tracing::{error, info};
use uuid::Uuid;

use crate::capture::{CaptureError, KeystrokeCapture};
use crate::events::{EventType, KeystrokeEvent};

// Raw FFI to stop a CFRunLoop from another thread.
// CFRunLoopStop is thread-safe per Apple's documentation.
#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRunLoopStop(rl: *const c_void);
    fn CFRunLoopGetCurrent() -> *const c_void;
    fn CFRetain(cf: *const c_void) -> *const c_void;
    fn CFRelease(cf: *const c_void);
}

/// Wraps a raw CFRunLoopRef so it can be sent across threads.
/// CFRunLoop is thread-safe for retain/release/stop operations.
struct RawRunLoop(*const c_void);
unsafe impl Send for RawRunLoop {}
unsafe impl Sync for RawRunLoop {}

impl Drop for RawRunLoop {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}

pub struct MacosCapture {
    running: Arc<AtomicBool>,
    run_loop: Arc<Mutex<Option<RawRunLoop>>>,
}

impl MacosCapture {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            run_loop: Arc::new(Mutex::new(None)),
        }
    }
}

impl Default for MacosCapture {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeystrokeCapture for MacosCapture {
    async fn start(&self, tx: Sender<KeystrokeEvent>) -> Result<(), CaptureError> {
        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();
        let run_loop_store = self.run_loop.clone();
        let session_id = Uuid::new_v4();

        std::thread::spawn(move || {
            // Retain the current run loop so we can stop it from another thread.
            let rl_ref = unsafe {
                let ptr = CFRunLoopGetCurrent();
                CFRetain(ptr)
            };
            if let Ok(mut guard) = run_loop_store.lock() {
                *guard = Some(RawRunLoop(rl_ref));
            }

            let tap_result = CGEventTap::new(
                CGEventTapLocation::HID,
                CGEventTapPlacement::HeadInsertEventTap,
                CGEventTapOptions::ListenOnly,
                vec![CGEventType::KeyDown, CGEventType::KeyUp],
                move |_proxy, event_type, event| {
                    if !running.load(Ordering::SeqCst) {
                        return None;
                    }

                    let et = match event_type {
                        CGEventType::KeyDown => EventType::KeyDown,
                        CGEventType::KeyUp => EventType::KeyUp,
                        _ => return None,
                    };

                    // Virtual key code (HID usage, matches macOS kCGKeyboardEventKeycode).
                    let key_code =
                        event.get_integer_value_field(EventField::KEYBOARD_EVENT_KEYCODE) as u32;

                    let timestamp_ns = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);

                    let _ = tx.send(KeystrokeEvent {
                        key_code,
                        event_type: et,
                        timestamp_ns,
                        session_id,
                    });

                    // ListenOnly: always return None (we must not modify the event).
                    None
                },
            );

            match tap_result {
                Ok(tap) => {
                    let source = tap
                        .mach_port
                        .create_runloop_source(0)
                        .expect("Failed to create CFRunLoopSource from CGEventTap");

                    let run_loop = CFRunLoop::get_current();
                    // SAFETY: add_source is safe; kCFRunLoopCommonModes is a valid static ref.
                    unsafe { run_loop.add_source(&source, kCFRunLoopCommonModes) };
                    tap.enable();

                    info!(
                        "macOS CGEventTap started — ensure Accessibility access is granted in \
                         System Settings → Privacy & Security → Accessibility"
                    );

                    // Blocks until CFRunLoopStop() is called (from stop()).
                    CFRunLoop::run_current();
                    info!("macOS CGEventTap run loop exited");
                }
                Err(()) => {
                    error!(
                        "Failed to create CGEventTap. Grant Accessibility access to this \
                         binary in System Settings → Privacy & Security → Accessibility, \
                         then restart the agent."
                    );
                }
            }
        });

        Ok(())
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        // Wake up and stop the run loop running on the capture thread.
        if let Ok(guard) = self.run_loop.lock() {
            if let Some(ref rl) = *guard {
                // SAFETY: CFRunLoopStop is thread-safe per Apple documentation.
                unsafe { CFRunLoopStop(rl.0) };
            }
        }
    }
}
