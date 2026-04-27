use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use crossbeam_channel::Sender;
use tracing::{error, info};
use uuid::Uuid;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::Input::{
    GetRawInputData, RegisterRawInputDevices, RAWINPUT, RAWINPUTDEVICE, RAWINPUTHEADER,
    RIDEV_INPUTSINK, RID_INPUT, RIM_TYPEKEYBOARD,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, PostQuitMessage,
    PostThreadMessageW, RegisterClassW, CS_HREDRAW, CS_VREDRAW, HWND_MESSAGE, MSG, WM_DESTROY,
    WM_INPUT, WM_QUIT, WNDCLASSW,
};

use crate::capture::{CaptureError, KeystrokeCapture};
use crate::events::{EventType, KeystrokeEvent};

// Thread-local storage for the event sender and session, accessed from the WndProc callback.
thread_local! {
    static SENDER: RefCell<Option<Sender<KeystrokeEvent>>> = const { RefCell::new(None) };
    static SESSION_ID: RefCell<Uuid> = RefCell::new(Uuid::nil());
}

pub struct WindowsCapture {
    running: Arc<AtomicBool>,
    capture_thread_id: Arc<AtomicU32>,
}

impl WindowsCapture {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            capture_thread_id: Arc::new(AtomicU32::new(0)),
        }
    }
}

impl Default for WindowsCapture {
    fn default() -> Self {
        Self::new()
    }
}

/// Window procedure for the message-only Raw Input window.
///
/// SAFETY: Called by the OS; must follow Win32 calling conventions.
unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_INPUT => {
            // First call: query the required buffer size.
            let header_size = std::mem::size_of::<RAWINPUTHEADER>() as u32;
            let mut size: u32 = 0;
            GetRawInputData(
                lparam as isize,
                RID_INPUT,
                std::ptr::null_mut(),
                &mut size,
                header_size,
            );

            if size > 0 {
                let mut buf = vec![0u8; size as usize];
                let written = GetRawInputData(
                    lparam as isize,
                    RID_INPUT,
                    buf.as_mut_ptr().cast(),
                    &mut size,
                    header_size,
                );

                if written != u32::MAX {
                    let raw = &*(buf.as_ptr() as *const RAWINPUT);

                    if raw.header.dwType == RIM_TYPEKEYBOARD {
                        let kb = &raw.data.keyboard;

                        // RI_KEY_BREAK (0x01) set → key up; clear → key down.
                        // RI_KEY_E0 / RI_KEY_E1 indicate extended scan codes.
                        let event_type = if (kb.Flags & 0x01) != 0 {
                            EventType::KeyUp
                        } else {
                            EventType::KeyDown
                        };

                        // VKey is the virtual-key code (same mapping as VK_* constants).
                        let key_code = kb.VKey as u32;

                        let timestamp_ns = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_nanos() as u64)
                            .unwrap_or(0);

                        SENDER.with(|cell| {
                            SESSION_ID.with(|sid_cell| {
                                if let Some(sender) = cell.borrow().as_ref() {
                                    let _ = sender.send(KeystrokeEvent {
                                        key_code,
                                        event_type,
                                        timestamp_ns,
                                        session_id: *sid_cell.borrow(),
                                    });
                                }
                            });
                        });
                    }
                }
            }
            0 // handled
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[async_trait]
impl KeystrokeCapture for WindowsCapture {
    async fn start(&self, tx: Sender<KeystrokeEvent>) -> Result<(), CaptureError> {
        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();
        let capture_thread_id = self.capture_thread_id.clone();
        let session_id = Uuid::new_v4();

        std::thread::spawn(move || {
            // Store sender + session_id in thread-locals so wnd_proc can reach them.
            SENDER.with(|cell| *cell.borrow_mut() = Some(tx));
            SESSION_ID.with(|cell| *cell.borrow_mut() = session_id);

            unsafe {
                let tid = GetCurrentThreadId();
                capture_thread_id.store(tid, Ordering::SeqCst);

                let hinstance = GetModuleHandleW(std::ptr::null());

                // Register a window class for our message-only window.
                let class_name: Vec<u16> = "DwellRawInput\0".encode_utf16().collect();
                let wnd_class = WNDCLASSW {
                    style: CS_HREDRAW | CS_VREDRAW,
                    lpfnWndProc: Some(wnd_proc),
                    cbClsExtra: 0,
                    cbWndExtra: 0,
                    hInstance: hinstance,
                    hIcon: 0,
                    hCursor: 0,
                    hbrBackground: 0,
                    lpszMenuName: std::ptr::null(),
                    lpszClassName: class_name.as_ptr(),
                };
                RegisterClassW(&wnd_class);

                // A message-only window (HWND_MESSAGE parent) receives messages but
                // is invisible and not enumerable by other applications.
                let hwnd = CreateWindowExW(
                    0,
                    class_name.as_ptr(),
                    std::ptr::null(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    HWND_MESSAGE,
                    0,
                    hinstance,
                    std::ptr::null(),
                );

                if hwnd == 0 {
                    error!("Failed to create message-only window for Raw Input capture");
                    return;
                }

                // Register for keyboard raw input from all devices, even when not focused
                // (RIDEV_INPUTSINK).
                let rid = RAWINPUTDEVICE {
                    usUsagePage: 0x01, // HID_USAGE_PAGE_GENERIC
                    usUsage: 0x06,     // HID_USAGE_GENERIC_KEYBOARD
                    dwFlags: RIDEV_INPUTSINK,
                    hwndTarget: hwnd,
                };

                let ok =
                    RegisterRawInputDevices(&rid, 1, std::mem::size_of::<RAWINPUTDEVICE>() as u32);
                if ok == 0 {
                    error!("RegisterRawInputDevices failed");
                    return;
                }

                info!("Windows Raw Input keyboard capture started");

                // Standard Win32 message loop; exits when WM_QUIT is posted or
                // the running flag is cleared.
                let mut msg: MSG = std::mem::zeroed();
                loop {
                    if !running.load(Ordering::SeqCst) {
                        break;
                    }
                    // GetMessageW blocks until a message arrives.
                    let ret = GetMessageW(&mut msg, 0, 0, 0);
                    if ret == 0 || ret == -1 {
                        // 0 → WM_QUIT; -1 → error
                        break;
                    }
                    DispatchMessageW(&msg);
                }

                info!("Windows Raw Input message loop exited");
                capture_thread_id.store(0, Ordering::SeqCst);
            }
        });

        Ok(())
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let tid = self.capture_thread_id.load(Ordering::SeqCst);
        if tid != 0 {
            unsafe {
                let _ = PostThreadMessageW(tid, WM_QUIT, 0, 0);
            }
        }
    }
}
