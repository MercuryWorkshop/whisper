use std::{
    ffi::{c_char, c_int, c_ushort, CStr, CString},
    net::SocketAddr,
    ptr,
    sync::OnceLock,
};

use cfg_if::cfg_if;
use hyper::Uri;
use log::info;
use log::LevelFilter;
use tokio::{
    runtime::{Builder, Runtime},
    sync::{
        mpsc::{unbounded_channel, UnboundedSender},
        Mutex,
    },
};
use tun2::{create_as_async, AsyncDevice, Configuration};

use crate::{
    start_whisper,
    util::{connect_to_wisp, WhisperError, WhisperMux},
    WhisperEvent, WispServer,
};

struct WhisperInitState {
    mux: WhisperMux,
    tun: AsyncDevice,
    mtu: u16,
    socketaddr: SocketAddr,
}

struct WhisperRunningState {
    socketaddr: SocketAddr,
    channel: UnboundedSender<WhisperEvent>,
}

static WHISPER: Mutex<(Option<WhisperInitState>, Option<WhisperRunningState>)> =
    Mutex::const_new((None, None));

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

macro_rules! build_runtime {
    () => {
        RUNTIME.get_or_try_init(|| Builder::new_current_thread().enable_all().build())
    };
}

#[no_mangle]
pub extern "C" fn whisper_init_logging(app_name: *const c_char) -> bool {
    #[allow(unused_variables)]
    let app_name = unsafe {
        if app_name.is_null() {
            return false;
        }
        CStr::from_ptr(app_name).to_string_lossy().to_string()
    };
    cfg_if! {
        if #[cfg(target_os = "ios")] {
            oslog::OsLogger::new(&app_name)
                .level_filter(LevelFilter::Info)
                .init().is_ok()
        } else if #[cfg(target_os = "android")] {
            android_log::init(app_name).is_ok()
        } else {
            simplelog::SimpleLogger::init(LevelFilter::Info, simplelog::Config::default()).is_ok()
        }
    }
}

#[no_mangle]
pub extern "C" fn whisper_init(fd: c_int, ws: *const c_char, mtu: c_ushort) -> bool {
    let ws = unsafe {
        if ws.is_null() {
            return false;
        }
        CStr::from_ptr(ws).to_string_lossy().to_string()
    };
    if let Ok(rt) = build_runtime!() {
        rt.block_on(async {
            let mut whisper = WHISPER.lock().await;

            if whisper.0.is_some() || whisper.1.is_some() {
                return Err(WhisperError::AlreadyInitialized);
            }

            let (mux, socketaddr) = connect_to_wisp(&WispServer {
                pty: None,
                url: Some(Uri::try_from(ws).map_err(WhisperError::other)?),
            })
            .await
            .map_err(WhisperError::Other)?;

            let mut cfg = Configuration::default();
            cfg.raw_fd(fd);
            let tun = create_as_async(&cfg).map_err(WhisperError::other)?;

            whisper.0.replace(WhisperInitState {
                mux,
                tun,
                mtu,
                socketaddr: socketaddr.ok_or(WhisperError::NoSocketAddr)?,
            });
            info!("Initialized Whisper.");
            Ok(())
        })
        .is_ok()
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn whisper_get_ws_ip() -> *mut c_char {
    if let Ok(rt) = build_runtime!() {
        let ip = rt.block_on(async {
            let whisper = WHISPER.lock().await;
            if let Some(init) = &whisper.0 {
                CString::new(init.socketaddr.ip().to_string()).map_err(WhisperError::other)
            } else if let Some(running) = &whisper.1 {
                CString::new(running.socketaddr.ip().to_string()).map_err(WhisperError::other)
            } else {
                Err(WhisperError::NotInitialized)
            }
        });
        match ip {
            Ok(ptr) => ptr.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn whisper_free(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            return;
        }
        let _ = CString::from_raw(s);
    };
}

#[no_mangle]
pub extern "C" fn whisper_start() -> bool {
    if let Ok(rt) = build_runtime!() {
        rt.block_on(async {
            let mut whisper = WHISPER.lock().await;
            if whisper.1.is_some() {
                return Err(WhisperError::AlreadyStarted);
            }
            let WhisperInitState {
                mux,
                tun,
                mtu: _,
                socketaddr,
            } = whisper.0.take().ok_or(WhisperError::NotInitialized)?;
            let (channel, rx) = unbounded_channel();
            whisper.1.replace(WhisperRunningState {
                channel,
                socketaddr,
            });
            // unlock so other stuff can be called
            drop(whisper);
            info!("Starting Whisper...");
            let ret = start_whisper(mux, tun, rx)
                .await
                .map_err(WhisperError::Other);
            info!("Whisper finished with ret: {:?}", ret);
            ret
        })
        .is_ok()
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn whisper_stop() -> bool {
    if let Ok(rt) = build_runtime!() {
        rt.block_on(async {
            let mut whisper = WHISPER.lock().await;
            if whisper.1.is_none() {
                return Err(WhisperError::NotStarted);
            }
            let WhisperRunningState { channel, .. } =
                whisper.1.take().ok_or(WhisperError::NotInitialized)?;
            channel
                .send(WhisperEvent::EndFut)
                .map_err(WhisperError::other)?;
            info!("Told Whisper to stop.");
            Ok(())
        })
        .is_ok()
    } else {
        false
    }
}
