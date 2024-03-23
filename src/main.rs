mod pty;
mod util;

use util::{connect_to_wisp, WhisperMux};

use std::{
    error::Error,
    ffi::{c_char, c_int, c_ushort, CStr},
    net::Ipv4Addr,
    path::PathBuf,
};

use clap::{Args, Parser};
use hyper::Uri;
use ipstack::{IpStack, IpStackConfig};
use tokio::{io::copy_bidirectional, runtime::Runtime};
use tun2::{create_as_async, AsyncDevice, Configuration};
use wisp_mux::StreamType;

/// Wisp client that exposes the Wisp connection over a TUN device.
#[derive(Debug, Parser)]
#[command(version = clap::crate_version!())]
struct Cli {
    #[clap(flatten)]
    wisp: WispServer,
    /// Name of created TUN device
    #[arg(short, long)]
    tun: String,
    /// MTU of created TUN device
    #[arg(short, long, default_value_t = u16::MAX)]
    mtu: u16,
    /// IP address of created TUN device
    #[arg(short, long, default_value = "10.0.10.2")]
    ip: Ipv4Addr,
    // Mask of created TUN device (defaults to /0)
    #[arg(short = 'M', long, default_value = "0.0.0.0")]
    mask: Ipv4Addr,
    // Destination of created TUN device (defaults to 0.0.0.0)
    #[arg(short, long, default_value = "0.0.0.0")]
    dest: Ipv4Addr,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
struct WispServer {
    /// Path to PTY device
    #[arg(short, long)]
    pty: Option<PathBuf>,
    /// Wisp server URL
    #[arg(short, long)]
    url: Option<Uri>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error + 'static>> {
    let opts = Cli::parse();

    let mux = connect_to_wisp(&opts.wisp).await?;

    println!("Creating TUN device with name: {:?}", opts.tun);
    let tun = create_as_async(
        Configuration::default()
            .address(opts.ip)
            .netmask(opts.mask)
            .destination(opts.dest)
            .platform_config(|c| {
                #[cfg(unix)]
                c.ensure_root_privileges(true);
                #[cfg(windows)]
                c.device_guid(Some(12324323423423434234_u128));
            })
            .mtu(opts.mtu)
            .tun_name(opts.tun)
            .up(),
    )?;

    start_whisper(mux, tun, opts.mtu).await
}

/// Start whisper with a raw fd from FFI
///
/// # Safety
/// Call with a valid C string in the ws argument
#[no_mangle]
pub unsafe extern "C" fn start_tun_ffi(fd: c_int, ws: *const c_char, mtu: c_ushort) -> bool {
    let ws = CStr::from_ptr(ws).to_string_lossy().to_string();
    if let Ok(rt) = Runtime::new() {
        rt.block_on(async {
            let mux = connect_to_wisp(&WispServer {
                pty: None,
                url: Some(Uri::try_from(ws)?),
            })
            .await?;
            let mut cfg = Configuration::default();
            cfg.raw_fd(fd);
            let tun = create_as_async(&cfg)?;
            start_whisper(mux, tun, mtu).await
        })
        .is_ok()
    } else {
        false
    }
}

async fn start_whisper(mux: WhisperMux, tun: AsyncDevice, mtu: u16) -> Result<(), Box<dyn Error>> {
    let mut ip_stack_config = IpStackConfig::default();
    ip_stack_config.mtu(mtu);
    let mut ip_stack = IpStack::new(ip_stack_config, tun);

    loop {
        use ipstack::stream::IpStackStream as S;
        match ip_stack.accept().await? {
            S::Tcp(mut tcp) => {
                let addr = tcp.peer_addr();
                let mut stream = mux
                    .client_new_stream(StreamType::Tcp, addr.ip().to_string(), addr.port())
                    .await?
                    .into_io()
                    .into_asyncrw();
                tokio::spawn(async move {
                    if let Err(err) = copy_bidirectional(&mut tcp, &mut stream).await {
                        eprintln!("Error while forwarding TCP stream: {:?}", err);
                    }
                });
            }
            S::Udp(mut udp) => {
                let addr = udp.peer_addr();
                let mut stream = mux
                    .client_new_stream(StreamType::Udp, addr.ip().to_string(), addr.port())
                    .await?
                    .into_io()
                    .into_asyncrw();
                tokio::spawn(async move {
                    if let Err(err) = copy_bidirectional(&mut udp, &mut stream).await {
                        eprintln!("Error while forwarding UDP datagrams: {:?}", err);
                    }
                });
            }
            _ => {}
        }
    }
}
