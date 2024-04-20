#![feature(once_cell_try, let_chains)]
mod ffi;
mod pty;
pub mod util;

#[cfg(all(feature = "native-tls", feature = "rustls"))]
compile_error!("native-tls and rustls conflict. enable only one.");

use log::{error, info};
use util::WhisperMux;

use std::{error::Error, io::ErrorKind, net::Ipv4Addr, path::PathBuf};

use clap::{Args, Parser};
use hyper::Uri;
use ipstack::{IpStack, IpStackConfig};
use tokio::{io::copy_bidirectional, select, sync::mpsc::UnboundedReceiver};
use tun2::AsyncDevice;
use wisp_mux::StreamType;

use crate::util::WhisperError;

/// Wisp client that exposes the Wisp connection over a TUN device.
#[derive(Debug, Parser)]
#[command(version = clap::crate_version!())]
pub struct Cli {
    #[clap(flatten)]
    pub wisp: WispServer,
    /// Name of created TUN device
    #[arg(short, long)]
    pub tun: String,
    /// MTU of created TUN device
    #[arg(short, long, default_value_t = u16::MAX)]
    pub mtu: u16,
    /// IP address of created TUN device
    #[arg(short, long, default_value = "10.0.10.2")]
    pub ip: Ipv4Addr,
    // Mask of created TUN device (defaults to /0)
    #[arg(short = 'M', long, default_value = "0.0.0.0")]
    pub mask: Ipv4Addr,
    // Destination of created TUN device (defaults to 0.0.0.0)
    #[arg(short, long, default_value = "0.0.0.0")]
    pub dest: Ipv4Addr,
    // Use cloudflared access. URL must be specified. You must be logged into cloudflared.
    #[arg(short, long)]
    pub cf: bool,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct WispServer {
    /// Path to PTY device
    #[arg(short, long)]
    pub pty: Option<PathBuf>,
    /// Wisp server URL
    #[arg(short, long)]
    pub url: Option<Uri>,
}

#[derive(Debug, Clone, Copy)]
pub enum WhisperEvent {
    EndFut,
}

pub async fn start_whisper(
    mux: WhisperMux,
    tun: AsyncDevice,
    mtu: u16,
    mut channel: UnboundedReceiver<WhisperEvent>,
) -> Result<(), Box<dyn Error>> {
    let mut ip_stack_config = IpStackConfig::default();
    ip_stack_config.mtu(mtu);
    let mut ip_stack = IpStack::new(ip_stack_config, tun);

    info!("Whisper ready!");

    loop {
        use ipstack::stream::IpStackStream as S;
        let accept = select! {
            x = ip_stack.accept() => x?,
            x = channel.recv() => match x.ok_or(WhisperError::ChannelExited)? {
                WhisperEvent::EndFut => break,
            }
        };
        match accept {
            S::Tcp(mut tcp) => {
                let addr = tcp.peer_addr();
                let mut stream = mux
                    .client_new_stream(StreamType::Tcp, addr.ip().to_string(), addr.port())
                    .await?
                    .into_io()
                    .into_asyncrw();
                tokio::spawn(async move {
                    // ignore NotConnected as that usually mean client side properly closed
                    if let Err(err) = copy_bidirectional(&mut tcp, &mut stream).await
                        && err.kind() != ErrorKind::NotConnected
                    {
                        error!("Error while forwarding TCP stream: {:?}", err);
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
                    // ignore TimedOut as that usually mean client side properly closed
                    if let Err(err) = copy_bidirectional(&mut udp, &mut stream).await
                        && err.kind() != ErrorKind::TimedOut
                    {
                        error!("Error while forwarding UDP datagrams: {:?}", err);
                    }
                });
            }
            _ => {}
        }
    }
    info!("Broke from whisper loop.");
    Ok(())
}
