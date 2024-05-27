#![feature(once_cell_try, let_chains)]
mod ffi;
mod pty;
pub mod util;

#[cfg(all(feature = "native-tls", feature = "rustls"))]
compile_error!("native-tls and rustls conflict. enable only one.");

use futures_util::{future::select_all, Future, SinkExt, StreamExt};
use log::info;
use lwip::NetStack;
use util::WhisperMux;

use std::{error::Error, net::Ipv4Addr, path::PathBuf, pin::Pin, sync::Arc};

use clap::{Args, Parser};
use hyper::Uri;
use tokio::{io::copy_bidirectional, sync::mpsc::UnboundedReceiver, task::JoinError};
use tun2::AsyncDevice;
use wisp_mux::StreamType;

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
    mut channel: UnboundedReceiver<WhisperEvent>,
) -> Result<(), Box<dyn Error>> {
    let (stack, mut tcp_listener, mut _udp_socket) = NetStack::new()?;
    let (mut tun_tx, mut tun_rx) = tun.into_framed().split();
    let (mut stack_tx, mut stack_rx) = stack.split();

    let mux = Arc::new(mux);

    let read_handle: Pin<Box<dyn Future<Output = Result<(), JoinError>>>> =
        Box::pin(tokio::spawn(async move {
            while let Some(pkt) = stack_rx.next().await {
                if let Ok(pkt) = pkt {
                    tun_tx.send(pkt).await.unwrap();
                }
            }
        }));

    let write_handle: Pin<Box<dyn Future<Output = Result<(), JoinError>>>> =
        Box::pin(tokio::spawn(async move {
            while let Some(pkt) = tun_rx.next().await {
                if let Ok(pkt) = pkt {
                    stack_tx.send(pkt).await.unwrap();
                }
            }
        }));

    info!("Whisper ready!");

    let tcp_mux = mux.clone();
    let tcp_handle: Pin<Box<dyn Future<Output = Result<(), JoinError>>>> =
        Box::pin(tokio::spawn(async move {
            while let Some((mut stream, _local_addr, remote_addr)) = tcp_listener.next().await {
                let stream_mux = tcp_mux.clone();
                tokio::spawn(async move {
                    let mut wisp_stream = stream_mux
                        .client_new_stream(
                            StreamType::Tcp,
                            remote_addr.ip().to_string(),
                            remote_addr.port(),
                        )
                        .await
                        .unwrap()
                        .into_io()
                        .into_asyncrw();
                    copy_bidirectional(&mut stream, &mut wisp_stream)
                        .await
                        .unwrap();
                });
            }
        }));

    let channel_handle: Pin<Box<dyn Future<Output = Result<(), JoinError>>>> =
        Box::pin(tokio::spawn(async move {
            channel.recv().await;
        }));

    info!("Broke from whisper loop.");
    select_all(&mut [read_handle, write_handle, tcp_handle, channel_handle])
        .await
        .0?;
    Ok(())
}
