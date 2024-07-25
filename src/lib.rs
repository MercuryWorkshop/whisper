#![feature(once_cell_try, let_chains)]
mod ffi;
mod pty;
pub mod util;

#[cfg(all(feature = "native-tls", feature = "rustls"))]
compile_error!("native-tls and rustls conflict. enable only one.");

use dashmap::DashMap;
use futures_util::{
	future::select_all, stream::SplitSink, Future, Sink, SinkExt, Stream, StreamExt,
};
use log::{error, info};
use lwip::NetStack;
use tokio_util::compat::FuturesAsyncReadCompatExt;

use std::{
	error::Error,
	net::{Ipv4Addr, SocketAddr},
	path::PathBuf,
	pin::Pin,
	sync::Arc,
	task::Poll,
	time::Duration,
};

use clap::{Args, Parser};
use hyper::Uri;
use tokio::{
	io::copy_bidirectional,
	sync::mpsc::UnboundedReceiver,
	task::JoinError,
	time::{Instant, Sleep},
};
use tun2::AsyncDevice;
use wisp_mux::{ClientMux, MuxStreamIo, StreamType};

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
	// Use wisp v2.
	#[arg(long)]
	pub wisp_v2: bool,
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

struct TimeoutStreamSink<S>(Pin<Box<S>>, Duration, Pin<Box<Sleep>>);

impl<S> TimeoutStreamSink<S> {
	pub fn new(stream: S) -> Self {
		let duration = Duration::from_secs(30);
		Self(
			Box::pin(stream),
			duration,
			Box::pin(tokio::time::sleep(duration)),
		)
	}
}

impl<S: Stream> Stream for TimeoutStreamSink<S> {
	type Item = S::Item;

	fn poll_next(
		mut self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> Poll<Option<Self::Item>> {
		if matches!(self.2.as_mut().poll(cx), Poll::Ready(_)) {
			return Poll::Ready(None);
		}

		let duration = self.1;
		self.2.as_mut().reset(Instant::now() + duration);

		self.0.as_mut().poll_next(cx)
	}
}

impl<S: for<'a> Sink<&'a [u8], Error = std::io::Error>> Sink<Vec<u8>> for TimeoutStreamSink<S> {
	type Error = std::io::Error;

	fn poll_ready(
		mut self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> Poll<Result<(), Self::Error>> {
		if matches!(self.2.as_mut().poll(cx), Poll::Ready(_)) {
			return Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
		}
		self.0.as_mut().poll_ready(cx)
	}

	fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
		let duration = self.1;
		self.2.as_mut().reset(Instant::now() + duration);
		self.0.as_mut().start_send(&item)
	}

	fn poll_flush(
		mut self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> Poll<Result<(), Self::Error>> {
		self.0.as_mut().poll_flush(cx)
	}

	fn poll_close(
		mut self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> Poll<Result<(), Self::Error>> {
		self.0.as_mut().poll_close(cx)
	}
}

type TimeoutMuxStreamSink = SplitSink<TimeoutStreamSink<MuxStreamIo>, Vec<u8>>;

pub async fn start_whisper(
	mux: ClientMux,
	tun: AsyncDevice,
	mtu: u16,
	mut channel: UnboundedReceiver<WhisperEvent>,
) -> Result<(), Box<dyn Error>> {
	let (stack, mut tcp_listener, udp_socket) = NetStack::with_buffer_size(mtu.into(), 64)?;
	let (mut tun_tx, mut tun_rx) = tun.into_framed().split();
	let (mut stack_tx, mut stack_rx) = stack.split();
	let (udp_write, mut udp_read) = udp_socket.split();
	let udp_write = Arc::new(udp_write);

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

	let tcp_mux = mux.clone();
	let tcp_handle: Pin<Box<dyn Future<Output = Result<(), JoinError>>>> =
		Box::pin(tokio::spawn(async move {
			while let Some((mut stream, _src, dest)) = tcp_listener.next().await {
				let stream_mux = tcp_mux.clone();
				tokio::spawn(async move {
					let mut wisp_stream = stream_mux
						.client_new_stream(StreamType::Tcp, dest.ip().to_string(), dest.port())
						.await
						.unwrap()
						.into_io()
						.into_asyncrw()
						.compat();
					drop(stream_mux);
					info!("connected tcp: {:?}", dest);
					if let Err(err) = copy_bidirectional(&mut stream, &mut wisp_stream).await {
						error!("error while forwarding tcp to {:?}: {:?}", dest, err);
					}
					info!("disconnected tcp: {:?}", dest);
				});
			}
		}));

	let udp_mux = mux.clone();
	let udp_handle: Pin<Box<dyn Future<Output = Result<(), JoinError>>>> =
		Box::pin(tokio::spawn(async move {
			let udp_map: Arc<DashMap<(SocketAddr, SocketAddr), TimeoutMuxStreamSink>> =
				Arc::new(DashMap::new());

			while let Some((pkt, src, dest)) = udp_read.next().await {
				if let Some(mut stream) = udp_map.get_mut(&(src, dest)) {
					if let Err(err) = stream.send(pkt).await {
						error!("error while sending udp packet to {}: {:?}", dest, err);
						drop(stream);
						udp_map.remove(&(src, dest));
					}
				} else if let Ok(wisp_stream) = udp_mux
					.client_new_stream(StreamType::Udp, dest.ip().to_string(), dest.port())
					.await
				{
					info!("connected udp: {:?}", dest);

					let udp_channel = udp_write.clone();

					let (wisp_w, mut wisp_r) =
						TimeoutStreamSink::new(wisp_stream.into_io()).split();
					udp_map.insert((src, dest), wisp_w);

					let stream_map = udp_map.clone();
					tokio::spawn(async move {
						while let Some(Ok(pkt)) = wisp_r.next().await {
							udp_channel.send_to(&pkt, &dest, &src).unwrap();
						}
						info!("disconnected udp: {:?}", dest);
						stream_map.remove(&(src, dest));
					});
				}
			}
		}));

	let channel_handle: Pin<Box<dyn Future<Output = Result<(), JoinError>>>> =
		Box::pin(tokio::spawn(async move {
			channel.recv().await;
		}));

	info!("Whisper ready!");

	select_all(&mut [
		read_handle,
		write_handle,
		tcp_handle,
		udp_handle,
		channel_handle,
	])
	.await
	.0?;

	info!("Broke from whisper loop.");
	Ok(())
}
