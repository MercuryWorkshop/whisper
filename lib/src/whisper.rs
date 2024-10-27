use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use event_listener::{Event, IntoNotification};
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, trace};
use netstack_smoltcp::{Stack, StackBuilder, TcpListener, TcpStream, UdpSocket};
use tokio::{
	io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf},
	select,
	sync::Mutex,
	time::Instant,
};
use tokio_util::{compat::FuturesAsyncReadCompatExt, sync::CancellationToken, task::TaskTracker};
use tun2::AsyncDevice;
use wisp_mux::{MuxStreamAsyncRead, MuxStreamWrite, StreamType};

use crate::{conn_provider::ConnProviderWrapper, ConnProvider, InfoProvider};

async fn copy_read_fast(
	muxrx: MuxStreamAsyncRead,
	mut tcptx: WriteHalf<TcpStream>,
) -> std::io::Result<()> {
	let mut muxrx = muxrx.compat();
	loop {
		let buf = muxrx.fill_buf().await?;
		if buf.is_empty() {
			tcptx.flush().await?;
			return Ok(());
		}

		let i = tcptx.write(buf).await?;
		if i == 0 {
			return Err(std::io::ErrorKind::WriteZero.into());
		}

		muxrx.consume(i);
	}
}

async fn copy_write_fast(muxtx: MuxStreamWrite, tcprx: ReadHalf<TcpStream>) -> anyhow::Result<()> {
	let mut tcprx = BufReader::with_capacity(4096, tcprx);
	loop {
		let buf = tcprx.fill_buf().await?;

		let len = buf.len();
		if len == 0 {
			return Ok(());
		}

		muxtx.write(&buf).await?;
		tcprx.consume(len);
	}
}

fn forward_tun(tun: AsyncDevice, stack: Stack, tracker: TaskTracker, canceller: CancellationToken) {
	let (mut stack_sink, mut stack_stream) = stack.split();
	let (mut tun_sink, mut tun_stream) = tun.into_framed().split();
	let stack_tun_canceller = canceller.clone();
	tracker.spawn(async move {
		let fut = async {
			while let Some(Ok(pkt)) = stack_stream.next().await {
				let Ok(()) = tun_sink.send(pkt).await else {
					break;
				};
			}
			stack_tun_canceller.cancel();
		};

		select! {
			_ = stack_tun_canceller.cancelled() => (),
			_ = fut => ()
		}
	});
	let tun_stack_canceller = canceller.clone();
	tracker.spawn(async move {
		let fut = async {
			while let Some(Ok(pkt)) = tun_stream.next().await {
				let Ok(()) = stack_sink.send(pkt).await else {
					break;
				};
			}
			tun_stack_canceller.cancel();
		};

		select! {
			_ = tun_stack_canceller.cancelled() => (),
			_ = fut => ()
		}
	});
}

fn forward_tcp<C: ConnProvider, I: InfoProvider>(
	tracker: TaskTracker,
	canceller: CancellationToken,
	mut tcp_listener: TcpListener,
	provider: ConnProviderWrapper<C, I>,
) {
	tracker.clone().spawn(async move {
		let fut = async {
			while let Some((stack_stream, local, remote)) = tcp_listener.next().await {
				debug!("forwarding tcp stream {:?} -> {:?}", local, remote);
				let provider = provider.clone();
				let canceller = canceller.clone();
				tracker.spawn(async move {
					let fut = async {
						let wisp_stream = provider
							.create_stream(StreamType::Tcp, remote.ip().to_string(), remote.port())
							.await?;
						let (muxrx, muxtx) = wisp_stream.into_split();
						let muxrx = muxrx.into_stream().into_asyncread();
						let (tcprx, tcptx) = tokio::io::split(stack_stream);

						trace!("created tcp stream {:?} -> {:?}", local, remote);
						select! {
							_ = canceller.cancelled() => (),
							x = copy_read_fast(muxrx, tcptx) => x?,
							x = copy_write_fast(muxtx, tcprx) => x?,
						}
						trace!("finished tcp stream {:?} -> {:?}", local, remote);
						anyhow::Ok(())
					};

					if let Err(err) = fut.await {
						error!(
							"error while forwarding tcp stream {:?} -> {:?}: {} ({:?})",
							local, remote, err, err
						);
					}
				});
			}
			canceller.cancel();
		};

		select! {
			_ = canceller.cancelled() => (),
			_ = fut => ()
		}
	});
}

fn forward_udp<C: ConnProvider, I: InfoProvider>(
	tracker: TaskTracker,
	canceller: CancellationToken,
	udp_socket: UdpSocket,
	provider: ConnProviderWrapper<C, I>,
) {
	type MapKey = (SocketAddr, SocketAddr);
	type MapValue = (MuxStreamWrite, Arc<Event<bool>>);
	let map: Arc<Mutex<HashMap<MapKey, MapValue>>> = Arc::new(Mutex::new(HashMap::new()));

	let (mut read, write) = udp_socket.split();
	let write = Arc::new(Mutex::new(write));

	tracker.clone().spawn(async move {
		while let Some((packet, src, dst)) = read.next().await {
			let mut locked = map.lock().await;
			if let Some((stream, listener)) = locked.get_mut(&(src, dst)) {
				if let Err(err) = stream.write(packet).await {
					error!(
						"error while forwarding udp {:?} -> {:?}: {:?}",
						src, dst, err
					);
					listener.notify(usize::MAX.tag(true));
					locked.remove(&(src, dst));
				} else {
					listener.notify(usize::MAX.tag(false));
				}
			} else {
				let stream = match provider
					.create_stream(StreamType::Udp, dst.ip().to_string(), dst.port())
					.await
				{
					Ok(x) => x,
					Err(x) => {
						error!(
							"error while creating udp stream for {:?} -> {:?}: {:?}",
							src, dst, x
						);
						continue;
					}
				};
				let (rx, tx) = stream.into_split();

				debug!("created udp stream {:?} -> {:?}", src, dst);

				if let Err(err) = tx.write(packet).await {
					error!(
						"error while forwarding udp {:?} -> {:?}: {:?}",
						src, dst, err
					);
					continue;
				}

				let event = Arc::new(Event::with_tag());
				let udp_canceller = canceller.child_token();
				let map = map.clone();
				let write = write.clone();

				locked.insert((src, dst), (tx, event.clone()));
				let timeout_canceller = udp_canceller.clone();
				tracker.spawn(async move {
					let duration = Duration::from_secs(30);
					let sleep = tokio::time::sleep(duration);
					let mut listen = event.listen();
					tokio::pin!(sleep);
					loop {
						select! {
							() = &mut sleep => {
								trace!("udp stream {:?} -> {:?} timed out", src, dst);
								// timed out
								timeout_canceller.cancel();
								break;
							}
							x = listen => {
								// received an event
								if x {
									// some error
									timeout_canceller.cancel();
									break;
								} else {
									// refresh timeout
									sleep.as_mut().reset(Instant::now() + duration);
								}
								listen = event.listen();
							}
						}
					}
				});
				tracker.spawn(async move {
					let fut = async {
						let fut = async {
							while let Some(pkt) = rx.read().await {
								write.lock().await.send((pkt.to_vec(), dst, src)).await?;
							}

							anyhow::Ok(())
						};

						select! {
							_ = udp_canceller.cancelled() => (),
							x = fut => x?
						}

						anyhow::Ok(())
					};

					if let Err(err) = fut.await {
						error!(
							"error while forwarding udp {:?} -> {:?}: {:?}",
							src, dst, err
						);
					}

					map.lock().await.remove(&(src, dst));
					trace!("cleaned up udp stream {:?} -> {:?}", src, dst);
				});
			}
		}
	});
}

pub struct WhisperConfig<C, I>
where
	C: ConnProvider + 'static,
	I: InfoProvider,
{
	pub tun: AsyncDevice,
	pub connection: C,
	pub info: I,
}

impl<C, I> WhisperConfig<C, I>
where
	C: ConnProvider + 'static,
	I: InfoProvider + 'static,
{
	pub async fn start(self) -> anyhow::Result<()> {
		let tracker = TaskTracker::new();
		let canceller = CancellationToken::new();

		let info = Arc::new(self.info);

		let conn_provider =
			ConnProviderWrapper::new(self.connection, info.clone(), tracker.clone());
		conn_provider.replace_mux().await?;

		let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
			.enable_tcp(true)
			.enable_udp(true)
			.enable_icmp(true)
			.build()
			.context("failed to build netstack")?;

		let runner_canceller = canceller.clone();
		tracker.spawn(async move {
			select! {
				_ = runner_canceller.cancelled() => (),
				_ = runner.unwrap() => ()
			}
			runner_canceller.cancel();
		});

		forward_tun(self.tun, stack, tracker.clone(), canceller.clone());
		forward_tcp(
			tracker.clone(),
			canceller.clone(),
			tcp_listener.unwrap(),
			conn_provider.clone(),
		);
		forward_udp(
			tracker.clone(),
			canceller.clone(),
			udp_socket.unwrap(),
			conn_provider.clone(),
		);

		tracker.close();
		tracker.wait().await;

		Ok(())
	}
}
