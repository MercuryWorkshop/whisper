use std::sync::Arc;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use clap::Parser;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use fastwebsockets::{handshake, FragmentCollectorRead};
use http_body_util::Empty;
use hyper::{
	header::{
		CONNECTION, HOST, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, UPGRADE,
	},
	Request, Uri,
};
use hyper_util::rt::TokioExecutor;
use log::{info, trace, LevelFilter};
use sha2::{Digest, Sha256};
use tokio::{
	io::{stdin, AsyncBufReadExt, BufReader},
	net::{lookup_host, TcpSocket},
};
use tokio_rustls::{
	rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
	TlsConnector,
};
use tokio_util::either::Either;
use tun2::{AsyncDevice, Configuration, Device};
use webpki_roots::TLS_SERVER_ROOTS;
use whisper::{ConnProvider, InfoProvider, WhisperConfig};
use wisp_mux::{
	extensions::cert::SigningKey,
	ws::{WebSocketRead, WebSocketWrite},
};

fn tls_connector() -> TlsConnector {
	let root_store = RootCertStore::from_iter(TLS_SERVER_ROOTS.iter().cloned());

	let config = ClientConfig::builder()
		.with_root_certificates(root_store)
		.with_no_client_auth();

	TlsConnector::from(Arc::new(config))
}

struct FastwebsocketsConnProvider {
	iface: String,
	url: Uri,

	key: Option<SigningKey>,
}
impl ConnProvider for FastwebsocketsConnProvider {
	async fn connect(
		&mut self,
	) -> anyhow::Result<(
		impl WebSocketRead + Send + 'static,
		impl WebSocketWrite + Send + 'static,
	)> {
		let tcp_socket = TcpSocket::new_v4().context("failed to create socket")?;
		tcp_socket
			.bind_device(Some(self.iface.as_bytes()))
			.context("failed to bind to device")?;
		let port = self
			.url
			.port_u16()
			.or(self.url.scheme_str().and_then(|x| match x {
				"ws" => Some(80),
				"wss" => Some(443),
				_ => None,
			}))
			.context("no port in wisp url")?;
		let sock = lookup_host(format!(
			"{}:{}",
			self.url.host().context("no host in wisp url")?,
			port,
		))
		.await
		.context("failed to lookup host")?
		.find(|x| x.is_ipv4())
		.context("lookup host returned nothing")?;
		let tcp_stream = tcp_socket
			.connect(sock)
			.await
			.context("failed to connect")?;
		info!("Connected to {:?}", sock);

		let stream = match self.url.scheme_str().context("no scheme in wisp url")? {
			"ws" => Either::Left(tcp_stream),
			"wss" => {
				let tls_connector = tls_connector();
				let tls_stream = tls_connector
					.connect(
						ServerName::try_from(
							self.url
								.authority()
								.context("no authority in wisp url")?
								.to_string(),
						)
						.context("failed to create servername")?,
						tcp_stream,
					)
					.await?;
				Either::Right(tls_stream)
			}
			_ => bail!("invalid scheme in wisp url"),
		};

		let req = Request::builder()
			.method("GET")
			.uri("/")
			.header(HOST, self.url.host().context("no host in wisp url")?)
			.header(UPGRADE, "websocket")
			.header(CONNECTION, "upgrade")
			.header(SEC_WEBSOCKET_KEY, handshake::generate_key())
			.header(SEC_WEBSOCKET_VERSION, "13")
			.header(SEC_WEBSOCKET_PROTOCOL, ":333333")
			.body(Empty::<Bytes>::new())?;

		trace!("calling fastwebsockets handshake");
		let (ws, _) = handshake::client(&TokioExecutor::new(), req, stream).await?;
		trace!("fastwebsockets handshake finished");
		let (read, write) = ws.split(tokio::io::split);
		let read = FragmentCollectorRead::new(read);
		trace!("created fastwebsockets ws");

		Ok((read, write))
	}

	async fn get_key_auth(&mut self) -> anyhow::Result<SigningKey> {
		if let Some(key) = &self.key {
			return Ok(key.clone());
		}

		info!("Enter path to key:");
		let path = BufReader::new(stdin())
			.lines()
			.next_line()
			.await?
			.context("failed to read line")?;
		let data = tokio::fs::read_to_string(path).await?;
		let signer = ed25519_dalek::SigningKey::from_pkcs8_pem(&data)?;
		let binary_key = signer.verifying_key().to_bytes();

		let mut hasher = Sha256::new();
		hasher.update(binary_key);
		let hash: [u8; 32] = hasher.finalize().into();
		let key = SigningKey::new_ed25519(Arc::new(signer), hash);
		self.key = Some(key.clone());

		Ok(key)
	}

	async fn get_password_auth(&mut self) -> anyhow::Result<(String, String)> {
		bail!("Password authentication is insecure.")
	}
}

struct LoggingInfoProvider;

impl InfoProvider for LoggingInfoProvider {
	fn on_motd(&self, motd: String) {
		info!("Wisp server MOTD: {}", motd);
	}

	fn on_connect(&self) {
		info!("Connected.");
	}
}

/// Wisp protocol client that exposes the Wisp connection over a TUN device.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
	/// Name of TUN device.
	#[arg(short, long, default_value = "tun0")]
	bind: String,

	/// Wisp server URL.
	#[arg(short, long)]
	wisp: Uri,

	/// Interface to connect to Wisp with.
	#[arg(short, long)]
	iface: String,

	/// Log level.
	#[arg(short, long, default_value = "debug")]
	log: LevelFilter,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
	let cli = Cli::parse();
	env_logger::builder()
		.filter_module("smoltcp", LevelFilter::Info)
		.filter_level(cli.log)
		.parse_default_env()
		.init();

	let mut tun_cfg = Configuration::default();
	tun_cfg
		.tun_name(cli.bind)
		.address((10, 0, 10, 0))
		.up()
		.platform_config(|x| {
			x.ensure_root_privileges(true);
		});

	let tun = AsyncDevice::new(Device::new(&tun_cfg).context("failed to create tun device")?)
		.context("failed to create tun asyncdevice")?;

	info!("Created TUN device");

	let conn = FastwebsocketsConnProvider {
		url: cli.wisp,
		iface: cli.iface,

		key: None,
	};

	WhisperConfig {
		tun,
		connection: conn,
		info: LoggingInfoProvider,
	}
	.start()
	.await?;

	Ok(())
}
