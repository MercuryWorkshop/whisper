use std::{error::Error, fmt::Display, net::SocketAddr, process::abort};

use bytes::Bytes;
use fastwebsockets::{handshake, FragmentCollectorRead};
use futures_util::Future;
use http_body_util::Empty;
use hyper::{
    header::{CONNECTION, UPGRADE},
    rt::Executor,
    upgrade::Upgraded,
    Request,
};
use hyper_util::rt::TokioIo;
use log::info;
use tokio::{io::WriteHalf, net::TcpStream};
#[cfg(feature = "native-tls")]
use tokio_native_tls::{native_tls, TlsConnector};
#[cfg(feature = "rustls")]
use tokio_rustls::{rustls::{ClientConfig, RootCertStore}, TlsConnector};
use tokio_util::either::Either;
use wisp_mux::{
    ws::{Frame, WebSocketRead, WebSocketWrite},
    ClientMux,
};

use crate::{
    pty::{open_pty, PtyWrite},
    WispServer,
};

pub struct SpawnExecutor;

impl<Fut> Executor<Fut> for SpawnExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, fut: Fut) {
        tokio::spawn(fut);
    }
}

#[derive(Debug)]
pub enum WhisperError {
    UriHasNoScheme,
    UriHasInvalidScheme,
    UriHasNoHost,
    NoSocketAddr,
    NotInitialized,
    AlreadyInitialized,
    NotStarted,
    AlreadyStarted,
    ChannelExited,
    Other(Box<dyn Error>),
}

impl Display for WhisperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UriHasNoScheme => write!(f, "URI has no scheme"),
            Self::UriHasInvalidScheme => write!(f, "URI has invalid scheme"),
            Self::UriHasNoHost => write!(f, "URI has no host"),
            Self::NoSocketAddr => write!(f, "No socket addr"),
            Self::NotInitialized => write!(f, "Whisper not initialized"),
            Self::AlreadyInitialized => write!(f, "Whisper already initialized"),
            Self::NotStarted => write!(f, "Whisper not started"),
            Self::AlreadyStarted => write!(f, "Whisper already started"),
            Self::ChannelExited => write!(f, "Channel exited"),
            Self::Other(err) => err.fmt(f),
        }
    }
}

impl Error for WhisperError {}

impl WhisperError {
    pub fn other(err: impl Error + 'static) -> Self {
        Self::Other(Box::new(err))
    }
}

pub enum EitherWebSocketRead<L: WebSocketRead, R: WebSocketRead> {
    Left(L),
    Right(R),
}

impl<L: WebSocketRead, R: WebSocketRead> WebSocketRead for EitherWebSocketRead<L, R> {
    async fn wisp_read_frame(
        &mut self,
        tx: &wisp_mux::ws::LockedWebSocketWrite<impl wisp_mux::ws::WebSocketWrite>,
    ) -> Result<Frame, wisp_mux::WispError> {
        match self {
            Self::Left(read) => read.wisp_read_frame(tx).await,
            Self::Right(read) => read.wisp_read_frame(tx).await,
        }
    }
}

pub enum EitherWebSocketWrite<L: WebSocketWrite, R: WebSocketWrite> {
    Left(L),
    Right(R),
}

impl<L: WebSocketWrite, R: WebSocketWrite> WebSocketWrite for EitherWebSocketWrite<L, R> {
    async fn wisp_write_frame(&mut self, frame: Frame) -> Result<(), wisp_mux::WispError> {
        match self {
            Self::Left(write) => write.wisp_write_frame(frame).await,
            Self::Right(write) => write.wisp_write_frame(frame).await,
        }
    }
}

pub type WhisperMux = ClientMux<
    EitherWebSocketWrite<fastwebsockets::WebSocketWrite<WriteHalf<TokioIo<Upgraded>>>, PtyWrite>,
>;

pub async fn connect_to_wisp(
    opts: &WispServer,
) -> Result<(WhisperMux, Option<SocketAddr>), Box<dyn Error>> {
    let (rx, tx, socketaddr) = if let Some(pty) = &opts.pty {
        info!("Connecting to PTY [rx, tx]: {:?}", pty);
        let (rx, tx) = open_pty(&pty[0], &pty[1]).await?;
        (
            EitherWebSocketRead::Right(rx),
            EitherWebSocketWrite::Right(tx),
            None,
        )
    } else if let Some(url) = &opts.url {
        info!("Connecting to WebSocket: {:?}", url);

        let tls = match url.scheme_str().ok_or(WhisperError::UriHasNoScheme)? {
            "wss" => Ok(true),
            "ws" => Ok(false),
            _ => Err(Box::new(WhisperError::UriHasInvalidScheme)),
        }?;
        let host = url.host().ok_or(WhisperError::UriHasNoHost)?;
        let port = url.port_u16().unwrap_or(if tls { 443 } else { 80 });

        let socket = TcpStream::connect(format!("{}:{}", host, port)).await?;
        let peer_addr = socket.peer_addr()?;
        let socket = if tls {
            #[cfg(feature = "native-tls")]
            let cx = TlsConnector::from(native_tls::TlsConnector::builder().build()?);
            #[cfg(feature = "rustls")]
            let cx = {
                let mut root_cert_store = RootCertStore::empty();
                root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let config = ClientConfig::builder()
                    .with_root_certificates(root_cert_store)
                    .with_no_client_auth();
                TlsConnector::from(std::sync::Arc::new(config))
            };
            #[cfg(feature = "rustls")]
            let host = rustls_pki_types::ServerName::try_from(host.to_string())?;
            Either::Left(cx.connect(host, socket).await?)
        } else {
            Either::Right(socket)
        };

        let req = Request::builder()
            .method("GET")
            .uri(url.path())
            .header("Host", host)
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "upgrade")
            .header(
                "Sec-WebSocket-Key",
                fastwebsockets::handshake::generate_key(),
            )
            .header("Sec-WebSocket-Version", "13")
            .body(Empty::<Bytes>::new())?;

        let (ws, _) = handshake::client(&SpawnExecutor, req, socket).await?;

        let (rx, tx) = ws.split(tokio::io::split);
        let rx = FragmentCollectorRead::new(rx);
        (
            EitherWebSocketRead::Left(rx),
            EitherWebSocketWrite::Left(tx),
            Some(peer_addr),
        )
    } else {
        unreachable!("neither pty nor url specified");
    };

    let (mux, fut) = ClientMux::new(rx, tx).await?;

    tokio::spawn(async move {
        if let Err(err) = fut.await {
            eprintln!("Error in Wisp multiplexor future: {:?}", err);
            abort();
        }
    });
    info!("Connected.");
    Ok((mux, socketaddr))
}
