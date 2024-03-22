use std::{error::Error, fmt::Display, process::abort};

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
use tokio::{io::WriteHalf, net::TcpStream};
use tokio_native_tls::{native_tls, TlsConnector};
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
#[allow(clippy::enum_variant_names)]
enum WhisperError {
    UriHasNoScheme,
    UriHasInvalidScheme,
    UriHasNoHost,
}

impl Display for WhisperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UriHasNoScheme => write!(f, "URI has no scheme"),
            Self::UriHasInvalidScheme => write!(f, "URI has invalid scheme"),
            Self::UriHasNoHost => write!(f, "URI has no host"),
        }
    }
}

impl Error for WhisperError {}

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

pub async fn connect_to_wisp(
    opts: &WispServer,
) -> Result<
    ClientMux<
        EitherWebSocketWrite<
            fastwebsockets::WebSocketWrite<WriteHalf<TokioIo<Upgraded>>>,
            PtyWrite,
        >,
    >,
    Box<dyn Error>,
> {
    let (rx, tx) = if let Some(pty) = &opts.pty {
        println!("Connecting to PTY: {:?}", pty);
        let (rx, tx) = open_pty(pty).await?;
        (
            EitherWebSocketRead::Right(rx),
            EitherWebSocketWrite::Right(tx),
        )
    } else if let Some(url) = &opts.url {
        println!("Connecting to WebSocket: {:?}", url);

        let tls = match url.scheme_str().ok_or(WhisperError::UriHasNoScheme)? {
            "wss" => Ok(true),
            "ws" => Ok(false),
            _ => Err(Box::new(WhisperError::UriHasInvalidScheme)),
        }?;
        let host = url.host().ok_or(WhisperError::UriHasNoHost)?;
        let port = url.port_u16().unwrap_or(if tls { 443 } else { 80 });

        let socket = TcpStream::connect(format!("{}:{}", host, port)).await?;
        let socket = if tls {
            let cx = TlsConnector::from(native_tls::TlsConnector::builder().build()?);
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
    Ok(mux)
}
