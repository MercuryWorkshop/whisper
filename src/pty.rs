use std::{io, path::PathBuf};

use bytes::Bytes;
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use tokio::fs::File;
use tokio_util::codec::{BytesCodec, Framed};
use wisp_mux::{
    ws::{Frame, LockedWebSocketWrite, WebSocketRead, WebSocketWrite},
    WispError,
};

pub async fn open_pty(file: &PathBuf) -> Result<(PtyRead, PtyWrite), io::Error> {
    let pty = File::options().read(true).write(true).open(file).await?;
    let pty = Framed::new(pty, BytesCodec::new());
    let (tx, rx) = pty.split();
    Ok((PtyRead(rx), PtyWrite(tx)))
}

pub struct PtyRead(SplitStream<Framed<File, BytesCodec>>);

impl WebSocketRead for PtyRead {
    async fn wisp_read_frame(
        &mut self,
        _: &LockedWebSocketWrite<impl WebSocketWrite>,
    ) -> Result<Frame, WispError> {
        Ok(Frame::binary(
            self.0
                .next()
                .await
                .ok_or(WispError::WsImplSocketClosed)?
                .map_err(|x| WispError::WsImplError(Box::new(x)))?
                .into(),
        ))
    }
}

pub struct PtyWrite(SplitSink<Framed<File, BytesCodec>, Bytes>);

impl WebSocketWrite for PtyWrite {
    async fn wisp_write_frame(&mut self, frame: Frame) -> Result<(), wisp_mux::WispError> {
        use wisp_mux::ws::OpCode as O;
        match frame.opcode {
            O::Text | O::Binary => self
                .0
                .send(frame.payload)
                .await
                .map_err(|x| WispError::WsImplError(Box::new(x))),
            O::Close => self
                .0
                .close()
                .await
                .map_err(|x| WispError::WsImplError(Box::new(x))),
            _ => Err(WispError::WsImplNotSupported),
        }
    }
}
