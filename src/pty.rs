use std::{io, os::fd::AsFd, path::PathBuf};

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::fs::File;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use wisp_mux::{
	ws::{Frame, LockedWebSocketWrite, Payload, WebSocketRead, WebSocketWrite},
	WispError,
};

pub async fn open_pty(file: &PathBuf) -> Result<(PtyRead, PtyWrite), io::Error> {
	let rx = File::options().read(true).write(true).open(file).await?;
	let mut termios = nix::sys::termios::tcgetattr(rx.as_fd())?.clone();
	nix::sys::termios::cfmakeraw(&mut termios);
	nix::sys::termios::tcsetattr(rx.as_fd(), nix::sys::termios::SetArg::TCSANOW, &termios)?;
	let rx = LengthDelimitedCodec::builder()
		.little_endian()
		.max_frame_length(usize::MAX)
		.new_framed(rx);

	let tx = File::options().read(true).write(true).open(file).await?;
	let mut termios = nix::sys::termios::tcgetattr(tx.as_fd())?.clone();
	nix::sys::termios::cfmakeraw(&mut termios);
	nix::sys::termios::tcsetattr(tx.as_fd(), nix::sys::termios::SetArg::TCSANOW, &termios)?;
	let tx = LengthDelimitedCodec::builder()
		.little_endian()
		.max_frame_length(usize::MAX)
		.new_framed(tx);
	Ok((PtyRead(rx), PtyWrite(tx)))
}

pub struct PtyRead(Framed<File, LengthDelimitedCodec>);

#[async_trait]
impl WebSocketRead for PtyRead {
	async fn wisp_read_frame(
		&mut self,
		_: &LockedWebSocketWrite,
	) -> Result<Frame<'static>, WispError> {
		Ok(Frame::binary(Payload::Bytes(
			self.0
				.next()
				.await
				.ok_or(WispError::WsImplSocketClosed)?
				.map_err(|x| WispError::WsImplError(Box::new(x)))?,
		)))
	}
}

pub struct PtyWrite(Framed<File, LengthDelimitedCodec>);

#[async_trait]
impl WebSocketWrite for PtyWrite {
	async fn wisp_write_frame(&mut self, frame: Frame<'_>) -> Result<(), WispError> {
		use wisp_mux::ws::OpCode as O;
		match frame.opcode {
			O::Text | O::Binary => self
				.0
				.send(Bytes::copy_from_slice(frame.payload.as_ref()))
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

	async fn wisp_close(&mut self) -> Result<(), WispError> {
		self.0
			.get_mut()
			.sync_all()
			.await
			.map_err(|x| WispError::WsImplError(Box::new(x)))?;
		self.0
			.close()
			.await
			.map_err(|x| WispError::WsImplError(Box::new(x)))?;
		Ok(())
	}
}
