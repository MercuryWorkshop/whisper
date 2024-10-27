mod whisper;
use std::future::Future;

pub use whisper::WhisperConfig;
mod conn_provider;

use wisp_mux::{
	extensions::cert::SigningKey,
	ws::{WebSocketRead, WebSocketWrite},
};

pub trait ConnProvider: Sync + Send {
	fn connect(
		&mut self,
	) -> impl Future<
		Output = anyhow::Result<(
			impl WebSocketRead + Send + 'static,
			impl WebSocketWrite + Send + 'static,
		)>,
	> + Sync
	       + Send;

	fn get_password_auth(
		&mut self,
	) -> impl Future<Output = anyhow::Result<(String, String)>> + Sync + Send;
	fn get_key_auth(&mut self) -> impl Future<Output = anyhow::Result<SigningKey>> + Sync + Send;
}

pub trait InfoProvider: Sync + Send {
	fn on_motd(&self, motd: String);
	fn on_connect(&self);
}
