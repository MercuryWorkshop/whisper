use std::sync::Arc;

use anyhow::Context;
use log::{debug, error};
use tokio::sync::{Mutex, MutexGuard};
use tokio_util::task::TaskTracker;
use wisp_mux::{
	extensions::{
		cert::CertAuthProtocolExtensionBuilder,
		motd::{MotdProtocolExtension, MotdProtocolExtensionBuilder},
		password::PasswordProtocolExtensionBuilder,
		udp::{UdpProtocolExtension, UdpProtocolExtensionBuilder},
		ProtocolExtensionBuilderVecExt, ProtocolExtensionVecExt,
	},
	ClientMux, MuxStream, StreamType, WispError, WispV2Handshake, WispV2Middleware,
};

use crate::{ConnProvider, InfoProvider};

pub struct ConnProviderWrapper<P: ConnProvider + 'static, I: InfoProvider + 'static> {
	provider: Arc<Mutex<P>>,
	info: Arc<I>,
	client: Arc<Mutex<Option<ClientMux>>>,
	tracker: TaskTracker,
}

impl<P: ConnProvider + 'static, I: InfoProvider + 'static> Clone for ConnProviderWrapper<P, I> {
	fn clone(&self) -> Self {
		Self {
			provider: self.provider.clone(),
			info: self.info.clone(),
			client: self.client.clone(),
			tracker: self.tracker.clone(),
		}
	}
}

impl<P: ConnProvider + 'static, I: InfoProvider + 'static> ConnProviderWrapper<P, I> {
	pub fn new(provider: P, info: Arc<I>, tracker: TaskTracker) -> Self {
		Self {
			provider: Arc::new(Mutex::new(provider)),
			client: Arc::new(Mutex::new(None)),

			info,
			tracker,
		}
	}

	async fn create_client(
		&self,
		mut guard: MutexGuard<'_, Option<ClientMux>>,
	) -> anyhow::Result<()> {
		if let Some(guard) = guard.as_ref() {
			guard.close().await?;
		}

		let (read, write) = self
			.provider
			.lock()
			.await
			.connect()
			.await
			.context("failed to connect with connprovider")?;

		let extensions = vec![
			UdpProtocolExtensionBuilder.into(),
			MotdProtocolExtensionBuilder::new_client().into(),
			PasswordProtocolExtensionBuilder::new_client(None).into(),
			CertAuthProtocolExtensionBuilder::new_client(None).into(),
		];

		let v2_provider = self.provider.clone();
		let middleware: Box<WispV2Middleware> = Box::new(move |builders| {
			let v2_provider = v2_provider.clone();
			Box::pin(async move {
				debug!("handshake handler started");
				if let Some(password) =
					builders.find_extension_mut::<PasswordProtocolExtensionBuilder>()
				{
					debug!("password auth required: {:?}", password.is_required());
					if password.is_required().unwrap_or(false) {
						let auth = v2_provider
							.lock()
							.await
							.get_password_auth()
							.await
							.context("failed to get password authentication")
							.map_err(|x| WispError::Other(x.into()))?;
						password.set_creds(auth);
					} else {
						builders.remove_extension::<PasswordProtocolExtensionBuilder>();
					}
				}

				if let Some(certauth) =
					builders.find_extension_mut::<CertAuthProtocolExtensionBuilder>()
				{
					debug!("certificate auth required: {:?}", certauth.is_required());
					if certauth.is_required().unwrap_or(false) {
						let auth = v2_provider
							.lock()
							.await
							.get_key_auth()
							.await
							.context("failed to get cert authentication")
							.map_err(|x| WispError::Other(x.into()))?;
						certauth.set_signing_key(auth);
					} else {
						builders.remove_extension::<CertAuthProtocolExtensionBuilder>();
					}
				}
				debug!("handshake handler ended");

				Ok(())
			})
		});

		let v2 = WispV2Handshake::new_with_middleware(extensions, middleware);

		let (mux, fut) = ClientMux::create(read, write, Some(v2))
			.await
			.context("failed to perform handshake")?
			.with_required_extensions(&[UdpProtocolExtension::ID])
			.await
			.context("required extensions not found")?;

		if let Some(ext) = mux
			.supported_extensions
			.find_extension::<MotdProtocolExtension>()
		{
			self.info.on_motd(ext.motd.clone())
		}
		self.info.on_connect();

		let cloned_client = self.client.clone();
		self.tracker.spawn(async move {
			if let Err(err) = fut.await {
				error!("wisp_mux multiplexor task ended with an error: {:?}", err)
			}
			cloned_client.lock().await.take()
		});

		guard.replace(mux);

		Ok(())
	}

	pub async fn replace_mux(&self) -> anyhow::Result<()> {
		self.create_client(self.client.lock().await).await
	}

	pub async fn create_stream(
		&self,
		stream_type: StreamType,
		host: String,
		port: u16,
	) -> anyhow::Result<MuxStream> {
		Box::pin(async {
			let locked = self.client.lock().await;
			if let Some(mux) = locked.as_ref() {
				Ok(mux
					.client_new_stream(stream_type, host.clone(), port)
					.await?)
			} else {
				self.create_client(locked).await?;
				self.create_stream(stream_type, host, port).await
			}
		})
		.await
	}
}
