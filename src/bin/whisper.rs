use std::error::Error;

use clap::Parser;
use log::{info, LevelFilter};
use simplelog::{Config, SimpleLogger};
use tokio::sync::mpsc::unbounded_channel;
use tun2::{create_as_async, Configuration};
use whisper::{start_whisper, util::connect_to_wisp, Cli};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error + 'static>> {
    SimpleLogger::init(LevelFilter::Info, Config::default())?;
    let opts = Cli::parse();

    let (mux, socketaddr) = connect_to_wisp(&opts.wisp).await?;

    info!("Creating TUN device with name: {:?}", opts.tun);
    let mut cfg = Configuration::default();
    cfg.address(opts.ip)
        .netmask(opts.mask)
        .destination(opts.dest)
        .mtu(opts.mtu)
        .tun_name(opts.tun)
        .up();
    #[cfg(any(target_os = "linux", windows))]
    cfg.platform_config(|c| {
        #[cfg(target_os = "linux")]
        c.ensure_root_privileges(true);
        #[cfg(windows)]
        c.device_guid(Some(12324323423423434234_u128));
    });
    let tun = create_as_async(&cfg)?;

    if let Some(socketaddr) = socketaddr {
        info!("IP address of Wisp server (whitelist this): {}", socketaddr);
    }

    let (_tx, rx) = unbounded_channel();
    start_whisper(mux, tun, opts.mtu, rx).await
}

