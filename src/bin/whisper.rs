#![feature(let_chains)]
use std::{error::Error, net::TcpListener, process::abort};

use clap::Parser;
use hyper::Uri;
use log::{error, info, LevelFilter};
use simplelog::{Config, SimpleLogger};
use tokio::{net::lookup_host, process::Command, sync::mpsc::unbounded_channel};
use tun2::{create_as_async, Configuration};
use whisper::{
    start_whisper,
    util::{connect_to_wisp, WhisperError},
    Cli, WispServer,
};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error + 'static>> {
    SimpleLogger::init(LevelFilter::Info, Config::default())?;
    let opts = Cli::parse();

    let (mux, socketaddr) = if let Some(ref url) = opts.wisp.url
        && opts.cf
    {
        let free_port = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
        // this can fail but ehhh
        let mut cloudflared_command = Command::new("cloudflared")
            .arg("access")
            .arg("tcp")
            .arg("--hostname")
            .arg(url.to_string())
            .arg("--listener")
            .arg(&free_port.to_string())
            .kill_on_drop(true)
            .spawn()?;
        tokio::spawn(async move {
            if let Err(err) = cloudflared_command.wait().await {
                error!("error in cloudflared command: {:?}", err);
            }
            abort();
        });

        let tls = match url.scheme_str().ok_or(WhisperError::UriHasNoScheme)? {
            "https" => Ok(true),
            "http" => Ok(false),
            _ => Err(Box::new(WhisperError::UriHasInvalidScheme)),
        }?;
        let host = url.host().ok_or(WhisperError::UriHasNoHost)?;
        let port = url.port_u16().unwrap_or(if tls { 443 } else { 80 });

        let socketaddr = lookup_host(format!("{}:{}", host, port)).await?.next();
        let mut local_url = Uri::builder().scheme("ws").authority(free_port.to_string());
        if let Some(path_and_query) = url.path_and_query() {
            local_url = local_url.path_and_query(path_and_query.clone());
        }
        (
            connect_to_wisp(&WispServer {
                pty: None,
                url: Some(local_url.build()?),
            })
            .await?
            .0,
            socketaddr,
        )
    } else {
        connect_to_wisp(&opts.wisp).await?
    };

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
