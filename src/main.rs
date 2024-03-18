mod pty;

use std::{env::args, error::Error, io, net::Ipv4Addr};

use ipstack::{IpStack, IpStackConfig};
use tokio::io::copy_bidirectional;
use tun2::{create_as_async, Configuration};
use wisp_mux::{ClientMux, StreamType};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error + 'static>> {
    let file = args()
        .nth(1)
        .ok_or(io::Error::from(io::ErrorKind::NotFound))?;

    let ifname = args()
        .nth(2)
        .ok_or(io::Error::from(io::ErrorKind::NotFound))?;

    println!("pty: {:?}", file);
    println!("ifname: {:?}", ifname);

    let (rx, tx) = pty::open_pty(file).await?;
    let (mux, fut) = ClientMux::new(rx, tx).await?;
    tokio::spawn(fut);

    let mtu = u16::MAX;

    let tun = create_as_async(
        Configuration::default()
            .address(Ipv4Addr::new(10, 0, 10, 2))
            .netmask(Ipv4Addr::new(255, 255, 255, 0))
            .destination(Ipv4Addr::new(10, 0, 10, 1))
            .platform_config(|c| {
                c.ensure_root_privileges(true);
            })
            .mtu(mtu)
            .up(),
    )?;

    let mut ip_stack_config = IpStackConfig::default();
    ip_stack_config.mtu(mtu);
    let mut ip_stack = IpStack::new(ip_stack_config, tun);

    loop {
        use ipstack::stream::IpStackStream as S;
        match ip_stack.accept().await? {
            S::Tcp(mut tcp) => {
                let addr = tcp.peer_addr();
                let mut stream = mux
                    .client_new_stream(StreamType::Tcp, addr.ip().to_string(), addr.port())
                    .await?
                    .into_io()
                    .into_asyncrw();
                tokio::spawn(async move {copy_bidirectional(&mut tcp, &mut stream).await});
            }
            S::Udp(mut udp) => {
                let addr = udp.peer_addr();
                let mut stream = mux
                    .client_new_stream(StreamType::Udp, addr.ip().to_string(), addr.port())
                    .await?
                    .into_io()
                    .into_asyncrw();
                tokio::spawn(async move {copy_bidirectional(&mut udp, &mut stream).await});
            }
            _ => {}
        }
    }
}
