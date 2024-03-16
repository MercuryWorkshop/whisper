use etherparse::IpNumber;
use tun_tap::{Iface, Mode};

use super::error::TunError;

pub async fn tun_init(ifname: String) -> Result<(), TunError> {
    let iface = Iface::new(&ifname, Mode::Tun)?;
    let name = iface.name();
    println!("Bringing up interface: {}", name);

    let mut buffer = vec![0; 1504]; // MTU + 4 for the header
    loop {
        let nbytes = iface.recv(&mut buffer).unwrap();
        if nbytes < 4 {
            continue;
        }
        let ethertype = u16::from_be_bytes([buffer[2], buffer[3]]);
        match ethertype {
            0x0800 => {
                if let Err(err) = handle_ip_packet(&iface, &mut buffer).await {
                    match err {
                        TunError::UnsupportedPacketType => {
                            eprintln!("Unsupported packet type received");
                            eprintln!("Dropping packet");
                            continue;
                        }
                        _ => Err(err)?,
                    }
                }
            }
            _ => {}
        }
    }
}

async fn handle_ip_packet(iface: &Iface, buffer: &mut [u8]) -> Result<(), TunError> {
    let ip_packet = etherparse::Ipv4HeaderSlice::from_slice(&buffer[4..])?;
    match ip_packet.protocol() {
        IpNumber::TCP => handle_tcp_packet(iface, buffer).await?,
        // TODO: get off your ass and make udp work enderass
        _ => Err(TunError::UnsupportedPacketType)?,
    };
    Ok(())
}

// uhh this should probably be implemented
async fn handle_tcp_packet(iface: &Iface, buffer: &[u8]) -> Result<(), TunError> {
    let (header, slice) = etherparse::TcpHeader::from_slice(&buffer[4 + 20..])?;
    let src_port = header.source_port;
    let dest_port = header.destination_port;
    println!("TCP packet: {} -> {}", src_port, dest_port);
    Ok(())
}
