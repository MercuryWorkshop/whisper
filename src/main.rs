use bytes::Bytes;

mod info;
mod wisp;

#[tokio::main]
async fn main() {
    let args = std::env::args().skip(1);

    let mut pty: String = "/dev/pts/1".to_string();
    let mut ifname: String = "wisp0".to_string();

    for arg in args {
        match arg.as_str() {
            "--info" => {
                println!("{}", info::info());
                return;
            }
            _ => {
                if !arg.contains("=") {
                    println!("Invalid argument: {}", arg);
                    return;
                }
                match arg.find('=') {
                    None => {
                        println!("Invalid argument: {}", arg);
                        return;
                    }
                    Some(pos) => {
                        let (key, value) = arg.split_at(pos + 1);
                        match key {
                            "pty=" => {
                                pty = value.to_string();
                            }
                            "ifname=" => ifname = value.to_string(),
                            _ => {
                                println!("Invalid argument: {}", key);
                                return;
                            }
                        }
                    }
                };
            }
        }
    }
    println!("pty: {:?}", pty);
    println!("ifname: {:?}", ifname);

    // let (wisp_tx, wisp_rx) = tokio::sync::mpsc::channel::<Bytes>(1500);
    // let (tun_tx, tun_rx) = tokio::sync::mpsc::channel::<Bytes>(1500);

    let packet = wisp::packet::Packet::new(
        0,
        wisp::packet::PacketType::Connect(wisp::packet::ConnectPacket::new(
            wisp::packet::StreamType::Tcp,
            80,
            "example.com".to_string(),
        )),
    );

    let packet_vec: Vec<u8> = packet.clone().into();
    let packet_bytes = Bytes::from(packet_vec.clone());
    let packet_back = wisp::packet::Packet::try_from(packet_bytes.clone()).unwrap();

    println!("{:?}", packet);
    println!("{:?}", packet_vec);
    println!("{:?}", packet_bytes);
    println!("{:?}", packet_back);
}
