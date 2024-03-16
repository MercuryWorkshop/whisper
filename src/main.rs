use bytes::Bytes;

mod info;
mod pty;
mod tun;
mod wisp;

#[tokio::main]
async fn main() {
    let args = std::env::args().skip(1);

    let mut pty: String = "/home/endercass/fakepty".to_string();
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

    tun::tun::tun_init(ifname).await.unwrap();

    // let pty = Arc::new(PtyInterface::new(pty).await.unwrap());

    // let pty_input_clone = pty.clone();
    // let pty_output_clone = pty.clone();

    // let input_handle = tokio::spawn(async move {
    //     pty_input_clone.read_from_input().await;
    // });

    // let output_handle = tokio::spawn(async move {
    //     pty_output_clone.write_to_output().await;
    // });

    // tokio::spawn(async move {
    //     let mut count = 0;
    //     loop {
    //         if let Err(err) = pty.write(packet_bytes.clone()).await {
    //             eprintln!("Error sending message: {}", err);
    //         }
    //         println!("Sent message {}", count);
    //         count += 1;
    //         tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    //     }
    // });

    // input_handle.await.unwrap();
    // output_handle.await.unwrap();

    ()
}
