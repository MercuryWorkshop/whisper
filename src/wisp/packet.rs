use super::error::WispError;
use bytes::{Buf, BufMut, Bytes};

/// Wisp stream type.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum StreamType {
    Tcp = 0x01,
    Udp = 0x02,
}

impl TryFrom<u8> for StreamType {
    type Error = WispError;
    fn try_from(stream_type: u8) -> Result<Self, Self::Error> {
        use StreamType::*;
        match stream_type {
            0x01 => Ok(Tcp),
            0x02 => Ok(Udp),
            _ => Err(Self::Error::InvalidStreamType),
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum CloseReason {
    Unknown = 0x01,
    Voluntary = 0x02,
    Unexpected = 0x03,
    ServerStreamInvalidInfo = 0x41,
    ServerStreamUnreachable = 0x42,
    ServerStreamConnectionTimedOut = 0x43,
    ServerStreamConnectionRefused = 0x44,
    ServerStreamTimedOut = 0x47,
    ServerStreamBlockedAddress = 0x48,
    ServerStreamThrottled = 0x49,
    ClientUnexpected = 0x81,
}

impl TryFrom<u8> for CloseReason {
    type Error = WispError;
    fn try_from(stream_type: u8) -> Result<Self, Self::Error> {
        use CloseReason::*;
        match stream_type {
            0x01 => Ok(Unknown),
            0x02 => Ok(Voluntary),
            0x03 => Ok(Unexpected),
            0x41 => Ok(ServerStreamInvalidInfo),
            0x42 => Ok(ServerStreamUnreachable),
            0x43 => Ok(ServerStreamConnectionTimedOut),
            0x44 => Ok(ServerStreamConnectionRefused),
            0x47 => Ok(ServerStreamTimedOut),
            0x48 => Ok(ServerStreamBlockedAddress),
            0x49 => Ok(ServerStreamThrottled),
            0x81 => Ok(ClientUnexpected),
            _ => Err(Self::Error::InvalidStreamType),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectPacket {
    pub stream_type: StreamType,
    pub destination_port: u16,
    pub destination_hostname: String,
}

impl ConnectPacket {
    pub fn new(
        stream_type: StreamType,
        destination_port: u16,
        destination_hostname: String,
    ) -> Self {
        Self {
            stream_type,
            destination_port,
            destination_hostname,
        }
    }
}

impl TryFrom<Bytes> for ConnectPacket {
    type Error = WispError;
    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.remaining() < (1 + 2) {
            return Err(Self::Error::PacketTooSmall);
        }
        Ok(Self {
            stream_type: bytes.get_u8().try_into()?,
            destination_port: bytes.get_u16_le(),
            destination_hostname: std::str::from_utf8(&bytes)?.to_string(),
        })
    }
}

impl From<ConnectPacket> for Vec<u8> {
    fn from(packet: ConnectPacket) -> Self {
        let mut encoded = Self::with_capacity(1 + 2 + packet.destination_hostname.len());
        encoded.put_u8(packet.stream_type as u8);
        encoded.put_u16_le(packet.destination_port);
        encoded.extend(packet.destination_hostname.bytes());
        encoded
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ContinuePacket {
    pub buffer_remaining: u32,
}

impl ContinuePacket {
    pub fn new(buffer_remaining: u32) -> Self {
        Self { buffer_remaining }
    }
}

impl TryFrom<Bytes> for ContinuePacket {
    type Error = WispError;
    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.remaining() < 4 {
            return Err(Self::Error::PacketTooSmall);
        }
        Ok(Self {
            buffer_remaining: bytes.get_u32_le(),
        })
    }
}

impl From<ContinuePacket> for Vec<u8> {
    fn from(packet: ContinuePacket) -> Self {
        let mut encoded = Self::with_capacity(4);
        encoded.put_u32_le(packet.buffer_remaining);
        encoded
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ClosePacket {
    pub reason: CloseReason,
}

impl ClosePacket {
    pub fn new(reason: CloseReason) -> Self {
        Self { reason }
    }
}

impl TryFrom<Bytes> for ClosePacket {
    type Error = WispError;
    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.remaining() < 1 {
            return Err(Self::Error::PacketTooSmall);
        }
        Ok(Self {
            reason: bytes.get_u8().try_into()?,
        })
    }
}

impl From<ClosePacket> for Vec<u8> {
    fn from(packet: ClosePacket) -> Self {
        let mut encoded = Self::with_capacity(1);
        encoded.put_u8(packet.reason as u8);
        encoded
    }
}

#[derive(Debug, Clone)]
pub enum PacketType {
    Connect(ConnectPacket),
    Data(Bytes),
    Continue(ContinuePacket),
    Close(ClosePacket),
}

impl PacketType {
    pub fn as_u8(&self) -> u8 {
        use PacketType::*;
        match self {
            Connect(_) => 0x01,
            Data(_) => 0x02,
            Continue(_) => 0x03,
            Close(_) => 0x04,
        }
    }
}

impl From<PacketType> for Vec<u8> {
    fn from(packet: PacketType) -> Self {
        use PacketType::*;
        match packet {
            Connect(x) => x.into(),
            Data(x) => x.to_vec(),
            Continue(x) => x.into(),
            Close(x) => x.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub stream_id: u32,
    pub packet: PacketType,
}

impl Packet {
    pub fn new(stream_id: u32, packet: PacketType) -> Self {
        Self { stream_id, packet }
    }

    pub fn new_connect(
        stream_id: u32,
        stream_type: StreamType,
        destination_port: u16,
        destination_hostname: String,
    ) -> Self {
        Self {
            stream_id,
            packet: PacketType::Connect(ConnectPacket::new(
                stream_type,
                destination_port,
                destination_hostname,
            )),
        }
    }

    pub fn new_data(stream_id: u32, data: Bytes) -> Self {
        Self {
            stream_id,
            packet: PacketType::Data(data),
        }
    }

    pub fn new_continue(stream_id: u32, buffer_remaining: u32) -> Self {
        Self {
            stream_id,
            packet: PacketType::Continue(ContinuePacket::new(buffer_remaining)),
        }
    }

    pub fn new_close(stream_id: u32, reason: CloseReason) -> Self {
        Self {
            stream_id,
            packet: PacketType::Close(ClosePacket::new(reason)),
        }
    }
}

impl TryFrom<Bytes> for Packet {
    type Error = WispError;
    fn try_from(mut bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.remaining() < 5 {
            return Err(Self::Error::PacketTooSmall);
        }
        let packet_type = bytes.get_u8();
        use PacketType::*;
        Ok(Self {
            stream_id: bytes.get_u32_le(),
            packet: match packet_type {
                0x01 => Connect(ConnectPacket::try_from(bytes)?),
                0x02 => Data(bytes),
                0x03 => Continue(ContinuePacket::try_from(bytes)?),
                0x04 => Close(ClosePacket::try_from(bytes)?),
                _ => return Err(Self::Error::InvalidPacketType),
            },
        })
    }
}

impl From<Packet> for Vec<u8> {
    fn from(packet: Packet) -> Self {
        let mut encoded = Self::with_capacity(1 + 4);
        encoded.push(packet.packet.as_u8());
        encoded.put_u32_le(packet.stream_id);
        encoded.extend(Vec::<u8>::from(packet.packet));
        encoded
    }
}
