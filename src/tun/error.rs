/// Errors the tun device implementation can return.
#[derive(Debug)]
pub enum TunError {
    /// The tun device was closed early.
    TunEarlyExit,
    /// The tun device had an invalid packet.
    InvalidPacket,
    /// The type of packet was not supported.
    /// The wisp implementation can only handle TCP and UDP packets.
    /// Note: This should be recoverable.
    UnsupportedPacketType,
    /// Other error.
    Other(Box<dyn std::error::Error + Sync + Send>),
}

impl std::fmt::Display for TunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        use TunError::*;
        match self {
            TunEarlyExit => write!(f, "Tun device closed early"),
            InvalidPacket => write!(f, "Invalid packet"),
            UnsupportedPacketType => write!(f, "Unsupported packet type"),
            Other(err) => write!(f, "Other error: {:?}", err),
        }
    }
}

impl From<std::io::Error> for TunError {
    fn from(err: std::io::Error) -> TunError {
        TunError::Other(Box::new(err))
    }
}

impl From<etherparse::err::ipv4::HeaderSliceError> for TunError {
    fn from(err: etherparse::err::ipv4::HeaderSliceError) -> TunError {
        TunError::Other(Box::new(err))
    }
}

impl From<etherparse::err::tcp::HeaderSliceError> for TunError {
    fn from(err: etherparse::err::tcp::HeaderSliceError) -> TunError {
        TunError::Other(Box::new(err))
    }
}

impl std::error::Error for TunError {}
