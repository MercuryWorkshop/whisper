/// Errors the Wisp implementation can return.
#[derive(Debug)]
pub enum WispError {
    /// The packet recieved did not have enough data.
    PacketTooSmall,
    /// The packet recieved had an invalid type.
    InvalidPacketType,
    /// The stream had an invalid type.
    InvalidStreamType,
    /// The stream had an invalid ID.
    InvalidStreamId,
    /// The close packet had an invalid reason.
    InvalidCloseReason,
    /// The URI recieved was invalid.
    InvalidUri,
    /// The URI recieved had no host.
    UriHasNoHost,
    /// The URI recieved had no port.
    UriHasNoPort,
    /// The max stream count was reached.
    MaxStreamCountReached,
    /// The stream had already been closed.
    StreamAlreadyClosed,
    /// The websocket frame recieved had an invalid type.
    WsFrameInvalidType,
    /// The websocket frame recieved was not finished.
    WsFrameNotFinished,
    /// Error specific to the websocket implementation.
    WsImplError(Box<dyn std::error::Error + Sync + Send>),
    /// The websocket implementation socket closed.
    WsImplSocketClosed,
    /// The websocket implementation did not support the action.
    WsImplNotSupported,
    /// The string was invalid UTF-8.
    Utf8Error(std::str::Utf8Error),
    /// Other error.
    Other(Box<dyn std::error::Error + Sync + Send>),
}

impl From<std::str::Utf8Error> for WispError {
    fn from(err: std::str::Utf8Error) -> WispError {
        WispError::Utf8Error(err)
    }
}

impl std::fmt::Display for WispError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        use WispError::*;
        match self {
            PacketTooSmall => write!(f, "Packet too small"),
            InvalidPacketType => write!(f, "Invalid packet type"),
            InvalidStreamType => write!(f, "Invalid stream type"),
            InvalidStreamId => write!(f, "Invalid stream id"),
            InvalidCloseReason => write!(f, "Invalid close reason"),
            InvalidUri => write!(f, "Invalid URI"),
            UriHasNoHost => write!(f, "URI has no host"),
            UriHasNoPort => write!(f, "URI has no port"),
            MaxStreamCountReached => write!(f, "Maximum stream count reached"),
            StreamAlreadyClosed => write!(f, "Stream already closed"),
            WsFrameInvalidType => write!(f, "Invalid websocket frame type"),
            WsFrameNotFinished => write!(f, "Unfinished websocket frame"),
            WsImplError(err) => write!(f, "Websocket implementation error: {:?}", err),
            WsImplSocketClosed => write!(f, "Websocket implementation error: websocket closed"),
            WsImplNotSupported => write!(f, "Websocket implementation error: unsupported feature"),
            Utf8Error(err) => write!(f, "UTF-8 error: {:?}", err),
            Other(err) => write!(f, "Other error: {:?}", err),
        }
    }
}

impl std::error::Error for WispError {}
