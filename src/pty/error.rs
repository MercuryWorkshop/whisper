/// Errors the pty can encounter.
#[derive(Debug)]
pub enum PtyError {
    /// The pty could not be created.
    CreatePtyFailed,
    /// The pty could not be opened.
    OpenPtyFailed,
    /// The pty io pipe could not be created.
    CreatePipeFailed,
    /// The pty io pipe could not be opened.
    OpenPipeFailed,
    /// The pty io pipe could not be written to.
    WritePipeFailed,
    /// The pty io pipe could not be read from.
    ReadPipeFailed,
    /// The pty io pipe could not be closed.
    ClosePipeFailed,
    /// Other error.
    Other(Box<dyn std::error::Error + Sync + Send>),
}

impl std::fmt::Display for PtyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        use PtyError::*;
        match self {
            CreatePtyFailed => write!(f, "Failed to create pty"),
            OpenPtyFailed => write!(f, "Failed to open pty"),
            CreatePipeFailed => write!(f, "Failed to create pipe"),
            OpenPipeFailed => write!(f, "Failed to open pipe"),
            WritePipeFailed => write!(f, "Failed to write to pipe"),
            ReadPipeFailed => write!(f, "Failed to read from pipe"),
            ClosePipeFailed => write!(f, "Failed to close pipe"),
            Other(err) => write!(f, "Other error: {:?}", err),
        }
    }
}

impl From<std::io::Error> for PtyError {
    fn from(err: std::io::Error) -> PtyError {
        PtyError::Other(Box::new(err))
    }
}

impl std::error::Error for PtyError {}
