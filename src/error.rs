use std::fmt::{Display, Formatter};

use tonic::transport::Error;
use tonic::Status;

#[derive(thiserror::Error, Debug)]
pub enum ParseErrorKind {
    #[error("invalid syntax")]
    InvalidSyntaxWithInner(#[from] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(thiserror::Error, Debug)]
#[error("'{value}' has invalid syntax for {item}")]
pub struct ParseError {
    item: String,
    value: String,
    source: ParseErrorKind,
}

#[derive(Debug)]
pub struct ConnectError(pub(super) Error);

impl Display for ConnectError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "connect to check service")
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[derive(Debug)]
pub struct WriteError(pub(super) Status);

impl Display for WriteError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "write tuples grpc call")
    }
}

impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl From<Status> for WriteError {
    fn from(value: Status) -> Self {
        WriteError(value)
    }
}

/// Errors from Read / Expand / Watch / list-namespaces and response decoding.
#[derive(Debug)]
pub enum ReadError {
    /// gRPC transport or server status.
    Grpc(Status),
    /// Server returned a protobuf we cannot map (e.g. missing `Tuple.user`).
    InvalidResponse(String),
}

impl ReadError {
    pub fn invalid_response(msg: impl Into<String>) -> Self {
        ReadError::InvalidResponse(msg.into())
    }
}

impl Display for ReadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Grpc(_) => write!(f, "read tuples grpc call"),
            ReadError::InvalidResponse(msg) => write!(f, "invalid read response: {msg}"),
        }
    }
}

impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReadError::Grpc(status) => Some(status),
            ReadError::InvalidResponse(_) => None,
        }
    }
}

impl From<Status> for ReadError {
    fn from(value: Status) -> Self {
        ReadError::Grpc(value)
    }
}
