use std::fmt::{Display, Formatter};

use tonic::transport::Error;
use tonic::{Code, Status};

#[derive(thiserror::Error, Debug)]
pub enum ParseErrorKind {
    #[error("invalid syntax: '{0}'")]
    InvalidSyntax(String),
}

#[derive(thiserror::Error, Debug)]
#[error("'{value}' has invalid syntax for {item} {source}")]
pub struct ParseError {
    item: String,
    value: String,
    source: ParseErrorKind,
}

impl ParseError {
    pub(crate) fn invalid_syntax(item: &str, value: impl Into<String>, reason: &str) -> Self {
        ParseError {
            item: item.into(),
            value: value.into(),
            source: ParseErrorKind::InvalidSyntax(reason.into()),
        }
    }
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

/// Errors from Write. The precondition zookie has two rejections of its own so
/// callers can match on them; every variant keeps the server status.
#[derive(Debug)]
pub enum WriteError {
    /// `FAILED_PRECONDITION`: a tuple this write touches changed after the
    /// precondition zookie. Re-read, then retry with the fresh zookie.
    ZookieConflict(Status),
    /// `INVALID_ARGUMENT`: the precondition zookie is not older than this
    /// write's commit. Pass a zookie the server returned.
    FutureZookie(Status),
    /// Any other gRPC transport or server status.
    Grpc(Status),
}

impl WriteError {
    fn status(&self) -> &Status {
        match self {
            WriteError::ZookieConflict(status)
            | WriteError::FutureZookie(status)
            | WriteError::Grpc(status) => status,
        }
    }
}

impl Display for WriteError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let status = self.status();
        write!(
            f,
            "write tuples grpc call: {:?}: {}",
            status.code(),
            status.message()
        )
    }
}

impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.status())
    }
}

/// From nio check's `FutureWriteZookie` message. The code alone cannot tell a
/// future zookie from any other invalid argument.
const FUTURE_ZOOKIE_MARKER: &str = "is not strictly before the store fence";

impl From<Status> for WriteError {
    fn from(status: Status) -> Self {
        match status.code() {
            Code::FailedPrecondition => WriteError::ZookieConflict(status),
            Code::InvalidArgument if status.message().contains(FUTURE_ZOOKIE_MARKER) => {
                WriteError::FutureZookie(status)
            }
            _ => WriteError::Grpc(status),
        }
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
            ReadError::Grpc(status) => write!(
                f,
                "read tuples grpc call: {:?}: {}",
                status.code(),
                status.message()
            ),
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
