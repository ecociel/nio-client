use std::fmt::{Display, Formatter};

// use std::num::ParseIntError;
use tonic::transport::Error;
use tonic::Status;

#[derive(thiserror::Error, Debug)]
pub enum ParseErrorKind {
    //#[error("maxlen is {0}")]
    //LengthLimitExceeded(i32),
    // #[error("invalid syntax: {0}")]
    // InvalidSyntax(String),
    #[error("invalid syntax")]
    InvalidSyntaxWithInner(#[from] Box<dyn std::error::Error + Send + Sync>),
    // #[error("invalid integer")]
    // ParseInt(ParseIntError),
}

#[derive(thiserror::Error, Debug)]
#[error("'{value}' has invalid syntax for {item}")]
pub struct ParseError {
    item: String,
    value: String,
    source: ParseErrorKind,
    //hint: Option<&'static str>
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
pub struct AddError(pub(super) Status);

impl Display for AddError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "add tuples grpc call")
    }
}

impl std::error::Error for AddError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl From<Status> for AddError {
    fn from(value: Status) -> Self {
        AddError(value)
    }
}

#[derive(Debug)]
pub struct ReadError(pub(super) Status);

impl Display for crate::error::ReadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "read tuples grpc call")
    }
}

impl std::error::Error for crate::error::ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl From<Status> for crate::error::ReadError {
    fn from(value: Status) -> Self {
        crate::error::ReadError(value)
    }
}
