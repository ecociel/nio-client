use crate::UserId;
use std::fmt::{Display, Formatter};
use tonic::Status;

/// The principal a `check` decision applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Principal(UserId);

impl Principal {
    pub fn user_id(&self) -> UserId {
        self.0
    }
}

impl From<UserId> for Principal {
    fn from(value: UserId) -> Self {
        Principal(value)
    }
}

impl Display for Principal {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Debug)]
pub enum CheckResult {
    Ok(Principal),
    Forbidden(Principal),
}

impl CheckResult {
    /// True when the check granted access.
    pub fn is_ok(&self) -> bool {
        matches!(self, CheckResult::Ok(_))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum CallError {
    #[error("unexpected response format")]
    UnexpectedResponseFormat,
    #[error("call error: {0}")]
    Status(#[from] Status),
}
