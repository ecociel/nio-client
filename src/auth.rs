use tonic::Status;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal(String);

/// The principal used for resources that do not require a session.
pub const ANONYMOUS: &str = "anonymous";

impl Principal {
    pub fn anonymous() -> Principal {
        Principal(ANONYMOUS.into())
    }

    pub fn is_anonymous(&self) -> bool {
        self.0 == ANONYMOUS
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl AsRef<str> for Principal {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl From<String> for Principal {
    fn from(value: String) -> Self {
        Principal(value)
    }
}

impl From<Principal> for String {
    #[inline]
    fn from(value: Principal) -> String {
        value.0
    }
}

impl From<&Principal> for String {
    #[inline]
    fn from(value: &Principal) -> String {
        value.0.clone()
    }
}

#[derive(Clone, Debug)]
pub enum CheckResult {
    Ok(Principal),
    Forbidden(Principal),
    UnknownPutativeUser,
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
