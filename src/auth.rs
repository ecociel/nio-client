use tonic::Status;

#[derive(Debug)]
pub struct Principal(String);

impl Principal {
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

pub enum CheckResult {
    Ok(Principal),
    Forbidden(Principal),
    UnknownPutativeUser,
}


// impl TryFrom<String> for CheckResult {
//     type Error = ParseError;
//
//     fn try_from(value: String) -> Result<Self, Self::Error> {
//         Ok(CheckResult::Principal(Principal(value)))
//     }
// }


#[derive(thiserror::Error, Debug)]
pub enum CallError {
    #[error("unexpected response format")]
    UnexpectedResponseFormat,
    #[error("call error: {0}")]
    Status(#[from] Status),
}

// #[derive(thiserror::Error, Debug)]
// pub enum AuthError {
//     SessionMissing,
//     //InternalServerError(Box<dyn Error>),
//     InternalServerError,
//     Forbidden,
//     BadRequest,
// }

// impl warp::reject::Reject for AuthError {}

// pub trait AuthChecker: Clone + Send {
//     async fn check(
//         &mut self,
//         namespaces: Namespace,
//         obj: Obj,
//         permission: Permission,
//         user_id: UserId,
//     ) -> Result<CheckResult, CallError>;
// }
//
// pub fn uri() -> impl Filter<Extract = (Uri,), Error = Infallible> + Clone {
//     warp::path::full()
//         .and(
//             // Optional query string. See https://github.com/seanmonstar/warp/issues/86
//             query::raw().or(warp::any().map(String::default)).unify(),
//         )
//         .map(|path: FullPath, query: String| {
//             let pq = match query.as_str() {
//                 "" => PathAndQuery::try_from(path.as_str())
//                     .unwrap_or_else(|_| PathAndQuery::from_static("/")),
//                 qs => PathAndQuery::try_from(format!("{}?{}", path.as_str(), qs))
//                     .unwrap_or_else(|_| PathAndQuery::from_static("/")),
//             };
//             Uri::from(pq)
//         })
// }
//
// fn cookie() -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
//     const SESSION_COOKIE: &str = "session";
//     warp::any()
//         .and(warp::cookie::optional(SESSION_COOKIE))
//         .and(uri())
//         .and_then(
//             move |maybe_value: Option<String>, uri: Uri| match maybe_value {
//                 Some(value) => future::ready(Ok(value)),
//                 None => future::ready(Err(AuthError::SessionMissing)),
//             },
//         )
// }

// pub fn authorize<A: AuthChecker>(
//     checker: A,
//     namespaces: Namespace,
//     obj: Option<Obj>,
//     permission: Permission,
// ) -> impl Filter<Extract = ((),), Error = Rejection> + Clone {
//     cookie()
//         .and(with_one(namespaces.clone()))
//         .and(with_one(obj.clone()))
//         .and(with_one(permission.clone()))
//         .and(with_one(checker.clone()))
//         .and_then(|token: String, namespaces, obj, permission, cc: A| async {
//             let user_id = UserId::try_from(token).map_err(|err| AuthError::BadRequest)?;
//             let mut cc = cc;
//             match cc
//                 .check(namespaces, Obj(String::default()), permission, user_id)
//                 .await
//             {
//                 Err(err) => Err(AuthError::InternalServerError.into()), //(Box::new(err)).into()),
//                 //Ok(CheckResult::Principal(principal)) => Ok(principal),
//                 Ok(CheckResult::Principal(_)) => Ok(()),
//                 Ok(CheckResult::Forbidden) => Err(AuthError::Forbidden.into()),
//             }
//         })
// }
//
// pub fn authorize2(
//     agent: impl AuthChecker,
//     namespaces: Namespace,
//     obj: Option<Obj>,
//     permission: Permission,
// ) -> impl Filter<Extract = (Principal,), Error = Infallible> + Clone {
//     warp::any().map(|| Principal(String::default()))
// }
//
// async fn check<A: AuthChecker>(
//     token: String,
//     namespaces: Namespace,
//     obj: Option<Obj>,
//     permission: Permission,
//     cc: A,
// ) -> Result<(), Rejection> {
//     let user_id = UserId::try_from(token).map_err(|err| AuthError::BadRequest)?;
//     let mut cc = cc;
//     match cc
//         .check(namespaces, Obj(String::default()), permission, user_id)
//         .await
//     {
//         Err(err) => Err(AuthError::InternalServerError.into()), //(Box::new(err)).into()),
//         //Ok(CheckResult::Principal(principal)) => Ok(principal),
//         Ok(CheckResult::Principal(_)) => Ok(()),
//         Ok(CheckResult::Forbidden) => Err(AuthError::Forbidden.into()),
//     }
// }