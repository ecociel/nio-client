#![allow(unused_variables)]
#![allow(unused_imports)]
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use crate::auth::{CallError, CheckResult};
use crate::error::ReadError;
use crate::pb::tuple_set::ObjectSpec;
use crate::pb::TupleSet;
use chrono::{DateTime, Utc};
pub use error::ConnectError;
use error::{AddError, ParseError};
use http::Uri;
use tonic::transport::Channel;

pub mod auth;
#[cfg(feature = "axum")]
pub mod axum;
mod error;

#[derive(Clone, Debug)]
pub struct Namespace(pub String);

#[derive(Clone, Debug)]
pub struct Permission(pub &'static str);

#[derive(Clone, Debug)]
pub struct Rel(pub String);

impl From<Permission> for Rel {
    fn from(value: Permission) -> Self {
        Rel(value.0.to_string())
    }
}

#[derive(Clone, Debug)]
pub struct UserId(pub String);

#[derive(Clone, Debug)]
pub struct Timestamp(pub String);

impl Timestamp {
    pub fn empty() -> Self {
        Timestamp("1:0000000000000".into())
    }
}

impl FromStr for UserId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(UserId(s.into()))
    }
}

impl TryFrom<String> for UserId {
    type Error = ParseError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        UserId::from_str(&value)
    }
}

#[derive(Clone, Debug)]
pub struct Obj(pub String);

impl FromStr for Obj {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Obj(s.into()))
    }
}

impl TryFrom<String> for Obj {
    type Error = ParseError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Obj::from_str(&value)
    }
}

#[derive(Clone, Debug)]
pub struct Tuple {
    pub ns: Namespace,
    pub obj: Obj,
    pub rel: Rel,
    pub sbj: User,
}

impl Display for Tuple {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Tuple {
                ref ns,
                ref obj,
                ref rel,
                sbj: User::UserId(ref s),
            } => write!(f, "Tuple({}:{}#{}@{})", ns.0, obj.0, rel.0, s),
            Tuple {
                ref ns,
                ref obj,
                ref rel,
                sbj:
                    User::UserSet {
                        ns: ref ns2,
                        obj: ref obj2,
                        rel: ref rel2,
                    },
            } => write!(
                f,
                "Tuple({}:{}#{}@{}:{}#{})",
                ns.0, obj.0, rel.0, ns2.0, obj2.0, rel2.0
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Condition {
    Expires(DateTime<Utc>),
}

#[derive(Clone, Debug)]
pub enum User {
    UserId(String),
    UserSet { ns: Namespace, obj: Obj, rel: Rel },
}

mod pb {
    tonic::include_proto!("am");
}

#[derive(Clone, Debug)]
pub struct CheckClient {
    pub(crate) client: pb::check_service_client::CheckServiceClient<Channel>,
}

impl CheckClient {
    // <<<<<<< HEAD
    //     // pub async fn get_all(&mut self, ns: &Namespace, obj: &Obj) -> Result<String, AddError> {
    //     //     let response = self
    //     //         .client
    //     //         .read(pb::ReadRequest {
    //     //             tuple_sets: vec![TupleSet {
    //     //                 ns: "".to_string(),
    //     //                 spec: Some(ObjectSpec(ObjectSpec {})),
    //     //             }],
    //     //             ts: None,
    //     //         })
    //     //         .await
    //     //         .map(|r| r.into_inner().ts)
    //     //         .map_err(Into::into)?;
    //     // }
    // =======
    pub async fn get_all(&mut self, ns: &Namespace, obj: &Obj) -> Result<Vec<Tuple>, ReadError> {
        let response = self
            .client
            .read(pb::ReadRequest {
                tuple_sets: vec![TupleSet {
                    ns: ns.0.clone(),
                    spec: Some(pb::tuple_set::Spec::ObjectSpec(ObjectSpec {
                        obj: obj.0.clone(),
                        rel: None,
                    })),
                }],
                ts: None,
            })
            .await?;
        let response = response.into_inner();
        Ok(response
            .tuples
            .into_iter()
            .map(|tup| Tuple {
                ns: Namespace(tup.ns),
                obj: Obj(tup.obj),
                rel: Rel(tup.rel),
                sbj: match tup.user {
                    None => todo!(),
                    Some(user) => match user {
                        pb::tuple::User::UserId(userid) => User::UserId(userid),
                        pb::tuple::User::UserSet(pb::UserSet { ns, obj, rel }) => User::UserSet {
                            ns: Namespace(ns),
                            obj: Obj(obj),
                            rel: Rel(rel),
                        },
                    },
                },
            })
            .collect())
    }
    // >>>>>>> b14ae43 (Add read api and client API)
}
impl CheckClient {
    pub async fn create(uri: Uri) -> Result<Self, ConnectError> {
        match Channel::builder(uri).connect().await {
            Ok(channel) => Ok(CheckClient {
                client: pb::check_service_client::CheckServiceClient::new(channel),
            }),
            Err(err) => Err(ConnectError(err)),
        }
    }
    // pub async fn create(uri: Uri) -> Result<Self, ConnectError> {
    //     let retry_strategy = FixedInterval::from_millis(100).take(20);
    //     let channel = Retry::spawn(retry_strategy, connect(uri)).await?;
    //     let client = pb::check_service_client::CheckServiceClient::new(channel.clone());
    //     Ok(CheckClient { client })
    // }
    pub async fn add_one(&mut self, tuple: Tuple) -> Result<String, AddError> {
        let add_tuples = vec![pb::Tuple {
            ns: tuple.ns.0.to_string(),
            obj: tuple.obj.0,
            rel: tuple.rel.0.to_string(),
            user: match tuple.sbj {
                User::UserId(user_id) => Some(pb::tuple::User::UserId(user_id)),
                User::UserSet {
                    ns: Namespace(ns),
                    obj: Obj(obj),
                    rel: Rel(rel),
                } => Some(pb::tuple::User::UserSet(pb::UserSet {
                    ns: ns.to_string(),
                    obj,
                    rel: rel.to_string(),
                })),
            },
            condition: None,
        }];
        dbg!(&add_tuples);
        self.client
            .write(pb::WriteRequest {
                add_tuples,
                ..Default::default()
            })
            .await
            .map(|r| r.into_inner().ts)
            .map_err(Into::into)
    }

    pub async fn add_one_with_condition(
        &mut self,
        tuple: Tuple,
        condition: Condition,
    ) -> Result<String, AddError> {
        let add_tuples = vec![pb::Tuple {
            ns: tuple.ns.0.to_string(),
            obj: tuple.obj.0,
            rel: tuple.rel.0.to_string(),
            user: match tuple.sbj {
                User::UserId(user_id) => Some(pb::tuple::User::UserId(user_id)),
                User::UserSet {
                    ns: Namespace(ns),
                    obj: Obj(obj),
                    rel: Rel(rel),
                } => Some(pb::tuple::User::UserSet(pb::UserSet {
                    ns: ns.to_string(),
                    obj,
                    rel: rel.to_string(),
                })),
            },
            condition: match condition {
                Condition::Expires(exp) => Some(pb::tuple::Condition::Expires(exp.timestamp())),
            },
        }];
        self.client
            .write(pb::WriteRequest {
                add_tuples,
                ..Default::default()
            })
            .await
            .map(|r| r.into_inner().ts)
            .map_err(Into::into)
    }

    pub async fn add_many(&mut self, tuples: Vec<Tuple>) -> Result<String, AddError> {
        let add_tuples = tuples
            .into_iter()
            .map(|tuple| pb::Tuple {
                ns: tuple.ns.0,
                obj: tuple.obj.0,
                rel: tuple.rel.0,
                user: match tuple.sbj {
                    User::UserId(user_id) => Some(pb::tuple::User::UserId(user_id)),
                    User::UserSet {
                        ns: Namespace(ns),
                        obj: Obj(obj),
                        rel: Rel(rel),
                    } => Some(pb::tuple::User::UserSet(pb::UserSet { ns, obj, rel })),
                },
                condition: None,
            })
            .collect();
        self.client
            .write(pb::WriteRequest {
                add_tuples,
                ..Default::default()
            })
            .await
            .map(|r| r.into_inner().ts)
            .map_err(Into::into)
    }

    pub async fn delete_one(&mut self, tuple: Tuple) -> Result<String, AddError> {
        let del_tuples = vec![pb::Tuple {
            ns: tuple.ns.0,
            obj: tuple.obj.0,
            rel: tuple.rel.0.to_string(),
            user: match tuple.sbj {
                User::UserId(user_id) => Some(pb::tuple::User::UserId(user_id)),
                User::UserSet {
                    ns: Namespace(ns),
                    obj: Obj(obj),
                    rel: Rel(rel),
                } => Some(pb::tuple::User::UserSet(pb::UserSet {
                    ns: ns.to_string(),
                    obj,
                    rel: rel.to_string(),
                })),
            },
            condition: None,
        }];
        self.client
            .write(pb::WriteRequest {
                del_tuples,
                ..Default::default()
            })
            .await
            .map(|r| r.into_inner().ts)
            .map_err(Into::into)
    }
}

// fn connect<'a>(
//     uri: Uri,
// ) -> impl FnMut() -> Pin<Box<dyn Future<Output = Result<Channel, ConnectError>> + 'a>> {
//     move || {
//         let uri = uri.clone();
//         Box::pin(async {
//             match Channel::builder(uri).connect().await {
//                 Ok(channel) => Ok(channel),
//                 Err(err) => Err(ConnectError(err)),
//             }
//         })
//     }
// }
impl CheckClient {
    pub async fn check(
        &mut self,
        Namespace(ns): Namespace,
        Obj(obj): Obj,
        Permission(permission): Permission,
        UserId(user_id): UserId,
        timestamp: Option<Timestamp>,
    ) -> Result<CheckResult, CallError> {
        let r = pb::CheckRequest {
            ns: ns.to_string(),
            obj,
            rel: permission.to_string(),
            user_id,
            ts: timestamp.unwrap_or(Timestamp::empty()).0,
        };
        match self.client.check(r).await.map(|r| r.into_inner()) {
            Ok(pb::CheckResponse {
                principal: Some(pb::Principal { id }),
                ok,
            }) if ok => Ok(CheckResult::Ok(id.into())),
            Ok(pb::CheckResponse {
                principal: Some(pb::Principal { id }),
                ok,
            }) if !ok => Ok(CheckResult::Forbidden(id.into())),
            Ok(pb::CheckResponse {
                principal: None, ..
            }) => Ok(CheckResult::UnknownPutativeUser),
            Ok(pb::CheckResponse { .. }) => Err(CallError::UnexpectedResponseFormat),
            Err(status) => Err(status.into()),
        }
    }

    pub async fn list(
        &mut self,
        Namespace(ns): Namespace,
        Rel(rel): Rel,
        UserId(user_id): UserId,
        timestamp: Option<Timestamp>,
    ) -> Result<Vec<String>, CallError> {
        let r = pb::ListRequest {
            ns,
            rel: rel.to_string(),
            user_id,
            ts: timestamp.unwrap_or(Timestamp::empty()).0,
        };
        match self.client.list(r).await.map(|r| r.into_inner()) {
            Ok(response) => Ok(response.objs),
            Err(e) => Err(e.into()),
        }
    }
}