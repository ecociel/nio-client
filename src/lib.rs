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
const PERSONAL: &str = "personal";
const ROOT: &str = "root";
const TOKEN: &str = "token";
const SERVICEACCOUNT_NS: &str = "serviceaccount";
impl Namespace {
    pub fn personal() -> Namespace {
        Namespace(PERSONAL.into())
    }
    pub fn token() -> Namespace {
        Namespace(TOKEN.into())
    }
    pub fn root() -> Namespace {
        Namespace(ROOT.into())
    }
    pub fn serviceaccount() -> Namespace {
        Namespace(SERVICEACCOUNT_NS.into())
    }
}

#[derive(Clone, Debug)]
pub struct Permission(pub &'static str);

#[derive(Clone, Debug)]
pub struct Rel(pub String);
impl Rel {
    pub const TRIPLE_DOT: &'static str = "...";
    pub const IS: &'static str = "is";
    pub const PARENT: &'static str = "parent";
    pub const IAM_GET: &'static str = "iam.get";
    pub const IAM_UPDATE: &'static str = "iam.update";
    pub const IAM_DELETE: &'static str = "iam.delete";
    pub const SERVICEACCOUNT_GET: &'static str = "serviceaccount.get";
    pub const SERVICEACCOUNT_CREATE: &'static str = "serviceaccount.create";
    pub const SERVICEACCOUNT_KEY_GET: &'static str = "serviceaccount.key.get";
    pub const SERVICEACCOUNT_KEY_CREATE: &'static str = "serviceaccount.key.create";
    pub const SERVICEACCOUNT_CREATE_TOKEN: &'static str = "serviceaccount.createToken";
    pub const USER_CREATE: &'static str = "user.create";

    pub fn triple_dot() -> Rel {
        Rel(Self::TRIPLE_DOT.into())
    }
    pub fn is() -> Rel {
        Rel(Self::IS.into())
    }
    pub fn parent() -> Rel {
        Rel(Self::PARENT.into())
    }
    pub fn iam_get() -> Rel {
        Rel(Self::IAM_GET.into())
    }
    pub fn iam_update() -> Rel {
        Rel(Self::IAM_UPDATE.into())
    }
    pub fn iam_delete() -> Rel {
        Rel(Self::IAM_DELETE.into())
    }
    pub fn serviceaccount_get() -> Rel {
        Rel(Self::SERVICEACCOUNT_GET.into())
    }
    pub fn serviceaccount_create() -> Rel {
        Rel(Self::SERVICEACCOUNT_CREATE.into())
    }
    pub fn serviceaccount_key_get() -> Rel {
        Rel(Self::SERVICEACCOUNT_KEY_GET.into())
    }
    pub fn serviceaccount_key_create() -> Rel {
        Rel(Self::SERVICEACCOUNT_KEY_CREATE.into())
    }
    pub fn serviceaccount_create_token() -> Rel {
        Rel(Self::SERVICEACCOUNT_CREATE_TOKEN.into())
    }
    pub fn user_upsert() -> Rel {
        Rel(Self::USER_CREATE.into())
    }
}

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
const ROOT_OBJ: &str = "root";
const UNSPECIFIED_OBJ: &str = "...";
impl Obj {
    pub fn unspecified() -> Obj {
        Obj(UNSPECIFIED_OBJ.into())
    }
    pub fn root() -> Obj {
        Obj(ROOT_OBJ.into())
    }
}

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
