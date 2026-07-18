use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::auth::{CallError, CheckResult};
use crate::error::ReadError;
use chrono::{DateTime, Utc};
pub use error::ConnectError;
use error::{ParseError, WriteError};
use http::Uri;
use tonic::transport::{Channel, ClientTlsConfig};

pub mod auth;
#[cfg(feature = "axum")]
pub mod axum;
mod error;
pub mod memo;
pub mod session;

/// Ns is a collection of objects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Namespace(pub String);

/// Built-in namespaces (nio domain / check bootstrap): `iam` and
/// `serviceaccount` only.
impl Namespace {
    pub const IAM: &'static str = "iam";
    pub const SERVICEACCOUNT: &'static str = "serviceaccount";

    pub fn iam() -> Namespace {
        Namespace(Self::IAM.into())
    }
    pub fn serviceaccount() -> Namespace {
        Namespace(Self::SERVICEACCOUNT.into())
    }
}

/// Rel is a relation (or computed permission) on an object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rel(pub String);

/// Built-in relations (nio domain / check bootstrap). Roles
/// (admin/editor/viewer) carry direct tuples; dotted names are computed
/// permissions. The admin gate triple is iam:root#iam.get|iam.update.
impl Rel {
    pub const IS: &'static str = "is";
    pub const UNSPECIFIED: &'static str = "...";
    pub const PARENT: &'static str = "parent";

    pub const ADMIN: &'static str = "admin";
    pub const EDITOR: &'static str = "editor";
    pub const VIEWER: &'static str = "viewer";

    pub const IAM_GET: &'static str = "iam.get";
    pub const IAM_UPDATE: &'static str = "iam.update";
    pub const IAM_DELETE: &'static str = "iam.delete";

    pub const SERVICEACCOUNT_GET: &'static str = "serviceaccount.get";
    pub const SERVICEACCOUNT_CREATE: &'static str = "serviceaccount.create";
    pub const SERVICEACCOUNT_UPDATE: &'static str = "serviceaccount.update";
    pub const SERVICEACCOUNT_CREATE_TOKEN: &'static str = "serviceaccount.createToken";
    pub const SERVICEACCOUNT_KEY_CREATE: &'static str = "serviceaccount.key.create";
    pub const SERVICEACCOUNT_KEY_GET: &'static str = "serviceaccount.key.get";

    pub const USER_CREATE: &'static str = "user.create";

    /// A relation that never holds. [`CheckClient::check`] short-circuits it
    /// to a denial without an RPC.
    pub const IMPOSSIBLE: &'static str = "impossible";

    pub fn is() -> Rel {
        Rel(Self::IS.into())
    }
    pub fn unspecified() -> Rel {
        Rel(Self::UNSPECIFIED.into())
    }
    pub fn parent() -> Rel {
        Rel(Self::PARENT.into())
    }
    pub fn admin() -> Rel {
        Rel(Self::ADMIN.into())
    }
    pub fn editor() -> Rel {
        Rel(Self::EDITOR.into())
    }
    pub fn viewer() -> Rel {
        Rel(Self::VIEWER.into())
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
    pub fn serviceaccount_update() -> Rel {
        Rel(Self::SERVICEACCOUNT_UPDATE.into())
    }
    pub fn serviceaccount_create_token() -> Rel {
        Rel(Self::SERVICEACCOUNT_CREATE_TOKEN.into())
    }
    pub fn serviceaccount_key_create() -> Rel {
        Rel(Self::SERVICEACCOUNT_KEY_CREATE.into())
    }
    pub fn serviceaccount_key_get() -> Rel {
        Rel(Self::SERVICEACCOUNT_KEY_GET.into())
    }
    pub fn user_create() -> Rel {
        Rel(Self::USER_CREATE.into())
    }
    pub fn impossible() -> Rel {
        Rel(Self::IMPOSSIBLE.into())
    }
}

impl From<&str> for Rel {
    fn from(value: &str) -> Self {
        Rel(value.to_string())
    }
}

/// UserId is a user's ID: a principal UUID, or a public subject marker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserId(pub String);

/// Public subject markers (nio domain). Grantable like any other user id.
impl UserId {
    pub const ALL_USERS: &'static str = "allUsers";
    pub const AUTHENTICATED_USERS: &'static str = "authenticatedUsers";

    pub fn all_users() -> UserId {
        UserId(Self::ALL_USERS.into())
    }
    pub fn authenticated_users() -> UserId {
        UserId(Self::AUTHENTICATED_USERS.into())
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

/// Opaque client-side zookie. Wire value is standard Base64 of
/// `[epoch:u8][millis:u48 BE]` (7 bytes). Treat as opaque: store and echo
/// only; do not invent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timestamp(pub String);

impl Timestamp {
    /// Empty zookie on the wire: Base64 of `01 00 00 00 00 00 00` (epoch=1,
    /// millis=0). Use when no fresher-than constraint is required.
    pub const EMPTY: &'static str = "AQAAAAAAAA==";

    pub fn empty() -> Self {
        Timestamp(Self::EMPTY.into())
    }
}

/// Obj is an object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Obj(pub String);

/// `root` is the singleton object of the iam namespace; `...` is the pointer
/// keyword used as a parent-link object.
impl Obj {
    pub const ROOT: &'static str = "root";
    pub const UNSPECIFIED: &'static str = "...";

    pub fn root() -> Obj {
        Obj(Self::ROOT.into())
    }
    pub fn unspecified() -> Obj {
        Obj(Self::UNSPECIFIED.into())
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

/// UserSet names the set of users holding `rel` on ⟨ns, obj⟩.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserSet {
    pub ns: Namespace,
    pub obj: Obj,
    pub rel: Rel,
}

#[derive(Clone, Debug)]
pub enum User {
    UserId(String),
    UserSet { ns: Namespace, obj: Obj, rel: Rel },
}

#[derive(Clone, Debug)]
pub enum Condition {
    Expires(DateTime<Utc>),
}

/// A relationship edge for Write (add or delete) and Read results.
#[derive(Clone, Debug)]
pub struct Tuple {
    pub ns: Namespace,
    pub obj: Obj,
    pub rel: Rel,
    pub sbj: User,
    pub condition: Option<Condition>,
}

impl Tuple {
    pub fn new(ns: Namespace, obj: Obj, rel: Rel, sbj: User) -> Tuple {
        Tuple {
            ns,
            obj,
            rel,
            sbj,
            condition: None,
        }
    }

    /// Sets the tuple condition to expire at `expires` (UTC).
    pub fn with_expires(mut self, expires: DateTime<Utc>) -> Tuple {
        self.condition = Some(Condition::Expires(expires));
        self
    }
}

impl Display for Tuple {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.sbj {
            User::UserId(s) => write!(
                f,
                "Tuple({}:{}#{}@{})",
                self.ns.0, self.obj.0, self.rel.0, s
            ),
            User::UserSet { ns, obj, rel } => write!(
                f,
                "Tuple({}:{}#{}@{}:{}#{})",
                self.ns.0, self.obj.0, self.rel.0, ns.0, obj.0, rel.0
            ),
        }
    }
}

mod pb {
    tonic::include_proto!("am");
}

#[doc(hidden)]
pub mod wire {
    //! Generated protobuf types. Exposed for integration tests and advanced
    //! use; not part of the stable API.
    pub use crate::pb::*;
}

/// Result of [`CheckClient::list`]: the evaluation snapshot zookie and the
/// objects on which the subject holds the relation. Pass `ts` to a subsequent
/// check/list/read for a consistent snapshot.
#[derive(Clone, Debug)]
pub struct ListResult {
    pub ts: Timestamp,
    pub objs: Vec<String>,
}

/// Result of [`CheckClient::expand`]: the evaluation snapshot zookie, the
/// flattened leaf user ids, and the usersets left opaque (e.g. `...` parent
/// pointers or references the server could not resolve).
#[derive(Clone, Debug)]
pub struct ExpandResult {
    pub ts: Timestamp,
    pub user_ids: Vec<String>,
    pub usersets: Vec<UserSet>,
}

/// Result of [`CheckClient::read`]: the evaluation snapshot zookie and the
/// raw stored tuples matching the filters. Rewrite rules are not applied —
/// use [`CheckClient::expand`] for the effective userset.
#[derive(Clone, Debug)]
pub struct ReadResult {
    pub ts: Timestamp,
    pub tuples: Vec<Tuple>,
}

/// Result of [`CheckClient::content_change_check`]: whether the subject may
/// modify content, and the evaluation snapshot zookie to store with the new
/// content version.
#[derive(Clone, Debug)]
pub struct ContentChangeCheckResult {
    pub ok: bool,
    pub ts: Timestamp,
}

/// Schema metadata for one relation (name + rewrite kind). `kind` is one of
/// `this` | `computed` | `tuple_to` | `union`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationMeta {
    pub name: String,
    pub kind: String,
}

/// Schema metadata for one namespace loaded by check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceMeta {
    pub name: String,
    pub relations: Vec<RelationMeta>,
}

/// One tuple change within an atomic write. `deleted` true = tombstone.
#[derive(Clone, Debug)]
pub struct WatchUpdate {
    pub tuple: Tuple,
    pub deleted: bool,
}

/// One Watch stream message. `ts` is the watermark: every change with commit
/// ts <= `ts` has been delivered. Empty `updates` is a heartbeat. A non-empty
/// batch is one atomic write committed at `ts` — never split across messages —
/// so any `ts` is a safe resume point (exclusive) for a later Watch.
#[derive(Clone, Debug)]
pub struct WatchEvent {
    pub ts: Timestamp,
    pub updates: Vec<WatchUpdate>,
}

/// A server-streaming changelog tail for one namespace. Call [`Self::recv`]
/// until it returns `Ok(None)`; drop the stream to stop watching.
pub struct WatchStream {
    inner: tonic::Streaming<pb::WatchResponse>,
}

impl WatchStream {
    /// Blocks until the next Watch event, `Ok(None)` on clean stream end, or
    /// an error.
    pub async fn recv(&mut self) -> Result<Option<WatchEvent>, ReadError> {
        match self.inner.message().await {
            Ok(None) => Ok(None),
            Ok(Some(resp)) => watch_event_from_pb(resp).map(Some),
            Err(status) => Err(status.into()),
        }
    }
}

/// One TupleSet filter for the Read API (paper §2.4.2 / §2.4.3). Build with
/// [`ReadFilter::by_object`], [`ReadFilter::by_user`], or
/// [`ReadFilter::by_user_set`].
#[derive(Clone, Debug)]
pub struct ReadFilter {
    set: pb::TupleSet,
}

impl ReadFilter {
    /// Reads stored tuples on ⟨ns, obj⟩. `rel` `None` means all relations.
    pub fn by_object(ns: Namespace, obj: Obj, rel: Option<Rel>) -> ReadFilter {
        ReadFilter {
            set: pb::TupleSet {
                ns: ns.0,
                spec: Some(pb::tuple_set::Spec::ObjectSpec(pb::tuple_set::ObjectSpec {
                    obj: obj.0,
                    rel: rel.map(|r| r.0),
                })),
            },
        }
    }

    /// Reverse-reads tuples in `ns` whose subject is `user_id` (paper §2.4.3
    /// UserSetSpec). Answered via the reverse index — raw stored edges, no
    /// rewrite evaluation. `rel` `None` means all relations.
    pub fn by_user(ns: Namespace, user_id: UserId, rel: Option<Rel>) -> ReadFilter {
        ReadFilter {
            set: pb::TupleSet {
                ns: ns.0,
                spec: Some(pb::tuple_set::Spec::UsersetSpec(
                    pb::tuple_set::UserSetSpec {
                        user: Some(pb::tuple_set::user_set_spec::User::UserId(user_id.0)),
                        rel: rel.map(|r| r.0),
                    },
                )),
            },
        }
    }

    /// Reverse-reads tuples in `ns` whose subject is the userset. `rel`
    /// `None` means all relations.
    pub fn by_user_set(ns: Namespace, user_set: UserSet, rel: Option<Rel>) -> ReadFilter {
        ReadFilter {
            set: pb::TupleSet {
                ns: ns.0,
                spec: Some(pb::tuple_set::Spec::UsersetSpec(
                    pb::tuple_set::UserSetSpec {
                        user: Some(pb::tuple_set::user_set_spec::User::UserSet(pb::UserSet {
                            ns: user_set.ns.0,
                            obj: user_set.obj.0,
                            rel: user_set.rel.0,
                        })),
                        rel: rel.map(|r| r.0),
                    },
                )),
            },
        }
    }
}

pub type ObserveCheckFn =
    Arc<dyn Fn(&Namespace, &Obj, &Rel, &UserId, Duration, bool, bool) + Send + Sync>;
pub type ObserveListFn = Arc<dyn Fn(&Namespace, &Rel, &UserId, Duration, bool) + Send + Sync>;

// HTTP/2 keepalive contract shared with nio check_client (#239): pings must
// flow while idle so connections survive L4 idle-eviction.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const KEEPALIVE_WHILE_IDLE: bool = true;

/// Opens a gRPC channel with HTTP/2 keepalive (30s interval, 10s timeout,
/// pings while idle) so idle connections survive L4 idle-eviction (IPVS,
/// cloud LBs, NAT — nio #239). Used for both the check and the session
/// endpoint; pass `None` for an insecure channel (local dev only).
pub async fn connect_channel(
    uri: Uri,
    tls_config: Option<ClientTlsConfig>,
) -> Result<Channel, ConnectError> {
    let mut builder = Channel::builder(uri)
        .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
        .keep_alive_timeout(KEEPALIVE_TIMEOUT)
        .keep_alive_while_idle(KEEPALIVE_WHILE_IDLE);
    if let Some(tls) = tls_config {
        builder = builder.tls_config(tls).map_err(ConnectError)?;
    }
    builder.connect().await.map_err(ConnectError)
}

/// RPC-only check client (CheckService + NamespaceService). It has no session
/// resolution; for HTTP middleware combine it with a
/// [`session::SessionResolver`] (see the `axum` module's `AuthState`).
#[derive(Clone)]
pub struct CheckClient {
    check: pb::check_service_client::CheckServiceClient<Channel>,
    ns: pb::namespace_service_client::NamespaceServiceClient<Channel>,
    observe_check: Option<ObserveCheckFn>,
    observe_list: Option<ObserveListFn>,
}

impl std::fmt::Debug for CheckClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckClient").finish_non_exhaustive()
    }
}

impl CheckClient {
    pub async fn create(uri: Uri) -> Result<Self, ConnectError> {
        Self::create_with_tls(uri, None).await
    }

    pub async fn create_with_tls(
        uri: Uri,
        tls_config: Option<ClientTlsConfig>,
    ) -> Result<Self, ConnectError> {
        let channel = connect_channel(uri, tls_config).await?;
        Ok(Self::from_channel(channel))
    }

    pub fn from_channel(channel: Channel) -> Self {
        CheckClient {
            check: pb::check_service_client::CheckServiceClient::new(channel.clone()),
            ns: pb::namespace_service_client::NamespaceServiceClient::new(channel),
            observe_check: None,
            observe_list: None,
        }
    }

    /// Sets an observe function called after every check RPC with
    /// (ns, obj, rel, user_id, duration, ok, is_error).
    pub fn with_observe_check(mut self, f: ObserveCheckFn) -> Self {
        self.observe_check = Some(f);
        self
    }

    /// Sets an observe function called after every list RPC with
    /// (ns, rel, user_id, duration, is_error).
    pub fn with_observe_list(mut self, f: ObserveListFn) -> Self {
        self.observe_list = Some(f);
        self
    }

    /// Calls the check server's Check API: may `user_id` — a principal UUID;
    /// resolve session tokens to a principal client-side first (see
    /// [`crate::session`]) — exercise `rel` on ⟨ns, obj⟩? Evaluated at a
    /// snapshot at least as fresh as `timestamp` (a zookie from an earlier
    /// write/read); `None` accepts any current snapshot. An unknown principal
    /// maps to [`CheckResult::UnknownPutativeUser`], a known-but-unauthorized
    /// user to [`CheckResult::Forbidden`]. [`Rel::IMPOSSIBLE`] short-circuits
    /// to a denial (empty principal) without an RPC.
    pub async fn check(
        &mut self,
        ns: Namespace,
        obj: Obj,
        rel: Rel,
        user_id: UserId,
        timestamp: Option<Timestamp>,
    ) -> Result<CheckResult, CallError> {
        if rel.0 == Rel::IMPOSSIBLE {
            return Ok(CheckResult::Forbidden(String::new().into()));
        }
        let r = pb::CheckRequest {
            ns: ns.0.clone(),
            obj: obj.0.clone(),
            rel: rel.0.clone(),
            user_id: user_id.0.clone(),
            ts: timestamp.unwrap_or_else(Timestamp::empty).0,
        };
        let started = std::time::Instant::now();
        let result = self.check.check(r).await;
        if let Some(observe) = &self.observe_check {
            let ok = result.as_ref().map(|r| r.get_ref().ok).unwrap_or(false);
            observe(
                &ns,
                &obj,
                &rel,
                &user_id,
                started.elapsed(),
                ok,
                result.is_err(),
            );
        }
        match result.map(|r| r.into_inner()) {
            Ok(pb::CheckResponse {
                principal: Some(pb::Principal { id }),
                ok,
            }) => {
                if ok {
                    Ok(CheckResult::Ok(id.into()))
                } else {
                    Ok(CheckResult::Forbidden(id.into()))
                }
            }
            Ok(pb::CheckResponse {
                principal: None,
                ok: false,
            }) => Ok(CheckResult::UnknownPutativeUser),
            // ok without a principal is a contract violation (Go: ErrEmptyPrincipal).
            Ok(pb::CheckResponse {
                principal: None,
                ok: true,
            }) => Err(CallError::UnexpectedResponseFormat),
            Err(status) => Err(status.into()),
        }
    }

    /// Calls the check server's List API: the objects in `ns` on which the
    /// user holds `rel`, with rewrite rules applied — the user→objects dual
    /// of [`Self::check`]. Same zookie semantics as `check`. The returned
    /// `ts` is the evaluation snapshot so callers can chain a subsequent
    /// check/list/read to the same point in time.
    pub async fn list(
        &mut self,
        ns: Namespace,
        rel: Rel,
        user_id: UserId,
        timestamp: Option<Timestamp>,
    ) -> Result<ListResult, CallError> {
        let r = pb::ListRequest {
            ns: ns.0.clone(),
            rel: rel.0.clone(),
            user_id: user_id.0.clone(),
            ts: timestamp.unwrap_or_else(Timestamp::empty).0,
        };
        let started = std::time::Instant::now();
        let result = self.check.list(r).await;
        if let Some(observe) = &self.observe_list {
            observe(&ns, &rel, &user_id, started.elapsed(), result.is_err());
        }
        match result.map(|r| r.into_inner()) {
            Ok(response) => Ok(ListResult {
                ts: Timestamp(response.ts),
                objs: response.objs,
            }),
            Err(e) => Err(e.into()),
        }
    }

    /// Calls the check server's Expand API (paper §2.4.5): the effective
    /// userset of ⟨ns, obj, rel⟩, including assignments only reachable
    /// through userset rewrite rules. Pass the `ts` returned by a previous
    /// call to evaluate several expansions against one consistent snapshot;
    /// `None` lets the server choose.
    pub async fn expand(
        &mut self,
        ns: Namespace,
        obj: Obj,
        rel: Rel,
        timestamp: Option<Timestamp>,
    ) -> Result<ExpandResult, ReadError> {
        let r = pb::ExpandRequest {
            ns: ns.0,
            obj: obj.0,
            rel: rel.0,
            ts: timestamp.unwrap_or_else(Timestamp::empty).0,
        };
        match self.check.expand(r).await.map(|r| r.into_inner()) {
            Ok(response) => Ok(ExpandResult {
                ts: Timestamp(response.ts),
                user_ids: response.user_ids,
                usersets: response
                    .usersets
                    .into_iter()
                    .map(|us| UserSet {
                        ns: Namespace(us.ns),
                        obj: Obj(us.obj),
                        rel: Rel(us.rel),
                    })
                    .collect(),
            }),
            Err(status) => Err(status.into()),
        }
    }

    /// Authorizes a content modification against the freshest snapshot (never
    /// a client-supplied zookie). Returns the evaluation zookie to store with
    /// the new content version.
    pub async fn content_change_check(
        &mut self,
        ns: Namespace,
        obj: Obj,
        rel: Rel,
        user_id: UserId,
    ) -> Result<ContentChangeCheckResult, CallError> {
        let r = pb::ContentChangeCheckRequest {
            ns: ns.0,
            obj: obj.0,
            rel: rel.0,
            user_id: user_id.0,
        };
        match self
            .check
            .content_change_check(r)
            .await
            .map(|r| r.into_inner())
        {
            Ok(response) => Ok(ContentChangeCheckResult {
                ok: response.ok,
                ts: Timestamp(response.ts),
            }),
            Err(status) => Err(status.into()),
        }
    }

    /// Starts a server-streaming tail of the changelog for `ns` (paper
    /// §2.4.6). Only changes committed after `start_ts` are delivered,
    /// oldest-first, interleaved with heartbeats (empty updates). Drop the
    /// stream to stop. Resume later by passing any previously received
    /// event's `ts` as `start_ts`.
    pub async fn watch(
        &mut self,
        ns: Namespace,
        start_ts: Timestamp,
    ) -> Result<WatchStream, CallError> {
        let r = pb::WatchRequest {
            ns: ns.0,
            start_ts: start_ts.0,
        };
        match self.check.watch(r).await {
            Ok(response) => Ok(WatchStream {
                inner: response.into_inner(),
            }),
            Err(status) => Err(status.into()),
        }
    }

    /// Fetches the namespace configs the check server loaded: per namespace
    /// the declared relations and the rewrite kind of each. Schema metadata
    /// only — no tuples.
    pub async fn list_namespaces(&mut self) -> Result<Vec<NamespaceMeta>, ReadError> {
        match self.ns.list_namespaces(()).await.map(|r| r.into_inner()) {
            Ok(resp) => Ok(resp
                .namespaces
                .into_iter()
                .map(|ns| NamespaceMeta {
                    name: ns.name,
                    relations: ns
                        .relations
                        .into_iter()
                        .map(|r| RelationMeta {
                            name: r.name,
                            kind: r.kind,
                        })
                        .collect(),
                })
                .collect()),
            Err(status) => Err(status.into()),
        }
    }

    /// Returns every stored tuple on ⟨ns, obj⟩ (all relations). Stored edges
    /// only — rewrites are not evaluated.
    pub async fn get_all(&mut self, ns: &Namespace, obj: &Obj) -> Result<ReadResult, ReadError> {
        self.read(vec![ReadFilter::by_object(ns.clone(), obj.clone(), None)])
            .await
    }

    /// Returns stored tuples on ⟨ns, obj, rel⟩.
    pub async fn get_all_rel(
        &mut self,
        ns: &Namespace,
        obj: &Obj,
        rel: &Rel,
    ) -> Result<ReadResult, ReadError> {
        self.read(vec![ReadFilter::by_object(
            ns.clone(),
            obj.clone(),
            Some(rel.clone()),
        )])
        .await
    }

    /// Reverse-reads tuples in `ns` whose subject is `user_id`. `rel` `None`
    /// means all relations. Answered via the reverse index — no rewrites.
    pub async fn read_by_user(
        &mut self,
        ns: &Namespace,
        user_id: &UserId,
        rel: Option<Rel>,
    ) -> Result<ReadResult, ReadError> {
        self.read(vec![ReadFilter::by_user(ns.clone(), user_id.clone(), rel)])
            .await
    }

    /// Reverse-reads tuples in `ns` whose subject is the userset. `rel`
    /// `None` means all relations.
    pub async fn read_by_user_set(
        &mut self,
        ns: &Namespace,
        user_set: &UserSet,
        rel: Option<Rel>,
    ) -> Result<ReadResult, ReadError> {
        self.read(vec![ReadFilter::by_user_set(
            ns.clone(),
            user_set.clone(),
            rel,
        )])
        .await
    }

    /// Returns stored tuples matching `filters` at any current snapshot.
    pub async fn read(&mut self, filters: Vec<ReadFilter>) -> Result<ReadResult, ReadError> {
        self.read_with_timestamp(Timestamp::empty(), filters).await
    }

    /// Returns stored tuples matching `filters` at a snapshot at least as
    /// fresh as `ts`. The returned `ts` is the snapshot the server used.
    pub async fn read_with_timestamp(
        &mut self,
        ts: Timestamp,
        filters: Vec<ReadFilter>,
    ) -> Result<ReadResult, ReadError> {
        if filters.is_empty() {
            return Err(ReadError::invalid_response(
                "read: at least one filter required",
            ));
        }
        let request = pb::ReadRequest {
            ts: (ts != Timestamp::empty()).then_some(ts.0),
            tuple_sets: filters.into_iter().map(|f| f.set).collect(),
        };
        let response = self.check.read(request).await?.into_inner();
        let mut tuples = Vec::with_capacity(response.tuples.len());
        for tup in response.tuples {
            tuples.push(tuple_from_pb(tup)?);
        }
        Ok(ReadResult {
            ts: Timestamp(response.ts),
            tuples,
        })
    }

    /// Commits `add` and `del` tuples atomically. `precondition` is an
    /// optional OCC zookie; `None` is an unconditional write. Returns the
    /// commit zookie for read-your-writes / chaining subsequent reads.
    pub async fn write(
        &mut self,
        add: Vec<Tuple>,
        del: Vec<Tuple>,
        precondition: Option<Timestamp>,
    ) -> Result<Timestamp, WriteError> {
        let request = pb::WriteRequest {
            ts: precondition.map(|t| t.0),
            add_tuples: add.into_iter().map(tuple_to_pb).collect(),
            del_tuples: del.into_iter().map(tuple_to_pb).collect(),
        };
        self.check
            .write(request)
            .await
            .map(|r| Timestamp(r.into_inner().ts))
            .map_err(Into::into)
    }

    /// Adds one tuple. Returns the commit zookie for read-your-writes.
    pub async fn add_one(&mut self, tuple: Tuple) -> Result<Timestamp, WriteError> {
        self.write(vec![tuple], vec![], None).await
    }

    /// Adds many tuples atomically. Returns the commit zookie.
    pub async fn add_many(&mut self, tuples: Vec<Tuple>) -> Result<Timestamp, WriteError> {
        self.write(tuples, vec![], None).await
    }

    /// Adds an inheritance relationship using the quasi-standard relation
    /// `parent`: ns:obj#parent@parent_ns:parent_obj#`...`. Returns the commit
    /// zookie.
    pub async fn add_parent(
        &mut self,
        ns: Namespace,
        obj: Obj,
        parent_ns: Namespace,
        parent_obj: Obj,
    ) -> Result<Timestamp, WriteError> {
        self.add_one(Tuple::new(
            ns,
            obj,
            Rel::parent(),
            User::UserSet {
                ns: parent_ns,
                obj: parent_obj,
                rel: Rel::unspecified(),
            },
        ))
        .await
    }

    /// Deletes one tuple. Returns the commit zookie.
    pub async fn delete_one(&mut self, tuple: Tuple) -> Result<Timestamp, WriteError> {
        self.write(vec![], vec![tuple], None).await
    }
}

fn tuple_to_pb(t: Tuple) -> pb::Tuple {
    pb::Tuple {
        ns: t.ns.0,
        obj: t.obj.0,
        rel: t.rel.0,
        user: Some(match t.sbj {
            User::UserId(user_id) => pb::tuple::User::UserId(user_id),
            User::UserSet { ns, obj, rel } => pb::tuple::User::UserSet(pb::UserSet {
                ns: ns.0,
                obj: obj.0,
                rel: rel.0,
            }),
        }),
        condition: t.condition.map(|c| match c {
            Condition::Expires(exp) => pb::tuple::Condition::Expires(exp.timestamp()),
        }),
    }
}

/// Maps a wire `pb::Tuple` to the client model. Missing `user` is a contract
/// violation — fail the call instead of panicking (NIO-003 / paper §2.4.2).
#[allow(clippy::result_large_err)] // ReadError embeds tonic::Status by design
fn tuple_from_pb(tup: pb::Tuple) -> Result<Tuple, ReadError> {
    let sbj = match tup.user {
        None => {
            return Err(ReadError::invalid_response(format!(
                "tuple {}:{}#{} missing user field",
                tup.ns, tup.obj, tup.rel
            )));
        }
        Some(pb::tuple::User::UserId(userid)) => User::UserId(userid),
        Some(pb::tuple::User::UserSet(pb::UserSet { ns, obj, rel })) => User::UserSet {
            ns: Namespace(ns),
            obj: Obj(obj),
            rel: Rel(rel),
        },
    };
    let condition = match tup.condition {
        None => None,
        Some(pb::tuple::Condition::Expires(secs)) => match DateTime::from_timestamp(secs, 0) {
            Some(dt) => Some(Condition::Expires(dt)),
            None => {
                return Err(ReadError::invalid_response(format!(
                    "tuple {}:{}#{} expires out of range: {}",
                    tup.ns, tup.obj, tup.rel, secs
                )));
            }
        },
    };
    Ok(Tuple {
        ns: Namespace(tup.ns),
        obj: Obj(tup.obj),
        rel: Rel(tup.rel),
        sbj,
        condition,
    })
}

#[allow(clippy::result_large_err)] // ReadError embeds tonic::Status by design
fn watch_event_from_pb(resp: pb::WatchResponse) -> Result<WatchEvent, ReadError> {
    let mut updates = Vec::with_capacity(resp.updates.len());
    for (i, u) in resp.updates.into_iter().enumerate() {
        let tuple = match u.tuple {
            None => {
                return Err(ReadError::invalid_response(format!(
                    "watch update[{i}]: missing tuple"
                )));
            }
            Some(t) => tuple_from_pb(t)?,
        };
        updates.push(WatchUpdate {
            tuple,
            deleted: u.deleted,
        });
    }
    Ok(WatchEvent {
        ts: Timestamp(resp.ts),
        updates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_empty_is_packed_empty_zookie() {
        assert_eq!(Timestamp::empty().0, "AQAAAAAAAA==");
        assert_eq!(Timestamp::EMPTY, "AQAAAAAAAA==");
    }

    // Pins the keepalive contract to nio check_client (#239) — mirror of
    // nioclient-go's TestClientKeepaliveMatchesNio.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn keepalive_matches_nio_check_client() {
        assert_eq!(KEEPALIVE_INTERVAL, Duration::from_secs(30));
        assert_eq!(KEEPALIVE_TIMEOUT, Duration::from_secs(10));
        assert!(KEEPALIVE_WHILE_IDLE);
    }

    // Domain constants must stay byte-identical to nio/domain (and check
    // bootstrap) — mirror of nioclient-go's TestDomainConstantsMatchNio.
    #[test]
    fn domain_constants_match_nio() {
        assert_eq!(Namespace::iam().0, "iam");
        assert_eq!(Namespace::serviceaccount().0, "serviceaccount");
        assert_eq!(Obj::root().0, "root");
        assert_eq!(Obj::unspecified().0, "...");
        assert_eq!(Rel::is().0, "is");
        assert_eq!(Rel::unspecified().0, "...");
        assert_eq!(Rel::parent().0, "parent");
        assert_eq!(Rel::admin().0, "admin");
        assert_eq!(Rel::editor().0, "editor");
        assert_eq!(Rel::viewer().0, "viewer");
        assert_eq!(Rel::iam_get().0, "iam.get");
        assert_eq!(Rel::iam_update().0, "iam.update");
        assert_eq!(Rel::iam_delete().0, "iam.delete");
        assert_eq!(Rel::serviceaccount_get().0, "serviceaccount.get");
        assert_eq!(Rel::serviceaccount_create().0, "serviceaccount.create");
        assert_eq!(Rel::serviceaccount_update().0, "serviceaccount.update");
        assert_eq!(
            Rel::serviceaccount_create_token().0,
            "serviceaccount.createToken"
        );
        assert_eq!(
            Rel::serviceaccount_key_create().0,
            "serviceaccount.key.create"
        );
        assert_eq!(Rel::serviceaccount_key_get().0, "serviceaccount.key.get");
        assert_eq!(Rel::user_create().0, "user.create");
        assert_eq!(UserId::all_users().0, "allUsers");
        assert_eq!(UserId::authenticated_users().0, "authenticatedUsers");
    }

    #[test]
    fn tuple_to_pb_user_id() {
        let pt = tuple_to_pb(Tuple::new(
            Namespace("doc".into()),
            Obj("1".into()),
            Rel("viewer".into()),
            User::UserId("u1".into()),
        ));
        assert_eq!(pt.ns, "doc");
        assert_eq!(pt.obj, "1");
        assert_eq!(pt.rel, "viewer");
        assert!(matches!(pt.user, Some(pb::tuple::User::UserId(ref u)) if u == "u1"));
        assert!(pt.condition.is_none());
    }

    #[test]
    fn tuple_to_pb_user_set() {
        let pt = tuple_to_pb(Tuple::new(
            Namespace("doc".into()),
            Obj("1".into()),
            Rel("viewer".into()),
            User::UserSet {
                ns: Namespace("group".into()),
                obj: Obj("eng".into()),
                rel: Rel("member".into()),
            },
        ));
        match pt.user {
            Some(pb::tuple::User::UserSet(us)) => {
                assert_eq!(us.ns, "group");
                assert_eq!(us.obj, "eng");
                assert_eq!(us.rel, "member");
            }
            other => panic!("expected userset, got {other:?}"),
        }
    }

    #[test]
    fn tuple_to_pb_expires() {
        let exp = DateTime::from_timestamp(1894785600, 0).unwrap();
        let pt = tuple_to_pb(
            Tuple::new(
                Namespace("doc".into()),
                Obj("1".into()),
                Rel("viewer".into()),
                User::UserId("u1".into()),
            )
            .with_expires(exp),
        );
        assert!(matches!(
            pt.condition,
            Some(pb::tuple::Condition::Expires(1894785600))
        ));
    }

    #[test]
    fn tuple_from_pb_maps_user_id_and_userset() {
        let with_id = pb::Tuple {
            ns: "coll".into(),
            obj: "uk".into(),
            rel: "owner".into(),
            user: Some(pb::tuple::User::UserId("user-1".into())),
            condition: None,
        };
        let t = tuple_from_pb(with_id).expect("userid tuple");
        assert_eq!(t.ns.0, "coll");
        assert_eq!(t.obj.0, "uk");
        assert_eq!(t.rel.0, "owner");
        assert!(matches!(t.sbj, User::UserId(ref s) if s == "user-1"));

        let with_set = pb::Tuple {
            ns: "coll".into(),
            obj: "uk".into(),
            rel: "viewer".into(),
            user: Some(pb::tuple::User::UserSet(pb::UserSet {
                ns: "grp".into(),
                obj: "eng".into(),
                rel: "member".into(),
            })),
            condition: None,
        };
        let t = tuple_from_pb(with_set).expect("userset tuple");
        assert!(matches!(
            t.sbj,
            User::UserSet { ref ns, ref obj, ref rel }
                if ns.0 == "grp" && obj.0 == "eng" && rel.0 == "member"
        ));
    }

    #[test]
    fn tuple_from_pb_missing_user_is_invalid_response_not_panic() {
        let bare = pb::Tuple {
            ns: "coll".into(),
            obj: "uk".into(),
            rel: "owner".into(),
            user: None,
            condition: None,
        };
        let err = tuple_from_pb(bare).expect_err("missing user must fail");
        match err {
            ReadError::InvalidResponse(msg) => {
                assert!(msg.contains("missing user"), "msg={msg}");
                assert!(msg.contains("coll"));
            }
            ReadError::Grpc(_) => panic!("expected InvalidResponse, got Grpc"),
        }
    }

    #[test]
    fn tuple_round_trip_expires() {
        let exp = DateTime::from_timestamp(1894785600, 0).unwrap();
        let t = Tuple::new(
            Namespace("doc".into()),
            Obj("1".into()),
            Rel("viewer".into()),
            User::UserId("u1".into()),
        )
        .with_expires(exp);
        let back = tuple_from_pb(tuple_to_pb(t)).expect("round trip");
        match back.condition {
            Some(Condition::Expires(dt)) => assert_eq!(dt, exp),
            None => panic!("expected expires condition"),
        }
    }

    #[test]
    fn filter_by_object() {
        let f = ReadFilter::by_object(Namespace("doc".into()), Obj("1".into()), None);
        assert_eq!(f.set.ns, "doc");
        match f.set.spec {
            Some(pb::tuple_set::Spec::ObjectSpec(ref os)) => {
                assert_eq!(os.obj, "1");
                assert!(os.rel.is_none());
            }
            ref other => panic!("expected object spec, got {other:?}"),
        }

        let f = ReadFilter::by_object(
            Namespace("doc".into()),
            Obj("1".into()),
            Some(Rel::viewer()),
        );
        match f.set.spec {
            Some(pb::tuple_set::Spec::ObjectSpec(ref os)) => {
                assert_eq!(os.rel.as_deref(), Some("viewer"));
            }
            ref other => panic!("expected object spec, got {other:?}"),
        }
    }

    #[test]
    fn filter_by_user() {
        let f = ReadFilter::by_user(Namespace("doc".into()), UserId("u1".into()), None);
        assert_eq!(f.set.ns, "doc");
        match f.set.spec {
            Some(pb::tuple_set::Spec::UsersetSpec(ref us)) => {
                assert!(matches!(
                    us.user,
                    Some(pb::tuple_set::user_set_spec::User::UserId(ref u)) if u == "u1"
                ));
                assert!(us.rel.is_none());
            }
            ref other => panic!("expected userset spec, got {other:?}"),
        }

        let f = ReadFilter::by_user(
            Namespace("doc".into()),
            UserId("u1".into()),
            Some(Rel::editor()),
        );
        match f.set.spec {
            Some(pb::tuple_set::Spec::UsersetSpec(ref us)) => {
                assert_eq!(us.rel.as_deref(), Some("editor"));
            }
            ref other => panic!("expected userset spec, got {other:?}"),
        }
    }

    #[test]
    fn filter_by_user_set() {
        let f = ReadFilter::by_user_set(
            Namespace("doc".into()),
            UserSet {
                ns: Namespace("grp".into()),
                obj: Obj("eng".into()),
                rel: Rel("member".into()),
            },
            None,
        );
        match f.set.spec {
            Some(pb::tuple_set::Spec::UsersetSpec(ref us)) => match us.user {
                Some(pb::tuple_set::user_set_spec::User::UserSet(ref set)) => {
                    assert_eq!(set.ns, "grp");
                    assert_eq!(set.obj, "eng");
                    assert_eq!(set.rel, "member");
                }
                ref other => panic!("expected userset subject, got {other:?}"),
            },
            ref other => panic!("expected userset spec, got {other:?}"),
        }
    }

    #[test]
    fn watch_event_from_pb_heartbeat() {
        let ev = watch_event_from_pb(pb::WatchResponse {
            ts: "AQAAAAAAAA==".into(),
            updates: vec![],
        })
        .expect("heartbeat");
        assert_eq!(ev.ts, Timestamp::empty());
        assert!(ev.updates.is_empty());
    }

    #[test]
    fn watch_event_from_pb_atomic_write() {
        let ev = watch_event_from_pb(pb::WatchResponse {
            ts: "commit-ts".into(),
            updates: vec![
                pb::Update {
                    tuple: Some(pb::Tuple {
                        ns: "doc".into(),
                        obj: "1".into(),
                        rel: "viewer".into(),
                        user: Some(pb::tuple::User::UserId("u1".into())),
                        condition: None,
                    }),
                    deleted: false,
                },
                pb::Update {
                    tuple: Some(pb::Tuple {
                        ns: "doc".into(),
                        obj: "1".into(),
                        rel: "editor".into(),
                        user: Some(pb::tuple::User::UserId("u1".into())),
                        condition: None,
                    }),
                    deleted: true,
                },
            ],
        })
        .expect("atomic write");
        assert_eq!(ev.ts.0, "commit-ts");
        assert_eq!(ev.updates.len(), 2);
        assert!(!ev.updates[0].deleted);
        assert!(matches!(ev.updates[0].tuple.sbj, User::UserId(ref u) if u == "u1"));
        assert!(ev.updates[1].deleted);
        assert_eq!(ev.updates[1].tuple.rel.0, "editor");
    }

    #[test]
    fn watch_event_from_pb_missing_tuple_user() {
        let err = watch_event_from_pb(pb::WatchResponse {
            ts: "t".into(),
            updates: vec![pb::Update {
                tuple: Some(pb::Tuple {
                    ns: "doc".into(),
                    obj: "1".into(),
                    rel: "viewer".into(),
                    user: None,
                    condition: None,
                }),
                deleted: false,
            }],
        })
        .expect_err("missing user must fail");
        assert!(matches!(err, ReadError::InvalidResponse(_)));
    }

    #[test]
    fn watch_event_from_pb_missing_tuple() {
        let err = watch_event_from_pb(pb::WatchResponse {
            ts: "t".into(),
            updates: vec![pb::Update {
                tuple: None,
                deleted: false,
            }],
        })
        .expect_err("missing tuple must fail");
        assert!(matches!(err, ReadError::InvalidResponse(_)));
    }
}
