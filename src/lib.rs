use std::fmt::{Display, Formatter};
use std::num::NonZeroI64;
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

/// UserId is a principal's ID: a positive 64-bit integer (nio #301).
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct UserId(NonZeroI64);

impl UserId {
    pub fn get(self) -> i64 {
        self.0.get()
    }
}

impl TryFrom<i64> for UserId {
    type Error = ParseError;

    fn try_from(n: i64) -> Result<Self, Self::Error> {
        match NonZeroI64::new(n) {
            Some(nz) if n > 0 => Ok(UserId(nz)),
            _ => Err(ParseError::invalid_syntax(
                "UserId",
                n.to_string(),
                "must be a positive 64-bit integer",
            )),
        }
    }
}

impl FromStr for UserId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decimal = !s.is_empty()
            && s.len() <= 19
            && !s.starts_with('0')
            && s.bytes().all(|b| b.is_ascii_digit());
        if !decimal {
            return Err(ParseError::invalid_syntax(
                "UserId",
                s,
                "must be a decimal integer from 1 to 9223372036854775807",
            ));
        }
        let n: i64 = s
            .parse()
            .map_err(|_| ParseError::invalid_syntax("UserId", s, "exceeds 9223372036854775807"))?;
        UserId::try_from(n)
    }
}

impl TryFrom<String> for UserId {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        UserId::from_str(&value)
    }
}

impl Display for UserId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
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

/// The subject of a tuple: one principal, a public wildcard, or a userset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum User {
    UserId(UserId),
    AllUsers,
    AuthenticatedUsers,
    UserSet { ns: Namespace, obj: Obj, rel: Rel },
}

impl User {
    pub const ALL_USERS: &'static str = "allUsers";
    pub const AUTHENTICATED_USERS: &'static str = "authenticatedUsers";

    fn from_id_str(s: &str) -> Result<User, ParseError> {
        match s {
            Self::ALL_USERS => Ok(User::AllUsers),
            Self::AUTHENTICATED_USERS => Ok(User::AuthenticatedUsers),
            _ => Ok(User::UserId(UserId::from_str(s)?)),
        }
    }
}

impl FromStr for User {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((ns_obj, rel)) = s.split_once('#') else {
            return User::from_id_str(s);
        };
        let Some((ns, obj)) = ns_obj.split_once(':') else {
            return Err(ParseError::invalid_syntax(
                "User::UserSet",
                s,
                "wrong pattern for userset: missing ':' delimiter",
            ));
        };
        Ok(User::UserSet {
            ns: Namespace(ns.into()),
            obj: Obj(obj.into()),
            rel: Rel(rel.into()),
        })
    }
}

impl Display for User {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            User::UserId(id) => write!(f, "{id}"),
            User::AllUsers => f.write_str(Self::ALL_USERS),
            User::AuthenticatedUsers => f.write_str(Self::AUTHENTICATED_USERS),
            User::UserSet { ns, obj, rel } => write!(f, "{}:{}#{}", ns.0, obj.0, rel.0),
        }
    }
}

impl From<UserId> for User {
    fn from(value: UserId) -> Self {
        User::UserId(value)
    }
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
        write!(
            f,
            "Tuple({}:{}#{}@{})",
            self.ns.0, self.obj.0, self.rel.0, self.sbj
        )
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
/// flattened leaf user ids, whether a public wildcard holds the relation, and
/// the usersets left opaque (e.g. `...` parent pointers or references the
/// server could not resolve).
#[derive(Clone, Debug)]
pub struct ExpandResult {
    pub ts: Timestamp,
    pub user_ids: Vec<UserId>,
    pub all_users: bool,
    pub authenticated_users: bool,
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

    /// Reverse-reads tuples in `ns` whose subject is `user` (paper §2.4.3
    /// UserSetSpec). Answered via the reverse index — raw stored edges, no
    /// rewrite evaluation. `rel` `None` means all relations.
    pub fn by_user(ns: Namespace, user: User, rel: Option<Rel>) -> ReadFilter {
        use pb::tuple_set::user_set_spec::User as Pb;
        ReadFilter {
            set: pb::TupleSet {
                ns: ns.0,
                spec: Some(pb::tuple_set::Spec::UsersetSpec(
                    pb::tuple_set::UserSetSpec {
                        user: Some(user_to_pb(user, Pb::UserId, Pb::UserSet, Pb::Wildcard)),
                        rel: rel.map(|r| r.0),
                    },
                )),
            },
        }
    }

    /// Reverse-reads tuples in `ns` whose subject is the userset. `rel`
    /// `None` means all relations.
    pub fn by_user_set(ns: Namespace, user_set: UserSet, rel: Option<Rel>) -> ReadFilter {
        let user = User::UserSet {
            ns: user_set.ns,
            obj: user_set.obj,
            rel: user_set.rel,
        };
        Self::by_user(ns, user, rel)
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

    /// Calls the check server's Check API: may `user_id` — a principal;
    /// resolve session tokens to a principal client-side first (see
    /// [`crate::session`]) — exercise `rel` on ⟨ns, obj⟩? Evaluated at a
    /// snapshot at least as fresh as `timestamp` (a zookie from an earlier
    /// write/read); `None` accepts any current snapshot. An unknown principal
    /// maps to [`CheckResult::UnknownPutativeUser`], a known-but-unauthorized
    /// user to [`CheckResult::Forbidden`]. [`Rel::IMPOSSIBLE`] short-circuits
    /// to a denial without an RPC.
    pub async fn check(
        &mut self,
        ns: Namespace,
        obj: Obj,
        rel: Rel,
        user_id: UserId,
        timestamp: Option<Timestamp>,
    ) -> Result<CheckResult, CallError> {
        if rel.0 == Rel::IMPOSSIBLE {
            return Ok(CheckResult::Forbidden(user_id.into()));
        }
        let r = pb::CheckRequest {
            ns: ns.0.clone(),
            obj: obj.0.clone(),
            rel: rel.0.clone(),
            user: Some(pb::check_request::User::UserId(user_id.get())),
            ts: timestamp.map(|t| t.0),
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
                let principal = UserId::try_from(id)
                    .map_err(|_| CallError::UnexpectedResponseFormat)?
                    .into();
                match ok {
                    true => Ok(CheckResult::Ok(principal)),
                    false => Ok(CheckResult::Forbidden(principal)),
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
            user: Some(pb::list_request::User::UserId(user_id.get())),
            ts: timestamp.map(|t| t.0),
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
            ts: timestamp.map(|t| t.0),
        };
        let response = self.check.expand(r).await?.into_inner();
        let user_ids = response
            .user_ids
            .into_iter()
            .map(UserId::try_from)
            .collect::<Result<_, _>>()
            .map_err(|e| ReadError::invalid_response(e.to_string()))?;
        let mut all_users = false;
        let mut authenticated_users = false;
        for w in response.wildcards {
            match wildcard_from_pb(w)? {
                Wildcard::AllUsers => all_users = true,
                Wildcard::AuthenticatedUsers => authenticated_users = true,
            }
        }
        Ok(ExpandResult {
            ts: Timestamp(response.ts),
            user_ids,
            all_users,
            authenticated_users,
            usersets: response
                .usersets
                .into_iter()
                .map(|us| UserSet {
                    ns: Namespace(us.ns),
                    obj: Obj(us.obj),
                    rel: Rel(us.rel),
                })
                .collect(),
        })
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
            user: Some(pb::content_change_check_request::User::UserId(
                user_id.get(),
            )),
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

    /// Reverse-reads tuples in `ns` whose subject is `user`. `rel` `None`
    /// means all relations. Answered via the reverse index — no rewrites.
    pub async fn read_by_user(
        &mut self,
        ns: &Namespace,
        user: &User,
        rel: Option<Rel>,
    ) -> Result<ReadResult, ReadError> {
        self.read(vec![ReadFilter::by_user(ns.clone(), user.clone(), rel)])
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

/// Encodes a subject into one of the generated `oneof user` enums, which
/// share the three variant shapes but are distinct types.
fn user_to_pb<T>(
    user: User,
    user_id: fn(i64) -> T,
    user_set: fn(pb::UserSet) -> T,
    wildcard: fn(i32) -> T,
) -> T {
    match user {
        User::UserId(id) => user_id(id.get()),
        User::AllUsers => wildcard(pb::Wildcard::AllUsers.into()),
        User::AuthenticatedUsers => wildcard(pb::Wildcard::AuthenticatedUsers.into()),
        User::UserSet { ns, obj, rel } => user_set(pb::UserSet {
            ns: ns.0,
            obj: obj.0,
            rel: rel.0,
        }),
    }
}

enum Wildcard {
    AllUsers,
    AuthenticatedUsers,
}

#[allow(clippy::result_large_err)]
fn wildcard_from_pb(w: i32) -> Result<Wildcard, ReadError> {
    match pb::Wildcard::try_from(w) {
        Ok(pb::Wildcard::AllUsers) => Ok(Wildcard::AllUsers),
        Ok(pb::Wildcard::AuthenticatedUsers) => Ok(Wildcard::AuthenticatedUsers),
        Ok(pb::Wildcard::Unspecified) | Err(_) => {
            Err(ReadError::invalid_response(format!("unknown wildcard {w}")))
        }
    }
}

#[allow(clippy::result_large_err)]
fn user_from_pb(user: pb::tuple::User) -> Result<User, ReadError> {
    match user {
        pb::tuple::User::UserId(id) => UserId::try_from(id)
            .map(User::UserId)
            .map_err(|e| ReadError::invalid_response(e.to_string())),
        pb::tuple::User::Wildcard(w) => Ok(match wildcard_from_pb(w)? {
            Wildcard::AllUsers => User::AllUsers,
            Wildcard::AuthenticatedUsers => User::AuthenticatedUsers,
        }),
        pb::tuple::User::UserSet(pb::UserSet { ns, obj, rel }) => Ok(User::UserSet {
            ns: Namespace(ns),
            obj: Obj(obj),
            rel: Rel(rel),
        }),
    }
}

fn tuple_to_pb(t: Tuple) -> pb::Tuple {
    use pb::tuple::User as Pb;
    pb::Tuple {
        ns: t.ns.0,
        obj: t.obj.0,
        rel: t.rel.0,
        user: Some(user_to_pb(t.sbj, Pb::UserId, Pb::UserSet, Pb::Wildcard)),
        condition: t.condition.map(|c| match c {
            Condition::Expires(exp) => pb::tuple::Condition::Expires(exp.timestamp()),
        }),
    }
}

/// Maps a wire `pb::Tuple` to the client model. Missing `user` is a contract
/// violation — fail the call instead of panicking (NIO-003 / paper §2.4.2).
#[allow(clippy::result_large_err)] // ReadError embeds tonic::Status by design
fn tuple_from_pb(tup: pb::Tuple) -> Result<Tuple, ReadError> {
    let Some(user) = tup.user else {
        return Err(ReadError::invalid_response(format!(
            "tuple {}:{}#{} missing user field",
            tup.ns, tup.obj, tup.rel
        )));
    };
    let sbj = user_from_pb(user)?;
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

    fn uid(n: i64) -> UserId {
        UserId::try_from(n).unwrap()
    }

    fn tuple_with(user: pb::tuple::User) -> pb::Tuple {
        pb::Tuple {
            ns: "doc".into(),
            obj: "1".into(),
            rel: "viewer".into(),
            user: Some(user),
            condition: None,
        }
    }

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
        assert_eq!(User::AllUsers.to_string(), "allUsers");
        assert_eq!(User::AuthenticatedUsers.to_string(), "authenticatedUsers");
    }

    #[test]
    fn user_id_accepts_max_i64() {
        let id = UserId::from_str("9223372036854775807").unwrap();
        assert_eq!(id.get(), 9223372036854775807);
        assert_eq!(id.to_string(), "9223372036854775807");
        assert_eq!(UserId::try_from("42".to_string()).unwrap().get(), 42);
    }

    #[test]
    fn user_id_rejects_non_canonical_decimals() {
        let not_decimal =
            "invalid syntax: 'must be a decimal integer from 1 to 9223372036854775807'";
        let error_of = |s: &str| UserId::from_str(s).unwrap_err().to_string();
        assert_eq!(
            error_of("0"),
            format!("'0' has invalid syntax for UserId {not_decimal}")
        );
        assert_eq!(
            error_of("-5"),
            format!("'-5' has invalid syntax for UserId {not_decimal}")
        );
        assert_eq!(
            error_of("01"),
            format!("'01' has invalid syntax for UserId {not_decimal}")
        );
        assert_eq!(
            error_of("9223372036854775808"),
            "'9223372036854775808' has invalid syntax for UserId invalid syntax: 'exceeds 9223372036854775807'"
        );
        let uuid = ["812eebc6", "480b", "4527", "bed4", "057e4d2fd1e3"].join("-");
        assert_eq!(
            error_of(&uuid),
            format!("'{uuid}' has invalid syntax for UserId {not_decimal}")
        );
    }

    #[test]
    fn user_id_try_from_i64_rejects_non_positive() {
        let positive = "invalid syntax: 'must be a positive 64-bit integer'";
        assert_eq!(
            UserId::try_from(0).unwrap_err().to_string(),
            format!("'0' has invalid syntax for UserId {positive}")
        );
        assert_eq!(
            UserId::try_from(-5).unwrap_err().to_string(),
            format!("'-5' has invalid syntax for UserId {positive}")
        );
    }

    #[test]
    fn user_parses_and_displays_every_subject_kind() {
        let cases = [
            ("42", User::UserId(uid(42))),
            ("allUsers", User::AllUsers),
            ("authenticatedUsers", User::AuthenticatedUsers),
            (
                "group:eng#member",
                User::UserSet {
                    ns: Namespace("group".into()),
                    obj: Obj("eng".into()),
                    rel: Rel("member".into()),
                },
            ),
        ];
        for (text, user) in cases {
            assert_eq!(User::from_str(text).unwrap(), user);
            assert_eq!(user.to_string(), text);
        }
    }

    #[test]
    fn user_rejects_bad_subjects() {
        assert_eq!(
            User::from_str("group#member").unwrap_err().to_string(),
            "'group#member' has invalid syntax for User::UserSet invalid syntax: 'wrong pattern for userset: missing ':' delimiter'"
        );
        assert!(User::from_str("alice").is_err());
    }

    #[test]
    fn tuple_display_uses_subject_text() {
        let t = Tuple::new(
            Namespace("doc".into()),
            Obj("1".into()),
            Rel("viewer".into()),
            User::AllUsers,
        );
        assert_eq!(t.to_string(), "Tuple(doc:1#viewer@allUsers)");
    }

    #[test]
    fn tuple_to_pb_encodes_each_subject_kind() {
        let encode = |sbj: User| {
            tuple_to_pb(Tuple::new(
                Namespace("doc".into()),
                Obj("1".into()),
                Rel("viewer".into()),
                sbj,
            ))
        };
        let pt = encode(User::UserId(uid(42)));
        assert_eq!(pt.ns, "doc");
        assert_eq!(pt.obj, "1");
        assert_eq!(pt.rel, "viewer");
        assert_eq!(pt.user, Some(pb::tuple::User::UserId(42)));
        assert!(pt.condition.is_none());
        assert_eq!(
            encode(User::AllUsers).user,
            Some(pb::tuple::User::Wildcard(1))
        );
        assert_eq!(
            encode(User::AuthenticatedUsers).user,
            Some(pb::tuple::User::Wildcard(2))
        );
        assert_eq!(
            encode(User::UserSet {
                ns: Namespace("group".into()),
                obj: Obj("eng".into()),
                rel: Rel("member".into()),
            })
            .user,
            Some(pb::tuple::User::UserSet(pb::UserSet {
                ns: "group".into(),
                obj: "eng".into(),
                rel: "member".into(),
            }))
        );
    }

    #[test]
    fn tuple_to_pb_expires() {
        let exp = DateTime::from_timestamp(1894785600, 0).unwrap();
        let pt = tuple_to_pb(
            Tuple::new(
                Namespace("doc".into()),
                Obj("1".into()),
                Rel("viewer".into()),
                User::UserId(uid(1)),
            )
            .with_expires(exp),
        );
        assert_eq!(
            pt.condition,
            Some(pb::tuple::Condition::Expires(1894785600))
        );
    }

    #[test]
    fn tuple_from_pb_maps_each_subject_kind() {
        let t = tuple_from_pb(tuple_with(pb::tuple::User::UserId(42))).unwrap();
        assert_eq!(t.ns.0, "doc");
        assert_eq!(t.obj.0, "1");
        assert_eq!(t.rel.0, "viewer");
        assert_eq!(t.sbj, User::UserId(uid(42)));

        let t = tuple_from_pb(tuple_with(pb::tuple::User::Wildcard(
            pb::Wildcard::AllUsers.into(),
        )))
        .unwrap();
        assert_eq!(t.sbj, User::AllUsers);

        let t = tuple_from_pb(tuple_with(pb::tuple::User::Wildcard(
            pb::Wildcard::AuthenticatedUsers.into(),
        )))
        .unwrap();
        assert_eq!(t.sbj, User::AuthenticatedUsers);

        let t = tuple_from_pb(tuple_with(pb::tuple::User::UserSet(pb::UserSet {
            ns: "grp".into(),
            obj: "eng".into(),
            rel: "member".into(),
        })))
        .unwrap();
        assert_eq!(
            t.sbj,
            User::UserSet {
                ns: Namespace("grp".into()),
                obj: Obj("eng".into()),
                rel: Rel("member".into()),
            }
        );
    }

    #[test]
    fn tuple_from_pb_rejects_unspecified_and_unknown_wildcards() {
        let message = |user| match tuple_from_pb(tuple_with(user)) {
            Err(ReadError::InvalidResponse(msg)) => msg,
            other => panic!("expected InvalidResponse, got {other:?}"),
        };
        assert_eq!(
            message(pb::tuple::User::Wildcard(pb::Wildcard::Unspecified.into())),
            "unknown wildcard 0"
        );
        assert_eq!(
            message(pb::tuple::User::Wildcard(99)),
            "unknown wildcard 99"
        );
        assert_eq!(
            message(pb::tuple::User::UserId(0)),
            "'0' has invalid syntax for UserId invalid syntax: 'must be a positive 64-bit integer'"
        );
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
        match tuple_from_pb(bare) {
            Err(ReadError::InvalidResponse(msg)) => {
                assert_eq!(msg, "tuple coll:uk#owner missing user field")
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn tuple_round_trip_expires() {
        let exp = DateTime::from_timestamp(1894785600, 0).unwrap();
        let t = Tuple::new(
            Namespace("doc".into()),
            Obj("1".into()),
            Rel("viewer".into()),
            User::UserId(uid(1)),
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
        assert_eq!(
            f.set.spec,
            Some(pb::tuple_set::Spec::ObjectSpec(pb::tuple_set::ObjectSpec {
                obj: "1".into(),
                rel: None,
            }))
        );

        let f = ReadFilter::by_object(
            Namespace("doc".into()),
            Obj("1".into()),
            Some(Rel::viewer()),
        );
        assert_eq!(
            f.set.spec,
            Some(pb::tuple_set::Spec::ObjectSpec(pb::tuple_set::ObjectSpec {
                obj: "1".into(),
                rel: Some("viewer".into()),
            }))
        );
    }

    #[test]
    fn filter_by_user() {
        use pb::tuple_set::user_set_spec::User as Pb;
        let spec = |user, rel| {
            ReadFilter::by_user(Namespace("doc".into()), user, rel)
                .set
                .spec
        };
        let expected = |user, rel: Option<&str>| {
            Some(pb::tuple_set::Spec::UsersetSpec(
                pb::tuple_set::UserSetSpec {
                    user: Some(user),
                    rel: rel.map(String::from),
                },
            ))
        };
        assert_eq!(
            spec(User::UserId(uid(42)), None),
            expected(Pb::UserId(42), None)
        );
        assert_eq!(
            spec(User::AuthenticatedUsers, Some(Rel::editor())),
            expected(Pb::Wildcard(2), Some("editor"))
        );
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
        assert_eq!(
            f.set.spec,
            Some(pb::tuple_set::Spec::UsersetSpec(
                pb::tuple_set::UserSetSpec {
                    user: Some(pb::tuple_set::user_set_spec::User::UserSet(pb::UserSet {
                        ns: "grp".into(),
                        obj: "eng".into(),
                        rel: "member".into(),
                    })),
                    rel: None,
                },
            ))
        );
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
        let mut editor = tuple_with(pb::tuple::User::UserId(7));
        editor.rel = "editor".into();
        let ev = watch_event_from_pb(pb::WatchResponse {
            ts: "commit-ts".into(),
            updates: vec![
                pb::Update {
                    tuple: Some(tuple_with(pb::tuple::User::UserId(7))),
                    deleted: false,
                },
                pb::Update {
                    tuple: Some(editor),
                    deleted: true,
                },
            ],
        })
        .expect("atomic write");
        assert_eq!(ev.ts.0, "commit-ts");
        assert_eq!(ev.updates.len(), 2);
        assert!(!ev.updates[0].deleted);
        assert_eq!(ev.updates[0].tuple.sbj, User::UserId(uid(7)));
        assert!(ev.updates[1].deleted);
        assert_eq!(ev.updates[1].tuple.rel.0, "editor");
    }

    #[test]
    fn watch_event_from_pb_missing_tuple_user() {
        let mut bare = tuple_with(pb::tuple::User::UserId(7));
        bare.user = None;
        let err = watch_event_from_pb(pb::WatchResponse {
            ts: "t".into(),
            updates: vec![pb::Update {
                tuple: Some(bare),
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
