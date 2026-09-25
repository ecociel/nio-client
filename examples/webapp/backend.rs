//! A tiny in-process stand-in for a real nio deployment.
//!
//! It serves the two gRPC services the axum extractors talk to:
//!
//! * `am.SessionService` — turns an opaque session **token hash** into a
//!   principal (session resolution).
//! * `am.CheckService` — answers "may this principal exercise this relation on
//!   this object?" (the access check) against a fixed set of relationship
//!   tuples.
//!
//! In a real system these are two separate nio processes and their data lives
//! in nio's stores. Here everything is one `Arc<Mutex<..>>` so the example is
//! self-contained and every RPC is logged to the console, letting you watch
//! resolution and checks happen as you click around.
//!
//! The other CheckService RPCs (list/read/write/watch/…) are not exercised by
//! the extractors, so they are left unimplemented.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use http::Uri;
use nio_client::session::token_hash;
use nio_client::wire;
use nio_client::{User, UserId};
use rand::RngCore;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

/// How long an issued demo session stays valid.
const SESSION_TTL_SECONDS: i64 = 3600;

struct Session {
    principal: UserId,
    expires_at_unix: i64,
}

#[derive(PartialEq, Eq, Hash)]
struct Grant {
    ns: String,
    obj: String,
    rel: String,
    subject: User,
}

#[derive(Default)]
struct State {
    /// token hash -> issued session. Written by `create_session` on sign-in.
    sessions: HashMap<String, Session>,
    tuples: HashSet<Grant>,
    names: HashMap<UserId, String>,
}

/// The in-process nio backend. Cloneable: every clone shares one `State`.
#[derive(Clone, Default)]
pub struct Backend {
    state: Arc<Mutex<State>>,
}

impl Backend {
    pub fn new() -> Self {
        Backend::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("backend state poisoned")
    }

    pub fn register_principal(&self, principal: UserId, name: &str) {
        self.lock().names.insert(principal, name.to_string());
    }

    /// Grants `subject` the `rel` relation on `ns:obj` — the equivalent of a
    /// nio `Write` of one relationship tuple.
    pub fn grant(&self, ns: &str, obj: &str, rel: &str, subject: User) {
        self.lock().tuples.insert(Grant {
            ns: ns.to_string(),
            obj: obj.to_string(),
            rel: rel.to_string(),
            subject,
        });
    }

    /// Issues a session for `principal` and returns the raw opaque token. Only
    /// the token's hash is stored — the raw token exists solely to be handed to
    /// the browser (cookie) or an API client (bearer). This models a session
    /// that nio's session service would create after your app authenticates a
    /// user.
    pub fn create_session(&self, principal: UserId) -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let raw = hex::encode(bytes);
        let expires_at_unix = now_unix() + SESSION_TTL_SECONDS;
        self.lock().sessions.insert(
            token_hash(&raw),
            Session {
                principal,
                expires_at_unix,
            },
        );
        raw
    }

    /// Drops a session by its token hash (sign-out / revoke).
    pub fn remove_session(&self, hash: &str) {
        self.lock().sessions.remove(hash);
    }

    /// Binds an ephemeral loopback port, starts the gRPC server on it, and
    /// returns the URI both clients should dial. Check and session share one
    /// endpoint here; in production they are distinct.
    pub async fn serve(self) -> Uri {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind nio backend");
        let addr = listener.local_addr().expect("backend addr");
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(wire::check_service_server::CheckServiceServer::new(
                    self.clone(),
                ))
                .add_service(wire::session_service_server::SessionServiceServer::new(
                    self,
                ))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .expect("nio backend server");
        });
        format!("http://{addr}").parse().expect("backend uri")
    }
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

fn short(hash: &str) -> &str {
    &hash[..hash.len().min(8)]
}

#[tonic::async_trait]
impl wire::session_service_server::SessionService for Backend {
    async fn resolve(
        &self,
        request: Request<wire::ResolveRequest>,
    ) -> Result<Response<wire::ResolveResponse>, Status> {
        let hash = request.into_inner().token_hash;
        let state = self.lock();
        let outcome = match state.sessions.get(&hash) {
            Some(s) if s.expires_at_unix > now_unix() => {
                let name = state.names.get(&s.principal).cloned().unwrap_or_default();
                println!(
                    "[nio session] resolve({}…) -> {} ({name})",
                    short(&hash),
                    s.principal
                );
                wire::resolve_response::Outcome::Session(wire::Session {
                    principal: s.principal.get(),
                    tenant_id: "demo".into(),
                    expires_at_unix_seconds: s.expires_at_unix,
                })
            }
            _ => {
                // Unknown, expired, or revoked — deliberately indistinguishable.
                println!("[nio session] resolve({}…) -> NOT FOUND", short(&hash));
                wire::resolve_response::Outcome::NotFound(wire::NotFound {})
            }
        };
        Ok(Response::new(wire::ResolveResponse {
            outcome: Some(outcome),
        }))
    }
}

#[tonic::async_trait]
impl wire::check_service_server::CheckService for Backend {
    async fn check(
        &self,
        request: Request<wire::CheckRequest>,
    ) -> Result<Response<wire::CheckResponse>, Status> {
        let req = request.into_inner();
        let Some(wire::check_request::User::UserId(id)) = req.user else {
            return Err(Status::invalid_argument(
                "the demo only checks userId subjects",
            ));
        };
        let user_id = UserId::try_from(id).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let state = self.lock();

        let key = |subject: User| Grant {
            ns: req.ns.clone(),
            obj: req.obj.clone(),
            rel: req.rel.clone(),
            subject,
        };
        let granted = state.tuples.contains(&key(user_id.into()));
        let public = state.tuples.contains(&key(User::AllUsers));
        let allowed = granted || public;
        let verdict = if allowed { "ALLOW" } else { "DENY" };

        let name = state
            .names
            .get(&user_id)
            .cloned()
            .unwrap_or_else(|| "?".into());
        println!(
            "[nio check]   {}:{}#{} @ {} ({name}) -> {verdict}",
            req.ns, req.obj, req.rel, user_id
        );

        Ok(Response::new(wire::CheckResponse {
            principal: Some(wire::Principal { id: user_id.get() }),
            ok: allowed,
        }))
    }

    async fn content_change_check(
        &self,
        _request: Request<wire::ContentChangeCheckRequest>,
    ) -> Result<Response<wire::ContentChangeCheckResponse>, Status> {
        Err(Status::unimplemented("not used in the webapp example"))
    }

    async fn list(
        &self,
        _request: Request<wire::ListRequest>,
    ) -> Result<Response<wire::ListResponse>, Status> {
        Err(Status::unimplemented("not used in the webapp example"))
    }

    async fn expand(
        &self,
        _request: Request<wire::ExpandRequest>,
    ) -> Result<Response<wire::ExpandResponse>, Status> {
        Err(Status::unimplemented("not used in the webapp example"))
    }

    async fn read(
        &self,
        _request: Request<wire::ReadRequest>,
    ) -> Result<Response<wire::ReadResponse>, Status> {
        Err(Status::unimplemented("not used in the webapp example"))
    }

    async fn write(
        &self,
        _request: Request<wire::WriteRequest>,
    ) -> Result<Response<wire::WriteResponse>, Status> {
        Err(Status::unimplemented("not used in the webapp example"))
    }

    type WatchStream = futures::stream::Empty<Result<wire::WatchResponse, Status>>;

    async fn watch(
        &self,
        _request: Request<wire::WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        Err(Status::unimplemented("not used in the webapp example"))
    }
}
