use crate::auth::{CheckResult, Principal};
use crate::session::SessionResolver;
use crate::UserId;
use crate::{CheckClient, Namespace, Obj, Rel};
use axum::extract::FromRef;
use axum::http::header::{CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{extract::FromRequestParts, http::request::Parts};
use headers::authorization::Bearer;
use headers::{Authorization, Cookie, HeaderMapExt};
use std::error::Error;
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
#[error("Web resource error")]
pub enum WebResourceError {
    /// No bearer token, a malformed `Authorization` header, or an unknown,
    /// expired or revoked token. Answered with 401, `WWW-Authenticate: Bearer`
    /// and an RFC 9457 problem body.
    Unauthorized,
    /// No session cookie, or an unknown, expired or revoked one. Answered with
    /// 303 to the sign-in location (`{prefix}/signin?back={original-uri}`).
    SigninRedirect(String),
    Forbidden,
    MethodNotAllowed,
    InternalServerError(Box<dyn Error + 'static>),
    Parse(Box<dyn Error + 'static>),
}

impl IntoResponse for WebResourceError {
    fn into_response(self) -> Response {
        match self {
            WebResourceError::Unauthorized => unauthorized(),
            WebResourceError::SigninRedirect(loc) => Redirect::to(loc.as_str()).into_response(),
            WebResourceError::Forbidden => StatusCode::FORBIDDEN.into_response(),
            WebResourceError::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED.into_response(),
            WebResourceError::InternalServerError(err) => {
                log::error!("web resource internal error: {err}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            WebResourceError::Parse(_) => StatusCode::BAD_REQUEST.into_response(),
        }
    }
}

const UNAUTHORIZED_PROBLEM: &str = r#"{"type":"about:blank","status":401,"title":"Unauthorized","detail":"the request carried no bearer token, or the token is not valid"}"#;

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (WWW_AUTHENTICATE, "Bearer"),
            (CONTENT_TYPE, "application/problem+json"),
        ],
        UNAUTHORIZED_PROBLEM,
    )
        .into_response()
}

pub struct SessionCookieAuth;
pub struct BearerTokenAuth;

/// Outcome of turning a raw session token into the subject passed to `check`.
enum Subject {
    /// Resolved — send this principal `UserId` to `check`.
    Principal(UserId),
    /// Token unknown / expired / revoked. Zero `check` RPCs.
    NotFound,
    /// Backend/transport fault while resolving.
    Error(WebResourceError),
}

/// Turn a raw token into a `check` subject: hash it in-process and resolve it
/// to a principal via the [`SessionResolver`] (the raw token never
/// reaches `check` — #243). `not_found` yields zero `check` RPCs; a
/// backend/transport fault is surfaced as an internal error.
async fn resolve_subject(resolver: &Arc<dyn SessionResolver>, token: &str) -> Subject {
    let hash = crate::session::token_hash(token);
    match resolver.resolve(&hash).await {
        Ok(Some(session)) => Subject::Principal(session.principal),
        Ok(None) => Subject::NotFound,
        Err(err) => {
            log::error!("nio-client: session resolve failed: {err}");
            Subject::Error(WebResourceError::InternalServerError(Box::new(err)))
        }
    }
}

/// Percent-encodes a query component (RFC 3986 unreserved characters pass
/// through).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub trait WebResource: Sized {
    type Rejection: IntoResponse + Error;

    fn namespace(&self) -> Namespace;
    fn rel(&self, method: &Method) -> Option<Rel>;
    fn parse<S: Send + Sync>(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send;
    fn object(&self) -> Obj;
}

pub struct WithPrincipal<R, A = SessionCookieAuth> {
    pub principal: Principal,
    pub resource: R,
    auth_type: PhantomData<A>,
}

impl<R, A> WithPrincipal<R, A> {
    pub fn into_principal(self) -> Principal {
        self.principal
    }

    pub fn into_resource(self) -> R {
        self.resource
    }

    pub fn into_principal_and_resource(self) -> (Principal, R) {
        (self.principal, self.resource)
    }

    pub fn map<T>(self, f: impl Fn(R) -> T) -> WithPrincipal<T, A> {
        let resource = f(self.resource);
        WithPrincipal {
            principal: self.principal,
            resource,
            auth_type: PhantomData,
        }
    }
}

impl<S, R> FromRequestParts<S> for WithPrincipal<R, SessionCookieAuth>
where
    R: WebResource + Send + 'static,
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = WebResourceError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        {
            let auth_state = AuthState::from_ref(state);

            let resource = R::parse(parts, state)
                .await
                .map_err(|err| WebResourceError::Parse(Box::new(err)))?;

            let token = match parts
                .headers
                .typed_get::<Cookie>()
                .and_then(|c| c.get("session").map(String::from))
            {
                None => {
                    return Err(WebResourceError::SigninRedirect(
                        auth_state.signin_location(parts),
                    ))
                }
                Some(token) => token,
            };

            let ns = resource.namespace();
            let obj = resource.object();
            let rel = resource
                .rel(&parts.method)
                .ok_or(WebResourceError::MethodNotAllowed)?;

            let u = match resolve_subject(&auth_state.resolver, &token).await {
                Subject::Principal(u) => u,
                Subject::NotFound => {
                    return Err(WebResourceError::SigninRedirect(
                        auth_state.signin_location(parts),
                    ))
                }
                Subject::Error(err) => return Err(err),
            };

            let mut cc = auth_state.check_client;

            match cc.check(ns, obj, rel, u, None).await {
                Err(err) => {
                    log::error!("nio-client: check returned error: {err:?}");
                    Err(WebResourceError::InternalServerError(Box::new(err)))
                }
                Ok(CheckResult::Ok(principal)) => Ok(WithPrincipal {
                    principal,
                    resource,
                    auth_type: PhantomData,
                }),
                // TODO consider passing along principal even when not authorized
                Ok(CheckResult::Forbidden(_)) => Err(WebResourceError::Forbidden),
            }
        }
    }
}

impl<S, R> FromRequestParts<S> for WithPrincipal<R, BearerTokenAuth>
where
    R: WebResource + Send + 'static,
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = WebResourceError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        {
            let auth_state = AuthState::from_ref(state);

            let resource = R::parse(parts, state)
                .await
                .map_err(|err| WebResourceError::Parse(Box::new(err)))?;

            let bearer = match parts.headers.typed_try_get::<Authorization<Bearer>>() {
                Ok(Some(bearer)) => bearer,
                Ok(None) | Err(_) => return Err(WebResourceError::Unauthorized),
            };

            let ns = resource.namespace();
            let obj = resource.object();
            let rel = resource
                .rel(&parts.method)
                .ok_or(WebResourceError::MethodNotAllowed)?;

            let u = match resolve_subject(&auth_state.resolver, bearer.token()).await {
                Subject::Principal(u) => u,
                Subject::NotFound => return Err(WebResourceError::Unauthorized),
                Subject::Error(err) => return Err(err),
            };

            let mut cc = auth_state.check_client;
            match cc.check(ns, obj, rel, u, None).await {
                Err(err) => Err(WebResourceError::InternalServerError(Box::new(err))),
                Ok(CheckResult::Ok(principal)) => Ok(WithPrincipal {
                    principal,
                    resource,
                    auth_type: PhantomData,
                }),
                Ok(CheckResult::Forbidden(_)) => Err(WebResourceError::Forbidden),
            }
        }
    }
}

/// Authenticates the caller and yields the principal **without** running a
/// check.
///
/// For handlers whose authorization object is not knowable from the request
/// [`Parts`] — e.g. where the object is identified by the request *body*. A
/// [`WebResource`] guard cannot express that, since `parse` never sees the
/// body. Such a handler **must** call [`CheckClient::check`] itself once it
/// knows the object; this extractor only establishes *who* is calling.
pub struct Authenticated<A = BearerTokenAuth> {
    pub principal: UserId,
    auth_type: PhantomData<A>,
}

impl<S> FromRequestParts<S> for Authenticated<BearerTokenAuth>
where
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = WebResourceError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        {
            let auth_state = AuthState::from_ref(state);
            let bearer = match parts.headers.typed_try_get::<Authorization<Bearer>>() {
                Ok(Some(bearer)) => bearer,
                Ok(None) | Err(_) => return Err(WebResourceError::Unauthorized),
            };
            match resolve_subject(&auth_state.resolver, bearer.token()).await {
                Subject::Principal(principal) => Ok(Authenticated {
                    principal,
                    auth_type: PhantomData,
                }),
                Subject::NotFound => Err(WebResourceError::Unauthorized),
                Subject::Error(err) => Err(err),
            }
        }
    }
}

pub struct WithOptPrincipal<R> {
    pub principal: Option<Principal>,
    pub resource: R,
}

impl<S, R> FromRequestParts<S> for WithOptPrincipal<R>
where
    R: WebResource + Send + 'static,
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = WebResourceError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        {
            let auth_state = AuthState::from_ref(state);

            let resource = R::parse(parts, state)
                .await
                .map_err(|err| WebResourceError::Parse(Box::new(err)))?;

            let token = match parts
                .headers
                .typed_get::<Cookie>()
                .and_then(|c| c.get("session").map(String::from))
            {
                None => {
                    return Ok(WithOptPrincipal {
                        principal: None,
                        resource,
                    })
                }
                Some(token) => token,
            };

            let ns = resource.namespace();
            let obj = resource.object();
            let rel = resource
                .rel(&parts.method)
                .ok_or(WebResourceError::MethodNotAllowed)?;

            let u = match resolve_subject(&auth_state.resolver, &token).await {
                Subject::Principal(u) => u,
                Subject::NotFound => {
                    return Ok(WithOptPrincipal {
                        principal: None,
                        resource,
                    })
                }
                Subject::Error(err) => return Err(err),
            };

            let mut cc = auth_state.check_client;
            match cc.check(ns, obj, rel, u, None).await {
                Err(err) => Err(WebResourceError::InternalServerError(Box::new(err))),
                Ok(CheckResult::Ok(principal)) => Ok(WithOptPrincipal {
                    principal: Some(principal),
                    resource,
                }),
                Ok(CheckResult::Forbidden(_)) => Err(WebResourceError::Forbidden),
            }
        }
    }
}

#[derive(Clone)]
pub struct AuthState {
    pub check_client: CheckClient,
    /// Token -> principal resolver over `am.SessionService` (see
    /// [`crate::session::GrpcSessionResolver`]). Required — the raw token is
    /// never sent to `check` (#243).
    pub resolver: Arc<dyn SessionResolver>,
    prefix: String,
}

impl AuthState {
    /// Creates a new AuthState for use with the Axum framework. With a
    /// `prefix` of [`None`] sign-in redirects go to `/signin`, else to
    /// `<prefix>/signin` (a lone "/" is treated as empty). The original
    /// request URI is appended as `?back=`.
    pub fn new(
        check_client: CheckClient,
        resolver: Arc<dyn SessionResolver>,
        prefix: Option<&str>,
    ) -> Self {
        let prefix = match prefix {
            None | Some("/") => "",
            Some(p) => p,
        };
        AuthState {
            check_client,
            resolver,
            prefix: prefix.to_string(),
        }
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    fn signin_location(&self, parts: &Parts) -> String {
        let back = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        format!("{}/signin?back={}", self.prefix, urlencode(back))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{ResolveFuture, ResolvedSession};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[derive(Debug, thiserror::Error)]
    #[error("test parse")]
    struct TestParseError;

    #[derive(Debug, thiserror::Error)]
    #[error("test internal")]
    struct TestInternalError;

    fn status(err: WebResourceError) -> StatusCode {
        err.into_response().status()
    }

    #[test]
    fn web_resource_error_status_mapping() {
        // NIO-015: variants must not all collapse to 404.
        assert_eq!(status(WebResourceError::Forbidden), StatusCode::FORBIDDEN);
        assert_eq!(
            status(WebResourceError::MethodNotAllowed),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            status(WebResourceError::InternalServerError(Box::new(
                TestInternalError
            ))),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            status(WebResourceError::Parse(Box::new(TestParseError))),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn signin_redirect_redirects_to_location() {
        let resp = WebResourceError::SigninRedirect("/app/signin?back=%2Fx".into()).into_response();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp
            .headers()
            .get(axum::http::header::LOCATION)
            .and_then(|v| v.to_str().ok());
        assert_eq!(loc, Some("/app/signin?back=%2Fx"));
    }

    struct NopResolver;
    impl SessionResolver for NopResolver {
        fn resolve<'a>(&'a self, _token_hash: &'a str) -> ResolveFuture<'a> {
            Box::pin(async { Ok(None::<ResolvedSession>) })
        }
        fn evict(&self, _token_hash: &str) {}
    }

    fn parts_for(uri: &str) -> Parts {
        let (parts, _) = axum::http::Request::builder()
            .uri(uri)
            .body(())
            .unwrap()
            .into_parts();
        parts
    }

    fn state_with_prefix(prefix: Option<&str>) -> AuthState {
        // The channel is lazy: no connection is made until an RPC runs.
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        AuthState::new(
            CheckClient::from_channel(channel),
            Arc::new(NopResolver),
            prefix,
        )
    }

    struct TestResource;
    impl WebResource for TestResource {
        type Rejection = std::convert::Infallible;

        fn namespace(&self) -> Namespace {
            Namespace("article".into())
        }

        fn rel(&self, _method: &Method) -> Option<Rel> {
            Some(Rel("article.get".into()))
        }

        async fn parse<S: Send + Sync>(
            _parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            Ok(TestResource)
        }

        fn object(&self) -> Obj {
            Obj("1".into())
        }
    }

    async fn bearer_rejection(authorization: Option<&str>) -> Response {
        let mut builder = axum::http::Request::builder().uri("/api/articles/1");
        if let Some(value) = authorization {
            builder = builder.header(axum::http::header::AUTHORIZATION, value);
        }
        let (mut parts, _) = builder.body(()).unwrap().into_parts();
        let state = state_with_prefix(None);
        match WithPrincipal::<TestResource, BearerTokenAuth>::from_request_parts(&mut parts, &state)
            .await
        {
            Ok(_) => panic!("bearer guard accepted the request"),
            Err(err) => err.into_response(),
        }
    }

    async fn assert_401_problem(resp: Response) {
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.headers().get(WWW_AUTHENTICATE).unwrap(), "Bearer");
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            body,
            r#"{"type":"about:blank","status":401,"title":"Unauthorized","detail":"the request carried no bearer token, or the token is not valid"}"#
        );
    }

    #[tokio::test]
    async fn bearer_missing_is_401_problem() {
        assert_401_problem(bearer_rejection(None).await).await;
    }

    #[tokio::test]
    async fn bearer_unknown_is_401_problem() {
        assert_401_problem(bearer_rejection(Some("Bearer unknown-token")).await).await;
    }

    #[tokio::test]
    async fn bearer_malformed_is_401_problem() {
        assert_401_problem(bearer_rejection(Some("Basic dXNlcjpwYXNz")).await).await;
    }

    #[tokio::test]
    async fn signin_location_without_prefix() {
        let state = state_with_prefix(None);
        let parts = parts_for("/articles/7?q=1");
        assert_eq!(
            state.signin_location(&parts),
            "/signin?back=%2Farticles%2F7%3Fq%3D1"
        );
    }

    #[tokio::test]
    async fn signin_location_with_prefix() {
        let state = state_with_prefix(Some("/app"));
        let parts = parts_for("/articles/7");
        assert_eq!(
            state.signin_location(&parts),
            "/app/signin?back=%2Farticles%2F7"
        );
    }

    #[tokio::test]
    async fn lone_slash_prefix_is_empty() {
        let state = state_with_prefix(Some("/"));
        assert_eq!(state.prefix(), "");
    }

    #[test]
    fn urlencode_escapes_reserved() {
        assert_eq!(urlencode("/a b?c=d&e"), "%2Fa%20b%3Fc%3Dd%26e");
        assert_eq!(urlencode("AZaz09-._~"), "AZaz09-._~");
    }
}
