use crate::auth::{CheckResult, Principal};
use crate::UserId;
use crate::{CheckClient, Namespace, Obj, Permission};
use axum::extract::FromRef;
use axum::http::Method;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{extract::FromRequestParts, http::request::Parts};
use headers::authorization::Bearer;
use headers::{Authorization, Cookie, HeaderMapExt};
use std::error::Error;
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;

#[derive(Debug, thiserror::Error)]
#[error("Web resource error")]
pub enum WebResourceError {
    // TODO need additional error for Bearer Token missing
    MissingSession,
    Forbidden,
    MethodNotAllowed,
    InternalServerError(Box<dyn Error + 'static>),
    Parse(Box<dyn Error + 'static>),
}

impl IntoResponse for WebResourceError {
    fn into_response(self) -> Response {
        dbg!(&self);
        match self {
            WebResourceError::MissingSession => Redirect::to("/signin").into_response(),
            _ => axum::http::StatusCode::NOT_FOUND.into_response(),
            // WebResourceError::Forbidden => {}
            // WebResourceError::MethodNotAllowed => {}
            // WebResourceError::InternalServerError(_) => {}
            // WebResourceError::Parse(_) => {}
        }
    }
}

pub struct SessionCookieAuth;
pub struct BearerTokenAuth;

pub trait WebResource: Sized {
    type Rejection: IntoResponse + Error;

    //fn route() -> &'static str;
    // fn namespace() -> Namespace;
    fn namespace(&self) -> Namespace;
    fn permission(&self, method: &Method) -> Option<Permission>;
    //async fn parse<S>(parts: &mut Parts, state: &S) -> Result<Self, ResourceXError> where AuthState: FromRef<AuthState>;
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

#[allow(dead_code)]
impl<R> WithPrincipal<R> {
    pub fn into_principal(self) -> Principal {
        self.principal
    }

    pub fn into_resource(self) -> R {
        self.resource
    }
    pub fn into_principal_and_resource(self) -> (Principal, R) {
        (self.principal, self.resource)
    }

    pub fn map<T>(self, f: impl Fn(R) -> T) -> WithPrincipal<T> {
        let resource = f(self.resource);
        WithPrincipal {
            principal: self.principal,
            resource,
            auth_type: PhantomData,
        }
    }
}

#[allow(dead_code)]
impl<R> WithPrincipal<R, BearerTokenAuth> {
    pub fn into_principal(self) -> Principal {
        self.principal
    }

    pub fn into_resource(self) -> R {
        self.resource
    }
    pub fn into_principal_and_resource(self) -> (Principal, R) {
        (self.principal, self.resource)
    }

    pub fn map<T>(self, f: impl Fn(R) -> T) -> WithPrincipal<T> {
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

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        async {
            let auth_state = AuthState::from_ref(state);

            let resource = R::parse(parts, state)
                .await
                .map_err(|err| WebResourceError::Parse(Box::new(err)))?;

            match parts.headers.typed_get::<Cookie>() {
                None => Err(WebResourceError::MissingSession),
                Some(c) => match c.get("session") {
                    None => Err(WebResourceError::MissingSession),
                    Some(token) => {
                        let ns = resource.namespace(); //R::namespace();
                        let obj = resource.object();
                        let p = resource
                            .permission(&parts.method)
                            .ok_or(WebResourceError::MethodNotAllowed)?;

                        let u = UserId(token.to_string());

                        let mut cc = auth_state.check_client;

                        println!("Permission check: user={:?}, namespace={:?}, object={:?}, permission={:?}",u,ns,obj,p);

                        match cc.check(ns, obj, p, u, None).await {
                            Err(err) => {
                                log::error!("check_client returned error: {:?}", err);
                                Err(WebResourceError::InternalServerError(Box::new(err)))
                            },
                            Ok(CheckResult::Ok(principal)) => {
                                log::info!("check_client success, principal={:?}", principal);
                                Ok(WithPrincipal {
                                principal,
                                resource,
                                auth_type: PhantomData,
                            })
                            },
                            // TODO consider passing along principal even when not authenticated
                            Ok(CheckResult::Forbidden(principal)) => {
                                log::warn!("check_client forbidden, principal={:?}", principal);
                                Err(WebResourceError::Forbidden)
                            }
                            Ok(CheckResult::UnknownPutativeUser) => {
                                log::warn!("check_client unknown user");
                                Err(WebResourceError::Forbidden)
                            }
                        }
                    }
                },
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

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        async {
            let auth_state = AuthState::from_ref(state);

            let resource = R::parse(parts, state)
                .await
                .map_err(|err| WebResourceError::Parse(Box::new(err)))?;

            // TOD impl proper oauth2 response
            match parts.headers.typed_try_get::<Authorization<Bearer>>() {
                Err(_) => Err(WebResourceError::MissingSession),
                Ok(None) => Err(WebResourceError::MissingSession), // TODO
                Ok(Some(bearer_auth_value)) => {
                    let ns = resource.namespace(); // R::namespace();
                    let obj = resource.object();
                    let p = resource
                        .permission(&parts.method)
                        .ok_or(WebResourceError::MethodNotAllowed)?;

                    let u = UserId(bearer_auth_value.token().to_string());

                    let mut cc = auth_state.check_client;
                    match cc.check(ns, obj, p, u, None).await {
                        Err(err) => Err(WebResourceError::InternalServerError(Box::new(err))),
                        Ok(CheckResult::Ok(principal)) => Ok(WithPrincipal {
                            principal,
                            resource,
                            auth_type: PhantomData,
                        }),
                        // TODO consider passing along principal even when not authenticated
                        Ok(CheckResult::Forbidden(_principal)) => Err(WebResourceError::Forbidden),
                        Ok(CheckResult::UnknownPutativeUser) => Err(WebResourceError::Forbidden),
                    }
                }
            }
        }
    }
}

pub struct WithOptPrincipal<R> {
    pub principal: Option<Principal>,
    pub resource: R,
}

impl<R> WithOptPrincipal<R> {
    // pub fn into_principal(self) -> Option<Principal> {
    //     self.principal
    // }
    //
    // pub fn into_resource(self) -> R {
    //     self.resource
    // }
    //
    // pub fn into_principal_and_resource(self) -> (Option<Principal>, R) {
    //     (self.principal, self.resource)
    // }
    //
    // pub fn map<T>(self, f: impl Fn(R) -> T) -> WithOptPrincipal<T> {
    //     let resource = f(self.resource);
    //     WithOptPrincipal {
    //         principal: self.principal,
    //         resource,
    //     }
    // }
}

impl<S, R> FromRequestParts<S> for WithOptPrincipal<R>
where
    R: WebResource + Send + 'static,
    AuthState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = WebResourceError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        async {
            let auth_state = AuthState::from_ref(state);

            let resource = R::parse(parts, state)
                .await
                .map_err(|err| WebResourceError::Parse(Box::new(err)))?;
            match parts.headers.typed_get::<Cookie>() {
                None => Ok(WithOptPrincipal {
                    principal: None,
                    resource,
                }),
                Some(cookies) => match cookies.get("session") {
                    None => Ok(WithOptPrincipal {
                        principal: None,
                        resource,
                    }),
                    Some(token) => {
                        let ns = resource.namespace(); // R::namespace();
                        let obj = resource.object();
                        let p = resource
                            .permission(&parts.method)
                            .ok_or(WebResourceError::MethodNotAllowed)?;
                        let u = UserId(token.to_string());
                        let mut cc = auth_state.check_client;
                        match cc.check(ns, obj, p, u, None).await {
                            Err(err) => Err(WebResourceError::InternalServerError(Box::new(err))),
                            Ok(CheckResult::Ok(principal)) => Ok(WithOptPrincipal {
                                principal: Some(principal),
                                resource,
                            }),
                            Ok(CheckResult::Forbidden(_)) => Err(WebResourceError::Forbidden),
                            Ok(CheckResult::UnknownPutativeUser) => {
                                Err(WebResourceError::Forbidden)
                            }
                        }
                    }
                },
            }
        }
    }
}

#[derive(Clone)]
pub struct AuthState {
    pub check_client: CheckClient,
}