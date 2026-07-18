//! The relying-party web app: the thing you would actually write.
//!
//! It owns three protected surfaces, one per extractor:
//!
//! * `GET /articles/{id}` — a browser **UI page** guarded by a `session`
//!   cookie ([`WithPrincipal`], the default `SessionCookieAuth`). No/invalid
//!   session redirects to sign-in.
//! * `GET|POST /api/articles/{id}` — a JSON **API** guarded by an
//!   `Authorization: Bearer` token ([`WithPrincipal`] with [`BearerTokenAuth`]).
//! * `GET /public/articles/{id}` — a page that is public but authorizes a
//!   caller who *does* present a session ([`WithOptPrincipal`]).
//!
//! Sign-in itself is ordinary app code: authenticate the user, ask the backend
//! to issue a session, drop the token into a cookie. The interesting nio work —
//! resolving that token to a principal and running the access check — happens
//! inside the extractors, wired up by [`AuthState`].

use axum::extract::rejection::PathRejection;
use axum::extract::{FromRef, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use headers::{Cookie, HeaderMapExt};
use nio_client::axum::{AuthState, BearerTokenAuth, WebResource, WithOptPrincipal, WithPrincipal};
use nio_client::session::token_hash;
use nio_client::{Namespace, Obj, Rel};
use serde::Deserialize;
use serde_json::json;

use crate::backend::Backend;

/// The demo namespace. Relations are `article.get` (read) and `article.update`
/// (write) — plain strings the app and the backend agree on.
pub const NAMESPACE: &str = "article";
const REL_GET: &str = "article.get";
const REL_UPDATE: &str = "article.update";

// Demo principals. In production these are real user UUIDs minted by nio.
const ALICE: &str = "11111111-1111-1111-1111-111111111111";
const BOB: &str = "22222222-2222-2222-2222-222222222222";

/// Seeds the backend with the demo users and the relationship tuples that the
/// checks evaluate against.
///
/// | object    | alice          | bob            | anyone |
/// |-----------|----------------|----------------|--------|
/// | article 1 | get + update   | —              | —      |
/// | article 2 | get            | get + update   | —      |
/// | article 3 | (via allUsers) | (via allUsers) | get    |
pub fn seed(backend: &Backend) {
    backend.register_principal(ALICE, "alice");
    backend.register_principal(BOB, "bob");

    backend.grant(NAMESPACE, "1", REL_GET, ALICE);
    backend.grant(NAMESPACE, "1", REL_UPDATE, ALICE);

    backend.grant(NAMESPACE, "2", REL_GET, BOB);
    backend.grant(NAMESPACE, "2", REL_UPDATE, BOB);
    backend.grant(NAMESPACE, "2", REL_GET, ALICE);

    backend.grant(NAMESPACE, "3", REL_GET, "allUsers");
}

#[derive(Clone)]
pub struct AppState {
    pub auth: AuthState,
    pub backend: Backend,
}

// Hands the nio wiring to the extractors: any handler taking `WithPrincipal`
// etc. pulls the AuthState out of our AppState through this.
impl FromRef<AppState> for AuthState {
    fn from_ref(state: &AppState) -> AuthState {
        state.auth.clone()
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/signin", get(signin_form).post(signin_submit))
        .route("/signout", post(signout))
        .route("/articles/{id}", get(ui_article))
        .route("/public/articles/{id}", get(public_article))
        .route("/api/articles/{id}", get(api_get).post(api_update))
        .with_state(state)
}

/// An article addressed by its id. This is the bridge from an HTTP request to a
/// nio authorization question: which namespace/object/relation to check.
struct ArticleResource {
    id: String,
}

impl WebResource for ArticleResource {
    type Rejection = PathRejection;

    fn namespace(&self) -> Namespace {
        Namespace(NAMESPACE.into())
    }

    // The HTTP method chooses the relation: reads need `article.get`, writes
    // need `article.update`. Any other method can never be authorized.
    fn rel(&self, method: &Method) -> Option<Rel> {
        match *method {
            Method::GET | Method::HEAD => Some(Rel(REL_GET.into())),
            Method::POST => Some(Rel(REL_UPDATE.into())),
            _ => Some(Rel::impossible()),
        }
    }

    async fn parse<S: Send + Sync>(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Path(id) = Path::<String>::from_request_parts(parts, state).await?;
        Ok(ArticleResource { id })
    }

    fn object(&self) -> Obj {
        Obj(self.id.clone())
    }
}

// --- handlers ---------------------------------------------------------------

async fn home() -> Html<String> {
    Html(page(HOME_BODY))
}

#[derive(Deserialize)]
struct BackQuery {
    back: Option<String>,
}

async fn signin_form(Query(q): Query<BackQuery>) -> Html<String> {
    Html(signin_form_html(q.back.as_deref().unwrap_or("")))
}

#[derive(Deserialize)]
struct SigninForm {
    username: String,
    password: String,
    back: Option<String>,
}

async fn signin_submit(State(app): State<AppState>, Form(form): Form<SigninForm>) -> Response {
    let Some(principal) = authenticate(&form.username, &form.password) else {
        return (
            StatusCode::UNAUTHORIZED,
            Html(page(
                "<h1>Sign-in failed</h1><p>Unknown user or bad password. \
                 <a href=\"/signin\">Try again</a>.</p>",
            )),
        )
            .into_response();
    };

    // The app authenticated the user; now the backend issues a session and we
    // hand the raw token to the browser as a cookie. Only its hash is stored.
    let token = app.backend.create_session(principal);
    println!(
        "[app] {} signed in -> session issued (bearer token {}…)",
        display_name(principal),
        &token[..8]
    );

    let cookie = format!("session={token}; Path=/; HttpOnly; SameSite=Lax");
    let back = form.back.as_deref().filter(|b| !b.is_empty());
    let body = signin_success_html(display_name(principal), &token, safe_back(back));
    ([(header::SET_COOKIE, cookie)], Html(body)).into_response()
}

async fn signout(State(app): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = headers
        .typed_get::<Cookie>()
        .and_then(|c| c.get("session").map(String::from))
    {
        let hash = token_hash(&token);
        app.backend.remove_session(&hash); // drop it at the source
        app.auth.resolver.evict(&hash); // and from the resolver's L1 cache
        println!("[app] signed out -> session {}… revoked", &hash[..8]);
    }
    let clear = "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
    ([(header::SET_COOKIE, clear)], Redirect::to("/")).into_response()
}

// Cookie-guarded UI page. Reaching the body means the cookie resolved to a
// principal and that principal passed the `article.get` check.
async fn ui_article(auth: WithPrincipal<ArticleResource>) -> Html<String> {
    let id = &auth.resource.id;
    let (title, body) = article(id);
    Html(article_page_html(
        id,
        display_name(auth.principal.as_str()),
        auth.principal.as_str(),
        title,
        body,
    ))
}

// Public page with optional authorization. No session -> anonymous view; a
// valid session must still pass the check (article 3 is granted to allUsers).
async fn public_article(auth: WithOptPrincipal<ArticleResource>) -> Html<String> {
    let id = &auth.resource.id;
    let (title, body) = article(id);
    let who = match &auth.principal {
        Some(p) => format!("signed in as <b>{}</b>", display_name(p.as_str())),
        None => "anonymous".to_string(),
    };
    let body = format!(
        "<p><a href=\"/\">← Home</a></p><h1>{title}</h1><p>{body}</p>\
         <hr><p><small>public article:{} · viewer: {who}</small></p>",
        html_escape(id)
    );
    Html(page(&body))
}

// Bearer-guarded API read (`article.get`).
async fn api_get(auth: WithPrincipal<ArticleResource, BearerTokenAuth>) -> Json<serde_json::Value> {
    let id = &auth.resource.id;
    let (title, body) = article(id);
    Json(json!({
        "action": "view",
        "id": id,
        "principal": auth.principal.as_str(),
        "user": display_name(auth.principal.as_str()),
        "title": title,
        "body": body,
    }))
}

// Bearer-guarded API write (`article.update`).
async fn api_update(
    auth: WithPrincipal<ArticleResource, BearerTokenAuth>,
) -> Json<serde_json::Value> {
    let id = &auth.resource.id;
    Json(json!({
        "action": "update",
        "id": id,
        "principal": auth.principal.as_str(),
        "user": display_name(auth.principal.as_str()),
        "ok": true,
        "message": format!("article {id} updated"),
    }))
}

// --- demo policy & content --------------------------------------------------

fn authenticate(username: &str, password: &str) -> Option<&'static str> {
    match (username, password) {
        ("alice", "alice") => Some(ALICE),
        ("bob", "bob") => Some(BOB),
        _ => None,
    }
}

fn display_name(principal: &str) -> &'static str {
    match principal {
        ALICE => "alice",
        BOB => "bob",
        _ => "unknown",
    }
}

fn article(id: &str) -> (&'static str, &'static str) {
    match id {
        "1" => (
            "Getting started with nio",
            "Relationship-based access control, wired end to end.",
        ),
        "2" => (
            "Zookies and consistency",
            "How opaque timestamps buy you read-your-writes.",
        ),
        "3" => (
            "Public announcement",
            "Anyone may read this one — it is granted to allUsers.",
        ),
        _ => ("(no such article)", "This article has no content."),
    }
}

/// Only allow post-sign-in redirects to local paths (no open redirects).
fn safe_back(back: Option<&str>) -> Option<&str> {
    back.filter(|b| b.starts_with('/') && !b.starts_with("//"))
}

// --- HTML helpers -----------------------------------------------------------

const HEAD: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>nio webapp example</title><style>\
body{font-family:system-ui,sans-serif;max-width:44rem;margin:2rem auto;padding:0 1rem;line-height:1.55;color:#111}\
code,pre{background:#f4f4f5;border-radius:4px}code{padding:.1rem .3rem}\
pre{padding:.7rem;overflow-x:auto}a{color:#2563eb}h1{font-size:1.6rem}\
table{border-collapse:collapse}td,th{border:1px solid #ddd;padding:.3rem .6rem}\
</style></head><body>";
const FOOT: &str = "</body></html>";

fn page(body: &str) -> String {
    format!("{HEAD}{body}{FOOT}")
}

const HOME_BODY: &str = "<h1>nio webapp example</h1>\
<p>A minimal relying party wired to nio through the <code>axum</code> feature. \
It shows the three things every nio integration needs: <b>sign-in</b>, \
<b>session resolution</b>, and <b>access checks</b>.</p>\
<p>Watch the terminal running this app: every <code>[nio session]</code> and \
<code>[nio check]</code> line is an RPC the extractors made for you.</p>\
<h2>1. Sign in (browser / cookie)</h2>\
<p>Demo users: <code>alice / alice</code> and <code>bob / bob</code>.</p>\
<p><a href=\"/signin\">Go to sign-in →</a></p>\
<h2>2. Cookie-protected UI pages</h2>\
<ul>\
<li><a href=\"/articles/1\">/articles/1</a> — alice may read; bob is denied (403)</li>\
<li><a href=\"/articles/2\">/articles/2</a> — both may read</li>\
<li><a href=\"/public/articles/3\">/public/articles/3</a> — public (allUsers), no sign-in needed</li>\
</ul>\
<p>Open <a href=\"/articles/1\">/articles/1</a> while signed out to see the \
redirect to <code>/signin?back=/articles/1</code>.</p>\
<h2>3. Bearer-protected API</h2>\
<p>Sign in first; the success page prints your bearer token. Then:</p>\
<pre>curl -H 'Authorization: Bearer &lt;token&gt;' http://127.0.0.1:8080/api/articles/1\n\
curl -X POST -H 'Authorization: Bearer &lt;token&gt;' http://127.0.0.1:8080/api/articles/1</pre>\
<p>The same token works as a cookie (UI) and as a bearer (API): both are \
resolved the same way. As alice, <code>GET</code> and <code>POST</code> on \
article 1 succeed; as bob, both are forbidden. On article 2 alice may \
<code>GET</code> but her <code>POST</code> is denied — she is a reader, not an editor.</p>";

fn signin_form_html(back: &str) -> String {
    let back = html_escape(back);
    let body = format!(
        "<h1>Sign in</h1>\
         <p>Demo users: <code>alice / alice</code>, <code>bob / bob</code>.</p>\
         <form method=\"post\" action=\"/signin\">\
         <p><label>User<br><input name=\"username\" autofocus></label></p>\
         <p><label>Password<br><input name=\"password\" type=\"password\"></label></p>\
         <input type=\"hidden\" name=\"back\" value=\"{back}\">\
         <p><button type=\"submit\">Sign in</button></p>\
         </form><p><a href=\"/\">Home</a></p>"
    );
    page(&body)
}

fn signin_success_html(name: &str, token: &str, back: Option<&str>) -> String {
    let cont = match back {
        Some(b) => {
            let b = html_escape(b);
            format!("<p><a href=\"{b}\">Continue to {b} →</a></p>")
        }
        None => String::new(),
    };
    let body = format!(
        "<h1>Signed in as {name}</h1>\
         <p>A <code>session</code> cookie is set, so the UI pages work now.</p>\
         <p>The same token is your API <b>bearer</b> token:</p>\
         <pre>{token}</pre>\
         <p>Call the bearer-protected API with it:</p>\
         <pre>curl -H 'Authorization: Bearer {token}' \\\n  http://127.0.0.1:8080/api/articles/1</pre>\
         {cont}\
         <p><a href=\"/articles/1\">Open article 1 (UI)</a> · <a href=\"/\">Home</a></p>\
         <form method=\"post\" action=\"/signout\"><button>Sign out</button></form>"
    );
    page(&body)
}

fn article_page_html(id: &str, name: &str, principal: &str, title: &str, body: &str) -> String {
    let id = html_escape(id);
    let body = format!(
        "<p><a href=\"/\">← Home</a></p>\
         <h1>{title}</h1><p>{body}</p><hr>\
         <p><small>article:{id} · viewed by <b>{name}</b> \
         (<code>{principal}</code>)<br>Access was granted by a nio check for \
         <code>article.get</code>.</small></p>\
         <form method=\"post\" action=\"/signout\"><button>Sign out</button></form>"
    );
    page(&body)
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}
