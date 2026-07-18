use axum::extract::rejection::PathRejection;
use axum::extract::{FromRequestParts, Path};
use axum::http::request::Parts;
use axum::http::Method;
use axum::routing::get;
use axum::Router;
use http::Uri;
use nio_client::axum::{AuthState, WebResource, WithPrincipal};
use nio_client::session::{GrpcSessionResolver, ResolverConfig};
use nio_client::{connect_channel, CheckClient, Namespace, Obj, Rel};
use std::env;

/// A single article, identified by its ID.
struct ArticleResource {
    id: String,
}

impl WebResource for ArticleResource {
    type Rejection = PathRejection;

    fn namespace(&self) -> Namespace {
        Namespace("article".into())
    }

    fn rel(&self, method: &Method) -> Option<Rel> {
        match *method {
            Method::GET | Method::HEAD => Some(Rel("article.get".into())),
            Method::POST => Some(Rel("article.update".into())),
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

async fn get_article(auth: WithPrincipal<ArticleResource>) -> String {
    format!(
        "Article id={} (principal {})",
        auth.resource.id,
        auth.principal.as_str()
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // check and nio-client (session) are always separate endpoints. The
    // library does not read environment variables; this example process does.
    let check_uri: Uri = env::var("NIO_CHECK_URI")
        .unwrap_or_else(|_| "http://localhost:50051".into())
        .parse()?;
    let session_uri: Uri = env::var("NIO_SESSION_URI")
        .unwrap_or_else(|_| "http://localhost:50052".into())
        .parse()?;

    let check_client = CheckClient::create(check_uri).await?;
    let session_channel = connect_channel(session_uri, None).await?;
    let resolver = GrpcSessionResolver::new(session_channel, ResolverConfig::default());

    let state = AuthState::new(check_client, resolver, None);

    let app = Router::new()
        .route("/articles/{id}", get(get_article))
        .with_state(state);

    println!("Starting server on port 8080...");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
