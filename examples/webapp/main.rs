//! Self-contained nio learning app: sign-in, cookie-session UI, bearer-token
//! API, session resolution, and access checks — all against an in-process nio
//! stand-in, so `cargo run --example webapp --features axum` needs no server.
//!
//! Run it, then read the console: every request prints the `[nio session]`
//! resolve and `[nio check]` RPCs the extractors issue on your behalf. See
//! `examples/webapp/README.md` for the guided walkthrough.
//!
//! Wiring, top to bottom:
//!
//! 1. Start the in-process nio backend (CheckService + SessionService).
//! 2. Build a `CheckClient` and a `GrpcSessionResolver` pointed at it.
//! 3. Combine them into an `AuthState` — the state the extractors read.
//! 4. Serve the axum app.
//!
//! In production, steps 1–2 change to dialing your real, separate nio check and
//! session endpoints (see `examples/server.rs`); everything else is identical.

mod app;
mod backend;

use app::AppState;
use backend::Backend;
use nio_client::axum::AuthState;
use nio_client::session::{GrpcSessionResolver, ResolverConfig};
use nio_client::{connect_channel, CheckClient};

const ADDR: &str = "127.0.0.1:8080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. The nio stand-in, seeded with the demo users and access rules.
    let backend = Backend::new();
    app::seed(&backend);
    let nio_uri = backend.clone().serve().await;

    // 2. Two clients over that endpoint. In production these dial two distinct
    //    nio services; the resolver hashes tokens and resolves them to
    //    principals, the check client answers authorization questions.
    let check_client = CheckClient::create(nio_uri.clone()).await?;
    let session_channel = connect_channel(nio_uri, None).await?;
    let resolver = GrpcSessionResolver::new(session_channel, ResolverConfig::default());

    // 3. The state the extractors read. `None` prefix -> sign-in at `/signin`.
    let auth = AuthState::new(check_client, resolver, None);
    let state = AppState { auth, backend };

    // 4. Serve.
    let app = app::router(state);
    let listener = tokio::net::TcpListener::bind(ADDR).await?;
    print_banner();
    axum::serve(listener, app).await?;
    Ok(())
}

fn print_banner() {
    println!("\nnio webapp example — http://{ADDR}");
    println!("  demo users: alice/alice, bob/bob");
    println!("  open http://{ADDR}/ and watch this console for nio RPCs\n");
}
