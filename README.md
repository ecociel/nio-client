# nio-client

A Rust client library for the **NIO Authorization Service**, a
high-performance, relationship-based authorization system. This library
provides a gRPC client to interact with the service and includes extractors
for easy integration with the `axum` framework (behind the `axum` feature).

# Usage

See the [examples](examples) directory: `check`, `list`, `write`, `watch`
(plain client) and `server` (axum integration).

# Updating gRPC Code

The generated code is built by `build.rs` (tonic-build) from the proto files
in [proto](proto). The original proto files track the nio server:

- [nio/proto/iam.proto](https://github.com/ecociel/nio/blob/main/proto/iam.proto) (authorization: check, list, expand, read, write, watch, …)
- [nio/proto/sessions.proto](https://github.com/ecociel/nio/blob/main/proto/sessions.proto) (session resolve)

`proto/iam.proto` and `proto/sessions.proto` should match the nio server you
deploy against so wire fields (e.g. `ListResponse.ts`, packed write zookies)
are visible to this client.

# Built-in namespaces and the admin gate

Constants mirror nio's `domain` crate and check bootstrap. Built-in
namespaces are `Namespace::iam()` (`iam`) and `Namespace::serviceaccount()`
(`serviceaccount`) only.

The singleton admin object is `iam:root` (`Namespace::iam()` + `Obj::root()`).
Typical gate relations:

- viewer path: `Rel::iam_get()` (`iam.get`)
- admin path: `Rel::iam_update()` (`iam.update`), `Rel::serviceaccount_create()`

Roles that carry direct grants: `Rel::admin()`, `Rel::editor()`,
`Rel::viewer()`. Public subject markers: `UserId::all_users()`,
`UserId::authenticated_users()`. The pointer object/rel keyword is `"..."`
(`Obj::unspecified()` / `Rel::unspecified()`).

# Construction

`check` and `nio-client` (session) are always separate TCP endpoints. The
library does not read environment variables; the process supplies targets,
TLS config, and cache config.

```rust,no_run
use nio_client::{connect_channel, CheckClient};
use nio_client::session::{GrpcSessionResolver, ResolverConfig};

# async fn build() -> Result<(), Box<dyn std::error::Error>> {
// RPC only (check / list / read / write / expand / watch / …)
let check_client = CheckClient::create("http://localhost:50051".parse()?).await?;

// Session resolution for HTTP middleware (axum feature): a second channel
// to am.SessionService on nio-client.
let session_channel = connect_channel("http://localhost:50052".parse()?, None).await?;
let resolver = GrpcSessionResolver::new(session_channel, ResolverConfig::default());
# Ok(())
# }
```

With the `axum` feature, `axum::AuthState::new(check_client, resolver, prefix)`
wires both into the `WithPrincipal` / `WithOptPrincipal` / `Authenticated`
extractors. Sign-in redirects go to `{prefix}/signin?back={original-uri}`.

All channels enable HTTP/2 keepalive (30s / 10s / while idle — nio #239).
`CheckClient::create_with_tls` / `connect_channel(uri, Some(tls))` take a
`tonic::transport::ClientTlsConfig` for (m)TLS.

# Session resolution

Opaque session tokens are resolved via `am.SessionService` on nio-client
(issue #243/#245). The axum extractors hash the cookie or bearer token
(`sha256`, hex — the raw token never leaves the process), resolve it, and
send the principal UUID to `check`. Unknown / expired / revoked tokens
redirect to signin with zero check RPCs.

The resolver caches positives (LRU, TTL with downward-only jitter), tombstones
unknown tokens, coalesces concurrent misses, refreshes hot entries ahead of
expiry, and can optionally serve stale entries during transport errors
(`ResolverConfig::stale_if_error`).

# Zookies (timestamps)

Check/list/write use **opaque packed zookies** (standard Base64 of 7 bytes:
`[epoch:u8][millis:u48 BE]`). Treat them as opaque: store and echo only.

- `Timestamp::empty()` (`AQAAAAAAAA==`) — no fresher-than constraint; server picks a snapshot
- Write helpers (`add_one`, `add_many`, `add_parent`, `delete_one`, `write`) return the **commit** zookie
- `list` / `read` / `expand` return the **evaluation** snapshot zookie in their results
- Pass a zookie into `check` / `list` / `read_with_timestamp` for read-your-writes

```rust,ignore
let ts = client.add_one(tuple).await?;
// ...
let res = client.check(ns, obj, rel, user_id, Some(ts)).await?;
```

`write(add, del, precondition)` supports atomic multi-tuple commits and an
optional OCC precondition zookie (`None` = unconditional). Tuples may carry
an expiry condition (`Tuple::with_expires`).

`content_change_check` authorizes a content modification at the freshest
snapshot and returns the zookie to store with the new content version.

`watch(ns, start_ts)` tails the changelog for a namespace (paper §2.4.6).
Call `recv` on the returned stream: empty `updates` is a heartbeat; non-empty
is one atomic write at `ts`. Resume from any received `ts` (exclusive).

The Read API supports object filters (`ReadFilter::by_object`) and reverse
subject filters (`ReadFilter::by_user`, `ReadFilter::by_user_set`, paper
§2.4.3) answered via the reverse index — raw stored edges, no rewrite
evaluation. Use `expand` for the effective userset.

# Request-scoped check memoization

`memo::RequestMemo` memoizes check and list decisions for the lifetime of a
single request — a handler running many check/list calls for the same subject
collapses to far fewer RPCs:

```rust,ignore
let memo = nio_client::memo::RequestMemo::new(check_client.clone());
let first = memo.check(ns.clone(), obj.clone(), rel.clone(), user.clone()).await?; // RPC
let again = memo.check(ns, obj, rel, user).await?; // in-request cache hit
```

Identical `(ns, obj, rel, principal)` checks (and `(ns, rel, principal)`
lists) are answered from an in-request cache; concurrent identical misses are
coalesced so a handler fanning checks across tasks still issues one RPC per
key. Errors are never cached.

This is free of staleness risk (a request is one logical instant) but create
one memo **per request** and do not use it in a handler that writes a tuple
and then re-checks expecting to observe its own write.
`RequestMemo::with_timestamp` pins the evaluation zookie for the request;
`RequestMemo::with_observer` reports per-lookup hit/miss.

# Building and testing

A [Taskfile](https://taskfile.dev) drives the workflow:

    task build       # cargo build --features axum
    task lint        # clippy, warnings are errors
    task test        # unit + in-process mock gRPC server tests
    task test-live   # live tests against NIO_CHECK_URI
    task ci          # fmt-check + lint + build + test
    task example-check -- customer acme customer.update <userid>

# License

This project is licensed under the **MIT License**. See the
[LICENSE](LICENSE) file for details.
