# The `webapp` example — learning nio end to end

A complete, runnable relying party built on the `nio-client` **axum** feature.
It demonstrates the three things every nio integration does:

1. **Sign-in** — authenticate a user and hand them a session token.
2. **Session resolution** — turn that token (from a cookie *or* a bearer
   header) back into a principal.
3. **Access checks** — ask nio whether that principal may perform the
   requested action on the requested object.

It runs **with no external server**: a small in-process stand-in
([`backend.rs`](backend.rs)) plays the role of nio, and it logs every RPC to
the console so you can watch resolution and checks happen as you click around.

```
cargo run --example webapp --features axum
# then open http://127.0.0.1:8080/
```

---

## The nio mental model in five terms

nio is a **relationship-based** authorization service (in the ReBAC / Google
Zanzibar family). Instead of roles baked into your app, permissions are stored
as relationship **tuples** and evaluated on demand.

| Term | Meaning | In this demo |
|------|---------|--------------|
| **Namespace** | A kind of object | `article` |
| **Object** | One thing in a namespace | `article:1` |
| **Relation** | A verb / permission on an object | `article.get`, `article.update` |
| **Tuple** | `namespace:object#relation@subject` — one stored grant | `article:1#article.get@alice` |
| **Principal** | The subject a check runs against | alice's UUID |

A **check** answers one yes/no question: *does `subject` hold `relation` on
`namespace:object`?* The client never sends a raw password or token to the
check — it sends the resolved **principal**.

A **session** is an opaque token your app gives the user after they sign in.
nio stores it hashed; resolving a session returns `{principal, tenant,
expires_at}`. The same token can arrive two ways, and nio treats them
identically:

- a **`session` cookie** — for browser UI pages, and
- an **`Authorization: Bearer` header** — for API clients.

---

## Architecture

```
        browser / API client
                │  cookie: session=<token>      (UI)
                │  Authorization: Bearer <token> (API)
                ▼
┌───────────────────────────────────────────────┐
│  your axum app  (app.rs)                        │
│                                                 │
│   handler(WithPrincipal<ArticleResource>)       │
│        │                                        │
│        ▼   the extractor does, per request:     │
│   1. hash the token      (sha256, in-process)   │
│   2. resolve  ──────────────┐                   │
│   3. check    ──────────┐   │                   │
└─────────────────────────┼───┼───────────────────┘
                          │   │
                 CheckService  SessionService     ← nio (backend.rs here;
                 (authorize)   (token → principal)   real nio in production)
```

The **raw token never leaves the process** and is **never sent to the check** —
only its `sha256` hash goes to the session service, and only the resolved
principal UUID goes to the check. If a token is unknown/expired/revoked, the
request is rejected with **zero** check RPCs.

### The request lifecycle inside an extractor

For a guarded route like `GET /articles/1`, the `WithPrincipal` extractor runs
*before* your handler and does:

1. **parse** the resource from the request → namespace `article`, object `1`,
   relation from the method (`GET` → `article.get`).
2. read the token (cookie for `SessionCookieAuth`, bearer for
   `BearerTokenAuth`). No token → redirect to `/signin?back=…`.
3. **resolve** `sha256(token)` → principal. Not found → redirect to sign-in
   (no check made).
4. **check** `article:1#article.get @ principal`. Allowed → your handler runs
   with `auth.principal` and `auth.resource`. Denied → `403`.

Your handler body only runs when all four steps succeed.

---

## The three extractors

| Extractor | Token source | No/invalid token | Use for |
|-----------|--------------|------------------|---------|
| `WithPrincipal<R>` (default `SessionCookieAuth`) | `session` cookie | redirect to sign-in | browser UI pages |
| `WithPrincipal<R, BearerTokenAuth>` | `Authorization: Bearer` | redirect to sign-in¹ | APIs |
| `WithOptPrincipal<R>` | `session` cookie | **allowed as anonymous** | public pages that still authorize a signed-in user |

There is also `Authenticated<BearerTokenAuth>`, which resolves the caller
*without* running a check — for handlers whose object is only known from the
request **body** (parse can't see the body). Such a handler must call
`CheckClient::check` itself once it knows the object.

¹ The current bearer path redirects (303) on a missing/invalid token, same as
the cookie path — there is a `TODO` in the library to return a proper OAuth2
`401`/`WWW-Authenticate` instead. For a real API you would map
`WebResourceError::MissingSession` to `401`.

---

## Demo policy

Users: `alice / alice`, `bob / bob`. Seeded tuples ([`app.rs`](app.rs),
`seed`):

| object | alice | bob | anyone (`allUsers`) |
|--------|-------|-----|---------------------|
| `article:1` | `get` + `update` | — | — |
| `article:2` | `get` | `get` + `update` | — |
| `article:3` | (via `allUsers`) | (via `allUsers`) | `get` |

So alice **owns** article 1, alice is a **reader** of article 2 (bob owns it),
and article 3 is **public**.

---

## Guided walkthrough

Run the app and keep its terminal visible — the `[nio session]` and
`[nio check]` lines are the RPCs the extractors made for you.

### A. The redirect loop (unauthenticated → sign-in → back)

```
curl -si http://127.0.0.1:8080/articles/1 | grep -i location
#   location: /signin?back=%2Farticles%2F1
```

No cookie → the extractor rejects with `MissingSession`, redirecting to
sign-in with the original path preserved in `back`. In a browser you land on
the sign-in form; after signing in, the success page links you back.

### B. Sign in (cookie + bearer are the same token)

```
curl -c alice.jar -X POST http://127.0.0.1:8080/signin \
  --data 'username=alice&password=alice'
```

The response sets a `session` cookie **and** prints the raw token — that one
token is your bearer token too. Console:

```
[app] alice signed in -> session issued (bearer token 2be41063…)
```

### C. Cookie-protected UI pages

```
curl -b alice.jar -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/articles/1   # 200
curl -b bob.jar   -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/articles/1   # 403
```

```
[nio session] resolve(1c96bd28…) -> …-alice   (resolved once, then cached ~30s)
[nio check]   article:1#article.get @ …-alice -> ALLOW
[nio check]   article:1#article.get @ …-bob   -> DENY
```

Note: resolution is **cached** (the resolver's L1 tier), so a burst of requests
on one session triggers **one** resolve but a check **per request**.

### D. Bearer-protected API (method → relation)

```
TOKEN=<the 64-hex token from step B>
curl -H "Authorization: Bearer $TOKEN"        http://127.0.0.1:8080/api/articles/1   # 200 view
curl -H "Authorization: Bearer $TOKEN" -X POST http://127.0.0.1:8080/api/articles/2   # 403
```

`GET` maps to `article.get`, `POST` to `article.update`. alice may read
article 2 but not update it — she is a reader, not an editor:

```
[nio check]   article:2#article.update @ …-alice -> DENY
```

### E. Public page with optional auth

```
curl -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/public/articles/3          # 200 anonymous
curl -b alice.jar -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/public/articles/3  # 200, "signed in as alice"
```

`WithOptPrincipal` lets anonymous callers through (no check), but a caller who
*does* present a valid session is still checked — here article 3's `allUsers`
grant means everyone passes.

### F. Sign out revokes the session

```
curl -b alice.jar -X POST http://127.0.0.1:8080/signout
curl -b alice.jar -si http://127.0.0.1:8080/articles/1 | grep -i location   # back to sign-in
```

Sign-out drops the session at the source **and** evicts it from the resolver's
cache, so the next resolve is immediate:

```
[app] signed out -> session 1c96bd28… revoked
[nio session] resolve(1c96bd28…) -> NOT FOUND
```

---

## From this demo to real nio

Only the wiring in [`main.rs`](main.rs) changes. Replace the in-process backend
with your real, **separate** nio endpoints (check and session are always
distinct services):

```rust
let check_client = CheckClient::create("https://check.internal:50051".parse()?).await?;
let session_channel = connect_channel("https://sessions.internal:50052".parse()?, None).await?;
let resolver = GrpcSessionResolver::new(session_channel, ResolverConfig::default());
let auth = AuthState::new(check_client, resolver, None);
```

Use `CheckClient::create_with_tls` / `connect_channel(uri, Some(tls))` for
(m)TLS. Everything in [`app.rs`](app.rs) — the extractors, the `WebResource`,
the handlers — stays exactly the same. See [`../server.rs`](../server.rs) for
the minimal "point at a real nio" server.

Two things this demo simplifies:

- **Session issuance.** Here the backend mints tokens directly so the example
  is self-contained. In production your app authenticates the user (password,
  OAuth, …) and nio's session service issues the session; your app only ever
  *resolves* tokens through the client.
- **Access tuples** are hard-coded in `seed`. In production you write them to
  nio with the client's `write` / `add_one` APIs.

### Production checklist

- Add `Secure` (and consider `__Host-`/`SameSite=Strict`) to the session
  cookie — this demo runs plain HTTP on loopback.
- Map the bearer `MissingSession` rejection to `401` for APIs (see note ¹).
- Serve check and session over TLS; never use an insecure channel off-box.

---

## Where to look in the code

| File | Role |
|------|------|
| [`main.rs`](main.rs) | Wiring: start nio, build `AuthState`, serve. The only part that differs in production. |
| [`app.rs`](app.rs) | The app you'd write: `WebResource`, handlers, sign-in, the demo policy. |
| [`backend.rs`](backend.rs) | The in-process nio stand-in (CheckService + SessionService). |
