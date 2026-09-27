//! Live-server integration tests: they connect to a running check at
//! `NIO_CHECK_URI` and, for sessions, to nio-client at `NIO_SESSION_URI`
//! (gRPC) and `NIO_BASE_URI` (sign-in pages). Off by default so the test build
//! stays green without a server. Start the stack with `task stack-up`, then run
//! `task test-live`.
#![cfg(feature = "live-tests")]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http::Uri;
use nio_client::auth::CheckResult;
use nio_client::session::{token_hash, GrpcSessionResolver, ResolverConfig};
use nio_client::wire::check_request;
use nio_client::wire::check_service_client::CheckServiceClient;
use nio_client::{
    connect_channel, CheckClient, Namespace, Obj, Rel, Timestamp, Tuple, User, UserId, UserSet,
};

fn env_uri(name: &str) -> Uri {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} environment variable not set"))
        .parse()
        .unwrap_or_else(|_| panic!("{name} must be a valid URI"))
}

fn check_uri() -> Uri {
    env_uri("NIO_CHECK_URI")
}

fn uid(n: i64) -> UserId {
    UserId::try_from(n).unwrap()
}

async fn client() -> CheckClient {
    CheckClient::create(check_uri())
        .await
        .expect("connect to check")
}

fn run_id() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn project() -> Namespace {
    Namespace("project".into())
}

fn viewer(obj: &Obj, sbj: User) -> Tuple {
    Tuple::new(project(), obj.clone(), Rel::viewer(), sbj)
}

fn shown(tuples: &[Tuple]) -> Vec<String> {
    tuples.iter().map(ToString::to_string).collect()
}

#[tokio::test]
async fn check() {
    let mut c = client().await;
    let res = c
        .check(
            Namespace("customer".into()),
            Obj("acme".into()),
            Rel("customer.update".into()),
            uid(1),
            None,
        )
        .await
        .expect("check");
    match res {
        CheckResult::Ok(p) => println!("ok {p}"),
        CheckResult::Forbidden(p) => println!("forbidden {p}"),
    }
}

#[tokio::test]
async fn list() {
    let mut c = client().await;
    let res = c
        .list(
            Namespace("customer".into()),
            Rel("customer.get".into()),
            uid(2),
            None,
        )
        .await
        .expect("list");
    println!("ts={} objs={:#?}", res.ts.0, res.objs);
}

#[tokio::test]
async fn write_check_read_delete_roundtrip() {
    let mut c = client().await;
    let ns = Namespace("customer".into());
    let obj = Obj("nio-client-live-test".into());
    let rel = Rel::viewer();
    let user = User::UserId(uid(1111));

    let tuple = Tuple::new(ns.clone(), obj.clone(), rel.clone(), user.clone());
    let commit_ts = c.add_one(tuple.clone()).await.expect("add");
    assert_ne!(commit_ts, Timestamp::empty());

    let read = c.get_all(&ns, &obj).await.expect("read");
    assert!(
        read.tuples.iter().any(|t| t.sbj == user),
        "written tuple must be readable"
    );

    let ts = c.delete_one(tuple).await.expect("delete");
    assert_ne!(ts, Timestamp::empty());
}

#[tokio::test]
async fn list_namespaces() {
    let mut c = client().await;
    let namespaces = c.list_namespaces().await.expect("list namespaces");
    println!("{namespaces:#?}");
}

#[tokio::test]
async fn check_rejects_invalid_user_id() {
    assert!(UserId::try_from(0).is_err(), "UserId 0 must not parse");
    assert!(UserId::try_from(-1).is_err(), "UserId -1 must not parse");

    let channel = connect_channel(check_uri(), None)
        .await
        .expect("connect to check");
    let mut raw = CheckServiceClient::new(channel);
    for id in [0, -1] {
        let status = raw
            .check(nio_client::wire::CheckRequest {
                ns: "project".into(),
                obj: "p42".into(),
                rel: "project.get".into(),
                user: Some(check_request::User::UserId(id)),
                ts: None,
            })
            .await
            .expect_err("check with an invalid user id must fail");
        println!("check(user_id={id}): {status}");
        assert_eq!(status.code(), tonic::Code::InvalidArgument, "user_id={id}");
    }
}

#[tokio::test]
async fn expand_returns_every_subject_kind() {
    let mut c = client().await;
    let obj = Obj(format!("expand-{}", run_id()));
    let parent = UserSet {
        ns: project(),
        obj: Obj("p42".into()),
        rel: Rel::unspecified(),
    };

    let ts = c
        .add_many(vec![
            viewer(&obj, User::UserId(uid(42))),
            viewer(&obj, User::AllUsers),
            viewer(
                &obj,
                User::UserSet {
                    ns: parent.ns.clone(),
                    obj: parent.obj.clone(),
                    rel: parent.rel.clone(),
                },
            ),
        ])
        .await
        .expect("write");

    let res = c
        .expand(project(), obj.clone(), Rel::viewer(), Some(ts))
        .await
        .expect("expand");
    println!("expand project:{}#viewer = {res:?}", obj.0);
    assert_eq!(res.user_ids, vec![uid(42)]);
    assert!(res.all_users, "allUsers must be expanded");
    assert!(
        !res.authenticated_users,
        "authenticatedUsers was not written"
    );
    assert_eq!(res.usersets, vec![parent]);
}

#[tokio::test]
async fn watch_and_read_by_user() {
    let mut c = client().await;
    let run = run_id();
    let start_obj = Obj(format!("watch-start-{run}"));
    let user_obj = Obj(format!("watch-user-{run}"));
    let all_obj = Obj(format!("watch-all-{run}"));
    let subject = User::UserId(uid(42));

    let start = c
        .add_one(viewer(&start_obj, subject.clone()))
        .await
        .expect("write start marker");
    let mut stream = c.watch(project(), start).await.expect("watch");
    c.add_one(viewer(&user_obj, subject.clone()))
        .await
        .expect("write user tuple");
    c.add_one(viewer(&all_obj, User::AllUsers))
        .await
        .expect("write allUsers tuple");

    let mut want = BTreeSet::from([
        viewer(&user_obj, subject.clone()).to_string(),
        viewer(&all_obj, User::AllUsers).to_string(),
    ]);
    tokio::time::timeout(Duration::from_secs(30), async {
        while !want.is_empty() {
            let event = stream
                .recv()
                .await
                .expect("recv")
                .expect("watch stream ended early");
            for u in event.updates {
                println!("watch ts={} {} deleted={}", event.ts.0, u.tuple, u.deleted);
                want.remove(&u.tuple.to_string());
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("watch did not deliver {want:?} within 30s"));

    let res = c
        .read_by_user(&project(), &subject, None)
        .await
        .expect("read by user");
    println!("read by user 42: {} tuples", res.tuples.len());
    assert!(
        res.tuples.iter().all(|t| t.sbj == subject),
        "read_by_user returned another subject: {:?}",
        shown(&res.tuples)
    );
    let this_run: BTreeSet<String> = res
        .tuples
        .iter()
        .filter(|t| [&start_obj, &user_obj, &all_obj].contains(&&t.obj))
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        this_run,
        BTreeSet::from([
            format!("Tuple(project:watch-start-{run}#viewer@42)"),
            format!("Tuple(project:watch-user-{run}#viewer@42)"),
        ])
    );
}

#[tokio::test]
async fn get_all_sees_own_write() {
    let mut c = client().await;
    let run = run_id();
    let obj = Obj(format!("read-latest-{run}"));

    c.add_one(viewer(&obj, User::UserId(uid(42))))
        .await
        .expect("write");
    let res = c.get_all(&project(), &obj).await.expect("get all");
    assert_eq!(
        shown(&res.tuples),
        vec![format!("Tuple(project:read-latest-{run}#viewer@42)")]
    );
}

#[tokio::test]
async fn conditional_write_conflicts_on_stale_precondition() {
    let mut c = client().await;
    let obj = Obj(format!("conflict-{}", run_id()));

    let stale = c
        .add_one(viewer(&obj, User::UserId(uid(42))))
        .await
        .expect("first write");
    c.add_one(viewer(&obj, User::UserId(uid(43))))
        .await
        .expect("concurrent write");
    let err = c
        .write(
            vec![viewer(&obj, User::UserId(uid(44)))],
            vec![],
            Some(stale),
        )
        .await
        .expect_err("write at a stale precondition must fail");
    println!("conditional write: {err}");
    let status = std::error::Error::source(&err)
        .and_then(|s| s.downcast_ref::<tonic::Status>())
        .expect("write error carries a gRPC status");
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn session_resolve_returns_tenant() {
    let base = env_uri("NIO_BASE_URI");
    let email = format!("live-{}@local.local", run_id());
    let password = "live-test-password";

    let signup = post_form(
        &base,
        "signup",
        "application/vnd.nio.signup-outcome+json",
        &[
            ("email", &email),
            ("password", password),
            ("confirm_password", password),
            ("back", "/"),
        ],
    );
    assert!(signup.contains("\"ok\":true"), "sign-up answered {signup}");
    let signin = post_form(
        &base,
        "signin",
        "application/vnd.nio.signin-outcome+json",
        &[("email", &email), ("password", password), ("back", "/")],
    );
    let token = session_cookie(&signin)
        .unwrap_or_else(|| panic!("sign-in set no session cookie: {signin}"));

    let channel = connect_channel(env_uri("NIO_SESSION_URI"), None)
        .await
        .expect("connect to session service");
    let resolver = GrpcSessionResolver::new(channel, ResolverConfig::default());
    let session = resolver
        .resolve(&token_hash(&token))
        .await
        .expect("resolve")
        .expect("signed-in session must resolve");
    println!("resolved {session:?}");
    assert_eq!(session.tenant_id, "default");
    assert!(session.expires_at > chrono::Utc::now());

    let unknown = resolver
        .resolve(&token_hash("not-a-session-token"))
        .await
        .expect("resolve unknown");
    assert!(unknown.is_none(), "unknown token resolved to {unknown:?}");
}

/// Posts a form to `<base>/<path>` over plain HTTP/1.1 and returns the raw
/// response, headers included, so the caller can read `Set-Cookie`.
fn post_form(base: &Uri, path: &str, accept: &str, fields: &[(&str, &str)]) -> String {
    let authority = base.authority().expect("NIO_BASE_URI has a host").as_str();
    let body = fields
        .iter()
        .map(|(k, v)| format!("{k}={}", form_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let request = format!(
        "POST {}/{path} HTTP/1.1\r\nHost: {authority}\r\nAccept: {accept}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        base.path().trim_end_matches('/'),
        body.len()
    );
    let mut stream = TcpStream::connect(authority).expect("connect to nio-client");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream.write_all(request.as_bytes()).expect("send form");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    response
}

fn form_encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn session_cookie(response: &str) -> Option<String> {
    response.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("set-cookie") {
            return None;
        }
        let token = value.trim().strip_prefix("session=")?.split(';').next()?;
        (!token.is_empty()).then(|| token.to_string())
    })
}

#[tokio::test]
#[ignore = "latency probe; run with --ignored --nocapture against a live stack"]
async fn check_latency_probe() {
    let mut c = client().await;
    let obj = Obj(format!("probe-{}", run_id()));
    c.add_one(viewer(&obj, User::UserId(uid(42))))
        .await
        .expect("write probe tuple");

    let mut samples = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let started = Instant::now();
        c.check(
            project(),
            obj.clone(),
            Rel("project.get".into()),
            uid(42),
            None,
        )
        .await
        .expect("check");
        samples.push(started.elapsed().as_micros());
    }
    samples.sort_unstable();
    println!("p50_us={} p99_us={}", samples[499], samples[989]);
}
