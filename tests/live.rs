//! Live-server integration tests: they connect to a running check at
//! `NIO_CHECK_URI` (read at runtime). Off by default so the test build stays
//! green without a server; run with
//! `NIO_CHECK_URI=http://localhost:50051 cargo test --features live-tests --test live`.
#![cfg(feature = "live-tests")]

use http::Uri;
use nio_client::auth::CheckResult;
use nio_client::{CheckClient, Namespace, Obj, Rel, Timestamp, Tuple, User, UserId};

fn check_uri() -> Uri {
    std::env::var("NIO_CHECK_URI")
        .expect("NIO_CHECK_URI environment variable not set")
        .parse()
        .expect("NIO_CHECK_URI must be a valid URI")
}

async fn client() -> CheckClient {
    CheckClient::create(check_uri())
        .await
        .expect("connect to check")
}

#[tokio::test]
async fn check() {
    let mut c = client().await;
    let res = c
        .check(
            Namespace("customer".into()),
            Obj("acme".into()),
            Rel("customer.update".into()),
            UserId("abcdef".into()),
            None,
        )
        .await
        .expect("check");
    match res {
        CheckResult::Ok(p) => println!("ok {}", p.as_str()),
        CheckResult::Forbidden(p) => println!("forbidden {}", p.as_str()),
        CheckResult::UnknownPutativeUser => println!("unknown user"),
    }
}

#[tokio::test]
async fn list() {
    let mut c = client().await;
    let res = c
        .list(
            Namespace("customer".into()),
            Rel("customer.get".into()),
            UserId("734962c4-d62c-4e1f-9236-0e8ee1811b9d".into()),
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
    let user = UserId("11111111-1111-1111-1111-111111111111".into());

    let tuple = Tuple::new(
        ns.clone(),
        obj.clone(),
        rel.clone(),
        User::UserId(user.0.clone()),
    );
    let commit_ts = c.add_one(tuple.clone()).await.expect("add");
    assert_ne!(commit_ts, Timestamp::empty());

    let read = c.get_all(&ns, &obj).await.expect("read");
    assert!(
        read.tuples
            .iter()
            .any(|t| matches!(t.sbj, User::UserId(ref u) if *u == user.0)),
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
