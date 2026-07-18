//! End-to-end tests against an in-process mock gRPC server implementing
//! CheckService, NamespaceService, and SessionService. They verify both the
//! request each client method puts on the wire and the mapping of responses
//! into the client model.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures::Stream;
use http::Uri;
use nio_client::auth::CheckResult;
use nio_client::memo::RequestMemo;
use nio_client::session::{GrpcSessionResolver, ResolverConfig};
use nio_client::wire;
use nio_client::{
    connect_channel, CheckClient, Namespace, Obj, ReadFilter, Rel, Timestamp, Tuple, User, UserId,
    UserSet,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

#[derive(Default)]
struct MockState {
    check_requests: Vec<wire::CheckRequest>,
    check_response: Option<wire::CheckResponse>,
    check_fail_next: bool,
    list_requests: Vec<wire::ListRequest>,
    list_response: Option<wire::ListResponse>,
    list_fail_next: bool,
    expand_requests: Vec<wire::ExpandRequest>,
    expand_response: Option<wire::ExpandResponse>,
    ccc_requests: Vec<wire::ContentChangeCheckRequest>,
    ccc_response: Option<wire::ContentChangeCheckResponse>,
    read_requests: Vec<wire::ReadRequest>,
    read_response: Option<wire::ReadResponse>,
    write_requests: Vec<wire::WriteRequest>,
    write_response: Option<wire::WriteResponse>,
    watch_requests: Vec<wire::WatchRequest>,
    watch_responses: Vec<wire::WatchResponse>,
    namespaces: Vec<wire::NamespaceMeta>,
    resolve_requests: Vec<wire::ResolveRequest>,
    resolve_response: Option<wire::ResolveResponse>,
    resolve_fail_next: bool,
}

#[derive(Clone, Default)]
struct Mock {
    state: Arc<Mutex<MockState>>,
}

impl Mock {
    fn lock(&self) -> std::sync::MutexGuard<'_, MockState> {
        self.state.lock().expect("mock state poisoned")
    }
}

#[tonic::async_trait]
impl wire::check_service_server::CheckService for Mock {
    async fn check(
        &self,
        request: Request<wire::CheckRequest>,
    ) -> Result<Response<wire::CheckResponse>, Status> {
        let mut state = self.lock();
        state.check_requests.push(request.into_inner());
        if state.check_fail_next {
            state.check_fail_next = false;
            return Err(Status::internal("boom"));
        }
        Ok(Response::new(state.check_response.clone().unwrap_or(
            wire::CheckResponse {
                principal: None,
                ok: false,
            },
        )))
    }

    async fn content_change_check(
        &self,
        request: Request<wire::ContentChangeCheckRequest>,
    ) -> Result<Response<wire::ContentChangeCheckResponse>, Status> {
        let mut state = self.lock();
        state.ccc_requests.push(request.into_inner());
        Ok(Response::new(
            state.ccc_response.clone().unwrap_or_default(),
        ))
    }

    async fn list(
        &self,
        request: Request<wire::ListRequest>,
    ) -> Result<Response<wire::ListResponse>, Status> {
        let mut state = self.lock();
        state.list_requests.push(request.into_inner());
        if state.list_fail_next {
            state.list_fail_next = false;
            return Err(Status::internal("boom"));
        }
        Ok(Response::new(
            state.list_response.clone().unwrap_or_default(),
        ))
    }

    async fn expand(
        &self,
        request: Request<wire::ExpandRequest>,
    ) -> Result<Response<wire::ExpandResponse>, Status> {
        let mut state = self.lock();
        state.expand_requests.push(request.into_inner());
        Ok(Response::new(
            state.expand_response.clone().unwrap_or_default(),
        ))
    }

    async fn read(
        &self,
        request: Request<wire::ReadRequest>,
    ) -> Result<Response<wire::ReadResponse>, Status> {
        let mut state = self.lock();
        state.read_requests.push(request.into_inner());
        Ok(Response::new(
            state.read_response.clone().unwrap_or_default(),
        ))
    }

    async fn write(
        &self,
        request: Request<wire::WriteRequest>,
    ) -> Result<Response<wire::WriteResponse>, Status> {
        let mut state = self.lock();
        state.write_requests.push(request.into_inner());
        Ok(Response::new(
            state.write_response.clone().unwrap_or_default(),
        ))
    }

    type WatchStream =
        Pin<Box<dyn Stream<Item = Result<wire::WatchResponse, Status>> + Send + 'static>>;

    async fn watch(
        &self,
        request: Request<wire::WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let mut state = self.lock();
        state.watch_requests.push(request.into_inner());
        let events: Vec<Result<wire::WatchResponse, Status>> =
            state.watch_responses.clone().into_iter().map(Ok).collect();
        Ok(Response::new(Box::pin(tokio_stream::iter(events))))
    }
}

#[tonic::async_trait]
impl wire::namespace_service_server::NamespaceService for Mock {
    async fn list_namespaces(
        &self,
        _request: Request<()>,
    ) -> Result<Response<wire::ListNamespacesResponse>, Status> {
        let state = self.lock();
        Ok(Response::new(wire::ListNamespacesResponse {
            namespaces: state.namespaces.clone(),
        }))
    }
}

#[tonic::async_trait]
impl wire::session_service_server::SessionService for Mock {
    async fn resolve(
        &self,
        request: Request<wire::ResolveRequest>,
    ) -> Result<Response<wire::ResolveResponse>, Status> {
        let mut state = self.lock();
        state.resolve_requests.push(request.into_inner());
        if state.resolve_fail_next {
            state.resolve_fail_next = false;
            return Err(Status::internal("session backend down"));
        }
        Ok(Response::new(state.resolve_response.clone().unwrap_or(
            wire::ResolveResponse {
                outcome: Some(wire::resolve_response::Outcome::NotFound(wire::NotFound {})),
            },
        )))
    }
}

async fn start_mock() -> (Mock, Uri) {
    let mock = Mock::default();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let server = mock.clone();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(wire::check_service_server::CheckServiceServer::new(
                server.clone(),
            ))
            .add_service(wire::namespace_service_server::NamespaceServiceServer::new(
                server.clone(),
            ))
            .add_service(wire::session_service_server::SessionServiceServer::new(
                server,
            ))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("mock server");
    });
    let uri: Uri = format!("http://{addr}").parse().expect("uri");
    (mock, uri)
}

async fn client(uri: Uri) -> CheckClient {
    CheckClient::create(uri).await.expect("connect")
}

#[tokio::test]
async fn check_ok_maps_principal_and_sends_default_ts() {
    let (mock, uri) = start_mock().await;
    mock.lock().check_response = Some(wire::CheckResponse {
        principal: Some(wire::Principal { id: "p-1".into() }),
        ok: true,
    });
    let mut c = client(uri).await;

    let res = c
        .check(
            Namespace("doc".into()),
            Obj("1".into()),
            Rel::viewer(),
            UserId("u1".into()),
            None,
        )
        .await
        .expect("check");
    match res {
        CheckResult::Ok(p) => assert_eq!(p.as_str(), "p-1"),
        other => panic!("expected ok, got {other:?}"),
    }

    let reqs = mock.lock().check_requests.clone();
    assert_eq!(
        reqs,
        vec![wire::CheckRequest {
            ns: "doc".into(),
            obj: "1".into(),
            rel: "viewer".into(),
            user_id: "u1".into(),
            ts: "AQAAAAAAAA==".into(),
        }]
    );
}

#[tokio::test]
async fn check_passes_explicit_timestamp() {
    let (mock, uri) = start_mock().await;
    mock.lock().check_response = Some(wire::CheckResponse {
        principal: Some(wire::Principal { id: "p-1".into() }),
        ok: true,
    });
    let mut c = client(uri).await;
    c.check(
        Namespace("doc".into()),
        Obj("1".into()),
        Rel::viewer(),
        UserId("u1".into()),
        Some(Timestamp("zookie-1".into())),
    )
    .await
    .expect("check");
    assert_eq!(mock.lock().check_requests[0].ts, "zookie-1");
}

#[tokio::test]
async fn check_forbidden_and_unknown_user() {
    let (mock, uri) = start_mock().await;
    mock.lock().check_response = Some(wire::CheckResponse {
        principal: Some(wire::Principal { id: "p-1".into() }),
        ok: false,
    });
    let mut c = client(uri).await;
    let res = c
        .check(
            Namespace("doc".into()),
            Obj("1".into()),
            Rel::viewer(),
            UserId("u1".into()),
            None,
        )
        .await
        .expect("check");
    assert!(matches!(res, CheckResult::Forbidden(p) if p.as_str() == "p-1"));

    mock.lock().check_response = Some(wire::CheckResponse {
        principal: None,
        ok: false,
    });
    let res = c
        .check(
            Namespace("doc".into()),
            Obj("1".into()),
            Rel::viewer(),
            UserId("nobody".into()),
            None,
        )
        .await
        .expect("check");
    assert!(matches!(res, CheckResult::UnknownPutativeUser));
}

#[tokio::test]
async fn check_ok_without_principal_is_error() {
    let (mock, uri) = start_mock().await;
    mock.lock().check_response = Some(wire::CheckResponse {
        principal: None,
        ok: true,
    });
    let mut c = client(uri).await;
    let err = c
        .check(
            Namespace("doc".into()),
            Obj("1".into()),
            Rel::viewer(),
            UserId("u1".into()),
            None,
        )
        .await
        .expect_err("ok without principal must be an error");
    assert!(matches!(
        err,
        nio_client::auth::CallError::UnexpectedResponseFormat
    ));
}

#[tokio::test]
async fn check_impossible_short_circuits_without_rpc() {
    let (mock, uri) = start_mock().await;
    let mut c = client(uri).await;
    let res = c
        .check(
            Namespace("doc".into()),
            Obj("1".into()),
            Rel::impossible(),
            UserId("u1".into()),
            None,
        )
        .await
        .expect("check");
    assert!(matches!(res, CheckResult::Forbidden(p) if p.as_str().is_empty()));
    assert!(mock.lock().check_requests.is_empty(), "no RPC must be made");
}

#[tokio::test]
async fn observe_check_reports_outcome_and_errors() {
    let (mock, uri) = start_mock().await;
    mock.lock().check_response = Some(wire::CheckResponse {
        principal: Some(wire::Principal { id: "p-1".into() }),
        ok: true,
    });
    let observed_ok = Arc::new(AtomicBool::new(false));
    let observed_err = Arc::new(AtomicBool::new(false));
    let (ok_flag, err_flag) = (observed_ok.clone(), observed_err.clone());
    let mut c = client(uri).await.with_observe_check(Arc::new(
        move |_ns, _obj, _rel, _user, _duration, ok, is_error| {
            ok_flag.store(ok, Ordering::Relaxed);
            err_flag.store(is_error, Ordering::Relaxed);
        },
    ));
    c.check(
        Namespace("doc".into()),
        Obj("1".into()),
        Rel::viewer(),
        UserId("u1".into()),
        None,
    )
    .await
    .expect("check");
    assert!(observed_ok.load(Ordering::Relaxed));
    assert!(!observed_err.load(Ordering::Relaxed));

    mock.lock().check_fail_next = true;
    let _ = c
        .check(
            Namespace("doc".into()),
            Obj("1".into()),
            Rel::viewer(),
            UserId("u1".into()),
            None,
        )
        .await
        .expect_err("must fail");
    assert!(observed_err.load(Ordering::Relaxed));
}

#[tokio::test]
async fn list_returns_snapshot_ts_and_objs() {
    let (mock, uri) = start_mock().await;
    mock.lock().list_response = Some(wire::ListResponse {
        objs: vec!["a".into(), "b".into()],
        ts: "eval-ts".into(),
    });
    let mut c = client(uri).await;
    let res = c
        .list(
            Namespace("doc".into()),
            Rel::viewer(),
            UserId("u1".into()),
            None,
        )
        .await
        .expect("list");
    assert_eq!(res.ts.0, "eval-ts");
    assert_eq!(res.objs, vec!["a".to_string(), "b".to_string()]);
    assert_eq!(
        mock.lock().list_requests[0],
        wire::ListRequest {
            ns: "doc".into(),
            rel: "viewer".into(),
            user_id: "u1".into(),
            ts: "AQAAAAAAAA==".into(),
        }
    );
}

#[tokio::test]
async fn expand_maps_user_ids_and_usersets() {
    let (mock, uri) = start_mock().await;
    mock.lock().expand_response = Some(wire::ExpandResponse {
        ts: "eval-ts".into(),
        user_ids: vec!["u1".into(), "u2".into()],
        usersets: vec![wire::UserSet {
            ns: "grp".into(),
            obj: "eng".into(),
            rel: "member".into(),
        }],
    });
    let mut c = client(uri).await;
    let res = c
        .expand(
            Namespace("doc".into()),
            Obj("1".into()),
            Rel::viewer(),
            None,
        )
        .await
        .expect("expand");
    assert_eq!(res.ts.0, "eval-ts");
    assert_eq!(res.user_ids, vec!["u1".to_string(), "u2".to_string()]);
    assert_eq!(
        res.usersets,
        vec![UserSet {
            ns: Namespace("grp".into()),
            obj: Obj("eng".into()),
            rel: Rel("member".into()),
        }]
    );
    assert_eq!(
        mock.lock().expand_requests[0],
        wire::ExpandRequest {
            ns: "doc".into(),
            obj: "1".into(),
            rel: "viewer".into(),
            ts: "AQAAAAAAAA==".into(),
        }
    );
}

#[tokio::test]
async fn content_change_check_maps_ok_and_ts() {
    let (mock, uri) = start_mock().await;
    mock.lock().ccc_response = Some(wire::ContentChangeCheckResponse {
        ok: true,
        ts: "content-ts".into(),
    });
    let mut c = client(uri).await;
    let res = c
        .content_change_check(
            Namespace("doc".into()),
            Obj("1".into()),
            Rel::editor(),
            UserId("u1".into()),
        )
        .await
        .expect("content change check");
    assert!(res.ok);
    assert_eq!(res.ts.0, "content-ts");
    assert_eq!(
        mock.lock().ccc_requests[0],
        wire::ContentChangeCheckRequest {
            ns: "doc".into(),
            obj: "1".into(),
            rel: "editor".into(),
            user_id: "u1".into(),
        }
    );
}

#[tokio::test]
async fn read_sends_filters_and_maps_tuples() {
    let (mock, uri) = start_mock().await;
    mock.lock().read_response = Some(wire::ReadResponse {
        ts: "read-ts".into(),
        tuples: vec![
            wire::Tuple {
                ns: "doc".into(),
                obj: "1".into(),
                rel: "viewer".into(),
                user: Some(wire::tuple::User::UserId("u1".into())),
                condition: Some(wire::tuple::Condition::Expires(1894785600)),
            },
            wire::Tuple {
                ns: "doc".into(),
                obj: "1".into(),
                rel: "viewer".into(),
                user: Some(wire::tuple::User::UserSet(wire::UserSet {
                    ns: "grp".into(),
                    obj: "eng".into(),
                    rel: "member".into(),
                })),
                condition: None,
            },
        ],
    });
    let mut c = client(uri).await;
    let res = c
        .read(vec![
            ReadFilter::by_object(Namespace("doc".into()), Obj("1".into()), None),
            ReadFilter::by_user(
                Namespace("doc".into()),
                UserId("u1".into()),
                Some(Rel::viewer()),
            ),
            ReadFilter::by_user_set(
                Namespace("doc".into()),
                UserSet {
                    ns: Namespace("grp".into()),
                    obj: Obj("eng".into()),
                    rel: Rel("member".into()),
                },
                None,
            ),
        ])
        .await
        .expect("read");

    assert_eq!(res.ts.0, "read-ts");
    assert_eq!(res.tuples.len(), 2);
    assert!(matches!(res.tuples[0].sbj, User::UserId(ref u) if u == "u1"));
    assert!(matches!(
        res.tuples[0].condition,
        Some(nio_client::Condition::Expires(dt)) if dt.timestamp() == 1894785600
    ));
    assert!(matches!(res.tuples[1].sbj, User::UserSet { ref ns, .. } if ns.0 == "grp"));

    let req = mock.lock().read_requests[0].clone();
    assert_eq!(req.ts, None, "empty ts must be omitted on the wire");
    assert_eq!(req.tuple_sets.len(), 3);
    assert!(matches!(
        req.tuple_sets[0].spec,
        Some(wire::tuple_set::Spec::ObjectSpec(ref os)) if os.obj == "1" && os.rel.is_none()
    ));
    match &req.tuple_sets[1].spec {
        Some(wire::tuple_set::Spec::UsersetSpec(us)) => {
            assert!(matches!(
                us.user,
                Some(wire::tuple_set::user_set_spec::User::UserId(ref u)) if u == "u1"
            ));
            assert_eq!(us.rel.as_deref(), Some("viewer"));
        }
        other => panic!("expected userset spec, got {other:?}"),
    }
    match &req.tuple_sets[2].spec {
        Some(wire::tuple_set::Spec::UsersetSpec(us)) => {
            assert!(matches!(
                us.user,
                Some(wire::tuple_set::user_set_spec::User::UserSet(ref set)) if set.ns == "grp"
            ));
        }
        other => panic!("expected userset spec, got {other:?}"),
    }
}

#[tokio::test]
async fn read_with_timestamp_sets_ts() {
    let (mock, uri) = start_mock().await;
    let mut c = client(uri).await;
    c.read_with_timestamp(
        Timestamp("zookie-7".into()),
        vec![ReadFilter::by_object(
            Namespace("doc".into()),
            Obj("1".into()),
            None,
        )],
    )
    .await
    .expect("read");
    assert_eq!(mock.lock().read_requests[0].ts.as_deref(), Some("zookie-7"));
}

#[tokio::test]
async fn read_requires_at_least_one_filter() {
    let (mock, uri) = start_mock().await;
    let mut c = client(uri).await;
    c.read(vec![]).await.expect_err("empty filters must fail");
    assert!(mock.lock().read_requests.is_empty());
}

#[tokio::test]
async fn get_all_and_get_all_rel_filter_by_object() {
    let (mock, uri) = start_mock().await;
    let mut c = client(uri).await;
    let ns = Namespace("doc".into());
    let obj = Obj("1".into());
    c.get_all(&ns, &obj).await.expect("get_all");
    c.get_all_rel(&ns, &obj, &Rel::viewer())
        .await
        .expect("get_all_rel");
    let reqs = mock.lock().read_requests.clone();
    assert!(matches!(
        reqs[0].tuple_sets[0].spec,
        Some(wire::tuple_set::Spec::ObjectSpec(ref os)) if os.rel.is_none()
    ));
    assert!(matches!(
        reqs[1].tuple_sets[0].spec,
        Some(wire::tuple_set::Spec::ObjectSpec(ref os)) if os.rel.as_deref() == Some("viewer")
    ));
}

#[tokio::test]
async fn write_sends_add_del_and_precondition() {
    let (mock, uri) = start_mock().await;
    mock.lock().write_response = Some(wire::WriteResponse {
        ts: "commit-ts".into(),
    });
    let mut c = client(uri).await;
    let exp = chrono::DateTime::from_timestamp(1894785600, 0).unwrap();
    let ts = c
        .write(
            vec![Tuple::new(
                Namespace("doc".into()),
                Obj("1".into()),
                Rel::viewer(),
                User::UserId("u1".into()),
            )
            .with_expires(exp)],
            vec![Tuple::new(
                Namespace("doc".into()),
                Obj("1".into()),
                Rel::editor(),
                User::UserSet {
                    ns: Namespace("grp".into()),
                    obj: Obj("eng".into()),
                    rel: Rel("member".into()),
                },
            )],
            Some(Timestamp("occ-ts".into())),
        )
        .await
        .expect("write");
    assert_eq!(ts, Timestamp("commit-ts".into()));

    let req = mock.lock().write_requests[0].clone();
    assert_eq!(req.ts.as_deref(), Some("occ-ts"));
    assert_eq!(req.add_tuples.len(), 1);
    assert_eq!(req.del_tuples.len(), 1);
    assert!(matches!(
        req.add_tuples[0].condition,
        Some(wire::tuple::Condition::Expires(1894785600))
    ));
    assert!(matches!(
        req.del_tuples[0].user,
        Some(wire::tuple::User::UserSet(ref us)) if us.ns == "grp"
    ));
}

#[tokio::test]
async fn add_one_and_delete_one_return_commit_zookie() {
    let (mock, uri) = start_mock().await;
    mock.lock().write_response = Some(wire::WriteResponse {
        ts: "commit-ts".into(),
    });
    let mut c = client(uri).await;
    let tuple = Tuple::new(
        Namespace("doc".into()),
        Obj("1".into()),
        Rel::viewer(),
        User::UserId("u1".into()),
    );
    let ts = c.add_one(tuple.clone()).await.expect("add_one");
    assert_eq!(ts.0, "commit-ts");
    let ts = c.delete_one(tuple).await.expect("delete_one");
    assert_eq!(ts.0, "commit-ts");

    let reqs = mock.lock().write_requests.clone();
    assert_eq!(reqs[0].add_tuples.len(), 1);
    assert!(reqs[0].del_tuples.is_empty());
    assert!(reqs[1].add_tuples.is_empty());
    assert_eq!(reqs[1].del_tuples.len(), 1);
    assert_eq!(reqs[0].ts, None, "unconditional write must omit ts");
}

#[tokio::test]
async fn add_parent_writes_parent_pointer() {
    let (mock, uri) = start_mock().await;
    let mut c = client(uri).await;
    c.add_parent(
        Namespace("doc".into()),
        Obj("1".into()),
        Namespace("folder".into()),
        Obj("f1".into()),
    )
    .await
    .expect("add_parent");
    let req = mock.lock().write_requests[0].clone();
    let tuple = &req.add_tuples[0];
    assert_eq!(tuple.rel, "parent");
    match &tuple.user {
        Some(wire::tuple::User::UserSet(us)) => {
            assert_eq!(us.ns, "folder");
            assert_eq!(us.obj, "f1");
            assert_eq!(us.rel, "...");
        }
        other => panic!("expected userset, got {other:?}"),
    }
}

#[tokio::test]
async fn watch_streams_heartbeats_and_atomic_writes() {
    let (mock, uri) = start_mock().await;
    mock.lock().watch_responses = vec![
        wire::WatchResponse {
            ts: "hb-1".into(),
            updates: vec![],
        },
        wire::WatchResponse {
            ts: "commit-1".into(),
            updates: vec![
                wire::Update {
                    tuple: Some(wire::Tuple {
                        ns: "doc".into(),
                        obj: "1".into(),
                        rel: "viewer".into(),
                        user: Some(wire::tuple::User::UserId("u1".into())),
                        condition: None,
                    }),
                    deleted: false,
                },
                wire::Update {
                    tuple: Some(wire::Tuple {
                        ns: "doc".into(),
                        obj: "1".into(),
                        rel: "editor".into(),
                        user: Some(wire::tuple::User::UserId("u1".into())),
                        condition: None,
                    }),
                    deleted: true,
                },
            ],
        },
    ];
    let mut c = client(uri).await;
    let mut stream = c
        .watch(Namespace("doc".into()), Timestamp("resume-ts".into()))
        .await
        .expect("watch");

    let hb = stream.recv().await.expect("recv").expect("heartbeat");
    assert_eq!(hb.ts.0, "hb-1");
    assert!(hb.updates.is_empty());

    let ev = stream.recv().await.expect("recv").expect("write event");
    assert_eq!(ev.ts.0, "commit-1");
    assert_eq!(ev.updates.len(), 2);
    assert!(!ev.updates[0].deleted);
    assert!(ev.updates[1].deleted);

    assert!(stream.recv().await.expect("recv").is_none(), "clean end");

    assert_eq!(
        mock.lock().watch_requests[0],
        wire::WatchRequest {
            ns: "doc".into(),
            start_ts: "resume-ts".into(),
        }
    );
}

#[tokio::test]
async fn list_namespaces_maps_schema_metadata() {
    let (mock, uri) = start_mock().await;
    mock.lock().namespaces = vec![wire::NamespaceMeta {
        name: "doc".into(),
        relations: vec![wire::RelationMeta {
            name: "viewer".into(),
            kind: "union".into(),
        }],
    }];
    let mut c = client(uri).await;
    let namespaces = c.list_namespaces().await.expect("list namespaces");
    assert_eq!(namespaces.len(), 1);
    assert_eq!(namespaces[0].name, "doc");
    assert_eq!(namespaces[0].relations[0].name, "viewer");
    assert_eq!(namespaces[0].relations[0].kind, "union");
}

fn session_outcome(principal: &str, expires_in_secs: i64) -> wire::ResolveResponse {
    wire::ResolveResponse {
        outcome: Some(wire::resolve_response::Outcome::Session(wire::Session {
            principal: principal.into(),
            expires_at_unix_seconds: chrono::Utc::now().timestamp() + expires_in_secs,
            tenant_id: "t1".into(),
        })),
    }
}

#[tokio::test]
async fn grpc_session_resolver_resolves_and_caches() {
    let (mock, uri) = start_mock().await;
    mock.lock().resolve_response = Some(session_outcome("p-1", 3600));
    let channel = connect_channel(uri, None).await.expect("connect");
    let resolver = GrpcSessionResolver::new(channel, ResolverConfig::default());

    let hash = nio_client::session::token_hash("raw-token");
    let session = resolver
        .resolve(&hash)
        .await
        .expect("resolve")
        .expect("session found");
    assert_eq!(session.principal, "p-1");
    assert_eq!(session.tenant_id, "t1");

    // Cached: no second RPC.
    let _ = resolver.resolve(&hash).await.expect("resolve");
    let reqs = mock.lock().resolve_requests.clone();
    assert_eq!(reqs.len(), 1, "second resolve must be served from L1");
    assert_eq!(
        reqs[0].token_hash, hash,
        "only the hash travels on the wire"
    );

    // Evict forces a refetch.
    resolver.evict(&hash);
    let _ = resolver.resolve(&hash).await.expect("resolve");
    assert_eq!(mock.lock().resolve_requests.len(), 2);
}

#[tokio::test]
async fn grpc_session_resolver_not_found_is_none() {
    let (_mock, uri) = start_mock().await;
    let channel = connect_channel(uri, None).await.expect("connect");
    let resolver = GrpcSessionResolver::new(channel, ResolverConfig::default());
    let outcome = resolver.resolve("deadbeef").await.expect("resolve");
    assert!(
        outcome.is_none(),
        "not_found must be Ok(None), not an error"
    );
}

#[tokio::test]
async fn memo_dedupes_identical_checks() {
    let (mock, uri) = start_mock().await;
    mock.lock().check_response = Some(wire::CheckResponse {
        principal: Some(wire::Principal { id: "p-1".into() }),
        ok: true,
    });
    let hits = Arc::new(AtomicUsize::new(0));
    let misses = Arc::new(AtomicUsize::new(0));
    let (h, m) = (hits.clone(), misses.clone());
    let memo = RequestMemo::new(client(uri).await).with_observer(Arc::new(move |_op, hit| {
        if hit {
            h.fetch_add(1, Ordering::Relaxed);
        } else {
            m.fetch_add(1, Ordering::Relaxed);
        }
    }));

    let ns = Namespace("doc".into());
    let obj = Obj("1".into());
    let first = memo
        .check(ns.clone(), obj.clone(), Rel::viewer(), UserId("u1".into()))
        .await
        .expect("check");
    assert!(first.is_ok());
    let second = memo
        .check(ns.clone(), obj.clone(), Rel::viewer(), UserId("u1".into()))
        .await
        .expect("check");
    assert!(second.is_ok());
    // Different key: goes to the server.
    memo.check(ns.clone(), obj.clone(), Rel::editor(), UserId("u1".into()))
        .await
        .expect("check");

    assert_eq!(
        mock.lock().check_requests.len(),
        2,
        "identical checks must collapse to one RPC"
    );
    assert_eq!(hits.load(Ordering::Relaxed), 1);
    assert_eq!(misses.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn memo_never_caches_errors() {
    let (mock, uri) = start_mock().await;
    mock.lock().check_response = Some(wire::CheckResponse {
        principal: Some(wire::Principal { id: "p-1".into() }),
        ok: true,
    });
    mock.lock().check_fail_next = true;
    let memo = RequestMemo::new(client(uri).await);

    let ns = Namespace("doc".into());
    let obj = Obj("1".into());
    memo.check(ns.clone(), obj.clone(), Rel::viewer(), UserId("u1".into()))
        .await
        .expect_err("first call fails");
    let res = memo
        .check(ns.clone(), obj.clone(), Rel::viewer(), UserId("u1".into()))
        .await
        .expect("second call retries and succeeds");
    assert!(res.is_ok());
    assert_eq!(mock.lock().check_requests.len(), 2);
}

#[tokio::test]
async fn memo_dedupes_identical_lists_and_fixes_timestamp() {
    let (mock, uri) = start_mock().await;
    mock.lock().list_response = Some(wire::ListResponse {
        objs: vec!["a".into()],
        ts: "eval-ts".into(),
    });
    let memo =
        RequestMemo::new(client(uri).await).with_timestamp(Some(Timestamp("pinned-ts".into())));

    let ns = Namespace("doc".into());
    let first = memo
        .list(ns.clone(), Rel::viewer(), UserId("u1".into()))
        .await
        .expect("list");
    assert_eq!(first.objs, vec!["a".to_string()]);
    let _ = memo
        .list(ns.clone(), Rel::viewer(), UserId("u1".into()))
        .await
        .expect("list");

    let reqs = mock.lock().list_requests.clone();
    assert_eq!(reqs.len(), 1, "identical lists must collapse to one RPC");
    assert_eq!(reqs[0].ts, "pinned-ts");
}

#[tokio::test]
async fn memo_concurrent_identical_misses_single_flight() {
    let (mock, uri) = start_mock().await;
    mock.lock().check_response = Some(wire::CheckResponse {
        principal: Some(wire::Principal { id: "p-1".into() }),
        ok: true,
    });
    let memo = Arc::new(RequestMemo::new(client(uri).await));

    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let memo = memo.clone();
            tokio::spawn(async move {
                memo.check(
                    Namespace("doc".into()),
                    Obj("1".into()),
                    Rel::viewer(),
                    UserId("u1".into()),
                )
                .await
            })
        })
        .collect();
    for t in tasks {
        assert!(t.await.expect("join").expect("check").is_ok());
    }
    assert_eq!(
        mock.lock().check_requests.len(),
        1,
        "concurrent identical misses must coalesce into one RPC"
    );
}

#[tokio::test]
async fn observe_list_reports_outcome_and_errors() {
    let (mock, uri) = start_mock().await;
    mock.lock().list_response = Some(wire::ListResponse {
        objs: vec![],
        ts: "t".into(),
    });
    let observed = Arc::new(AtomicUsize::new(0));
    let errored = Arc::new(AtomicBool::new(false));
    let (obs, err_flag) = (observed.clone(), errored.clone());
    let mut c = client(uri).await.with_observe_list(Arc::new(
        move |_ns, _rel, _user, _duration, is_error| {
            obs.fetch_add(1, Ordering::Relaxed);
            err_flag.store(is_error, Ordering::Relaxed);
        },
    ));
    c.list(
        Namespace("doc".into()),
        Rel::viewer(),
        UserId("u1".into()),
        None,
    )
    .await
    .expect("list");
    assert_eq!(observed.load(Ordering::Relaxed), 1);
    assert!(!errored.load(Ordering::Relaxed));

    mock.lock().list_fail_next = true;
    let _ = c
        .list(
            Namespace("doc".into()),
            Rel::viewer(),
            UserId("u1".into()),
            None,
        )
        .await
        .expect_err("must fail");
    assert_eq!(observed.load(Ordering::Relaxed), 2);
    assert!(errored.load(Ordering::Relaxed));
}

#[tokio::test]
async fn read_by_user_and_user_set_send_reverse_filters() {
    let (mock, uri) = start_mock().await;
    let mut c = client(uri).await;
    let ns = Namespace("doc".into());
    c.read_by_user(&ns, &UserId("u1".into()), Some(Rel::viewer()))
        .await
        .expect("read_by_user");
    c.read_by_user_set(
        &ns,
        &UserSet {
            ns: Namespace("grp".into()),
            obj: Obj("eng".into()),
            rel: Rel("member".into()),
        },
        None,
    )
    .await
    .expect("read_by_user_set");

    let reqs = mock.lock().read_requests.clone();
    match &reqs[0].tuple_sets[0].spec {
        Some(wire::tuple_set::Spec::UsersetSpec(us)) => {
            assert!(matches!(
                us.user,
                Some(wire::tuple_set::user_set_spec::User::UserId(ref u)) if u == "u1"
            ));
            assert_eq!(us.rel.as_deref(), Some("viewer"));
        }
        other => panic!("expected userset spec, got {other:?}"),
    }
    match &reqs[1].tuple_sets[0].spec {
        Some(wire::tuple_set::Spec::UsersetSpec(us)) => {
            assert!(matches!(
                us.user,
                Some(wire::tuple_set::user_set_spec::User::UserSet(ref s)) if s.ns == "grp"
            ));
        }
        other => panic!("expected userset spec, got {other:?}"),
    }
}

#[tokio::test]
async fn add_many_commits_one_atomic_write() {
    let (mock, uri) = start_mock().await;
    mock.lock().write_response = Some(wire::WriteResponse {
        ts: "commit-ts".into(),
    });
    let mut c = client(uri).await;
    let t1 = Tuple::new(
        Namespace("doc".into()),
        Obj("1".into()),
        Rel::viewer(),
        User::UserId("u1".into()),
    );
    let t2 = Tuple::new(
        Namespace("doc".into()),
        Obj("1".into()),
        Rel::editor(),
        User::UserId("u2".into()),
    );
    let ts = c.add_many(vec![t1, t2]).await.expect("add_many");
    assert_eq!(ts.0, "commit-ts");
    let reqs = mock.lock().write_requests.clone();
    assert_eq!(reqs.len(), 1, "one atomic write");
    assert_eq!(reqs[0].add_tuples.len(), 2);
}

// End-to-end coverage of the axum auth extractors against the in-process
// mock — the Rust counterpart of nioclient-go's wrap_test.go.
#[cfg(feature = "axum")]
mod axum_extractors {
    use super::*;
    use axum::extract::FromRequestParts;
    use axum::http::request::Parts;
    use axum::http::Method;
    use nio_client::axum::{
        AuthState, Authenticated, BearerTokenAuth, WebResource, WebResourceError, WithOptPrincipal,
        WithPrincipal,
    };
    use nio_client::session::{token_hash, GrpcSessionResolver, ResolverConfig};

    struct DocResource;

    impl WebResource for DocResource {
        type Rejection = std::convert::Infallible;

        fn namespace(&self) -> Namespace {
            Namespace("doc".into())
        }
        fn rel(&self, _method: &Method) -> Option<Rel> {
            Some(Rel::viewer())
        }
        async fn parse<S: Send + Sync>(
            _parts: &mut Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            Ok(DocResource)
        }
        fn object(&self) -> Obj {
            Obj("1".into())
        }
    }

    async fn auth_state(uri: Uri, prefix: Option<&str>) -> AuthState {
        let check_client = client(uri.clone()).await;
        let channel = connect_channel(uri, None).await.expect("connect");
        let resolver = GrpcSessionResolver::new(channel, ResolverConfig::default());
        AuthState::new(check_client, resolver, prefix)
    }

    fn parts_with_headers(headers: &[(&str, &str)]) -> Parts {
        let mut builder = axum::http::Request::builder().uri("/docs/1?x=1");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let (parts, _) = builder.body(()).unwrap().into_parts();
        parts
    }

    #[tokio::test]
    async fn cookie_auth_checks_resolved_principal_not_raw_token() {
        let (mock, uri) = start_mock().await;
        mock.lock().resolve_response = Some(session_outcome("p-uuid", 3600));
        mock.lock().check_response = Some(wire::CheckResponse {
            principal: Some(wire::Principal {
                id: "p-uuid".into(),
            }),
            ok: true,
        });
        let state = auth_state(uri, None).await;
        let mut parts = parts_with_headers(&[("cookie", "session=raw-token")]);
        let got = WithPrincipal::<DocResource>::from_request_parts(&mut parts, &state)
            .await
            .expect("authorized");
        assert_eq!(got.principal.as_str(), "p-uuid");

        let reqs = mock.lock().check_requests.clone();
        assert_eq!(reqs.len(), 1);
        assert_eq!(
            reqs[0].user_id, "p-uuid",
            "check must see the resolved principal, never the raw token"
        );
        assert_eq!(
            mock.lock().resolve_requests[0].token_hash,
            token_hash("raw-token"),
            "only the token hash may travel on the wire"
        );
    }

    #[tokio::test]
    async fn unknown_token_redirects_to_signin_without_check() {
        let (mock, uri) = start_mock().await; // default resolve outcome: NotFound
        let state = auth_state(uri, Some("/app")).await;
        let mut parts = parts_with_headers(&[("cookie", "session=unknown")]);
        let err = match WithPrincipal::<DocResource>::from_request_parts(&mut parts, &state).await {
            Ok(_) => panic!("unknown token must reject"),
            Err(err) => err,
        };
        match err {
            WebResourceError::MissingSession(loc) => {
                assert!(loc.starts_with("/app/signin?back="), "loc={loc}");
            }
            other => panic!("expected MissingSession, got {other:?}"),
        }
        assert!(mock.lock().check_requests.is_empty(), "zero check RPCs");
    }

    #[tokio::test]
    async fn resolver_fault_is_internal_error_without_check() {
        let (mock, uri) = start_mock().await;
        mock.lock().resolve_fail_next = true;
        let state = auth_state(uri, None).await;
        let mut parts = parts_with_headers(&[("cookie", "session=tok")]);
        let err = match WithPrincipal::<DocResource>::from_request_parts(&mut parts, &state).await {
            Ok(_) => panic!("resolver fault must reject"),
            Err(err) => err,
        };
        assert!(matches!(err, WebResourceError::InternalServerError(_)));
        assert!(mock.lock().check_requests.is_empty(), "zero check RPCs");
    }

    #[tokio::test]
    async fn opt_principal_without_cookie_is_none_without_rpcs() {
        let (mock, uri) = start_mock().await;
        let state = auth_state(uri, None).await;
        let mut parts = parts_with_headers(&[]);
        let got = WithOptPrincipal::<DocResource>::from_request_parts(&mut parts, &state)
            .await
            .expect("public access");
        assert!(got.principal.is_none());
        assert!(mock.lock().check_requests.is_empty());
        assert!(mock.lock().resolve_requests.is_empty());
    }

    #[tokio::test]
    async fn bearer_auth_resolves_and_checks() {
        let (mock, uri) = start_mock().await;
        mock.lock().resolve_response = Some(session_outcome("p-uuid", 3600));
        mock.lock().check_response = Some(wire::CheckResponse {
            principal: Some(wire::Principal {
                id: "p-uuid".into(),
            }),
            ok: true,
        });
        let state = auth_state(uri, None).await;
        let mut parts = parts_with_headers(&[("authorization", "Bearer api-token")]);
        let got =
            WithPrincipal::<DocResource, BearerTokenAuth>::from_request_parts(&mut parts, &state)
                .await
                .expect("authorized");
        assert_eq!(got.principal.as_str(), "p-uuid");
        assert_eq!(
            mock.lock().resolve_requests[0].token_hash,
            token_hash("api-token")
        );
    }

    #[tokio::test]
    async fn forbidden_check_is_forbidden() {
        let (mock, uri) = start_mock().await;
        mock.lock().resolve_response = Some(session_outcome("p-uuid", 3600));
        mock.lock().check_response = Some(wire::CheckResponse {
            principal: Some(wire::Principal {
                id: "p-uuid".into(),
            }),
            ok: false,
        });
        let state = auth_state(uri, None).await;
        let mut parts = parts_with_headers(&[("cookie", "session=tok")]);
        let err = match WithPrincipal::<DocResource>::from_request_parts(&mut parts, &state).await {
            Ok(_) => panic!("forbidden check must reject"),
            Err(err) => err,
        };
        assert!(matches!(err, WebResourceError::Forbidden));
    }

    #[tokio::test]
    async fn authenticated_yields_principal_without_check() {
        let (mock, uri) = start_mock().await;
        mock.lock().resolve_response = Some(session_outcome("p-uuid", 3600));
        let state = auth_state(uri, None).await;
        let mut parts = parts_with_headers(&[("authorization", "Bearer api-token")]);
        let got = Authenticated::<BearerTokenAuth>::from_request_parts(&mut parts, &state)
            .await
            .expect("authenticated");
        assert_eq!(got.principal.0, "p-uuid");
        assert!(mock.lock().check_requests.is_empty(), "no check RPC");
    }
}
