//! Request-scoped memoization of check and list decisions — the port of
//! nioclient-go's request memo (option 1 of the client-cache design).
//!
//! Within the lifetime of a single HTTP request, identical check/list
//! questions are answered from an in-request map instead of re-calling check
//! over gRPC. A handler that runs many check/list calls for the same subject
//! collapses to far fewer round-trips.
//!
//! This is SAFE with respect to staleness: a request is one logical instant,
//! so asking the same authorization question twice within it must yield the
//! same answer. The one caveat is read-after-write WITHIN a request — a
//! handler that writes a tuple and then re-checks expecting to observe its
//! own write must not use the memo.
//!
//! Concurrent identical misses are coalesced (per-key single flight), so a
//! handler that fans checks out across tasks still issues one RPC per key.
//! Errors are never cached.

use crate::auth::{CallError, CheckResult};
use crate::{CheckClient, ListResult, Namespace, Obj, Rel, Timestamp, UserId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;

type CheckKey = (String, String, String, String);
type ListKey = (String, String, String);

pub type MemoObserveFn = Arc<dyn Fn(&str, bool) + Send + Sync>;

/// Memoizes check and list decisions for the lifetime of one request. Create
/// one per request; drop it when the request ends. The timestamp is fixed for
/// the whole request (see [`Self::with_timestamp`]), so it is not part of the
/// keys.
pub struct RequestMemo {
    client: CheckClient,
    ts: Option<Timestamp>,
    checks: Mutex<HashMap<CheckKey, Arc<OnceCell<CheckResult>>>>,
    lists: Mutex<HashMap<ListKey, Arc<OnceCell<ListResult>>>>,
    observe: Option<MemoObserveFn>,
}

impl RequestMemo {
    pub fn new(client: CheckClient) -> Self {
        RequestMemo {
            client,
            ts: None,
            checks: Mutex::new(HashMap::new()),
            lists: Mutex::new(HashMap::new()),
            observe: None,
        }
    }

    /// Fixes the evaluation zookie used for every memoized check/list of this
    /// request (e.g. from a `check_ts` cookie). `None` accepts any current
    /// snapshot.
    pub fn with_timestamp(mut self, ts: Option<Timestamp>) -> Self {
        self.ts = ts;
        self
    }

    /// Reports each lookup to `f`: op is `"check"` or `"list"`; hit is true
    /// when the answer was served from the in-request cache.
    pub fn with_observer(mut self, f: MemoObserveFn) -> Self {
        self.observe = Some(f);
        self
    }

    fn report(&self, op: &str, hit: bool) {
        if let Some(observe) = &self.observe {
            observe(op, hit);
        }
    }

    pub async fn check(
        &self,
        ns: Namespace,
        obj: Obj,
        rel: Rel,
        user_id: UserId,
    ) -> Result<CheckResult, CallError> {
        let key = (
            ns.0.clone(),
            obj.0.clone(),
            rel.0.clone(),
            user_id.0.clone(),
        );
        let cell = {
            let mut map = self.checks.lock().expect("memo mutex poisoned");
            map.entry(key).or_default().clone()
        };
        self.report("check", cell.initialized());
        let result = cell
            .get_or_try_init(|| {
                let mut client = self.client.clone();
                let ts = self.ts.clone();
                async move { client.check(ns, obj, rel, user_id, ts).await }
            })
            .await?;
        Ok(result.clone())
    }

    pub async fn list(
        &self,
        ns: Namespace,
        rel: Rel,
        user_id: UserId,
    ) -> Result<ListResult, CallError> {
        let key = (ns.0.clone(), rel.0.clone(), user_id.0.clone());
        let cell = {
            let mut map = self.lists.lock().expect("memo mutex poisoned");
            map.entry(key).or_default().clone()
        };
        self.report("list", cell.initialized());
        let result = cell
            .get_or_try_init(|| {
                let mut client = self.client.clone();
                let ts = self.ts.clone();
                async move { client.list(ns, rel, user_id, ts).await }
            })
            .await?;
        Ok(result.clone())
    }
}
