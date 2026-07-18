//! Token -> principal resolution with an L1 cache tier — the port of the
//! normative resolver in nio's `check_client/src/session.rs` (issue #243/#245).
//!
//! An opaque session token is hashed in-process (`sha256`, hex) — the raw
//! token never leaves the process — and resolved to
//! `{principal, tenant_id, expires_at}` over `am.SessionService` on
//! nio-client. The cache is LRU-bounded with a positive TTL carrying
//! *downward-only* jitter (so the TTL is a hard staleness/revocation cap),
//! negative tombstones for unknown tokens, single-flight coalescing of
//! concurrent misses, refresh-ahead for hot entries, and an opt-in
//! stale-if-error window.

use crate::pb::session_service_client::SessionServiceClient;
use crate::pb::{resolve_response, ResolveRequest};
use chrono::{DateTime, Utc};
use futures::future::{BoxFuture, FutureExt, Shared};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tonic::transport::Channel;

/// Bounds a single fill's fetch (Go: resolveTimeout). The fill runs on a
/// detached task so one caller cancelling does not poison coalesced waiters;
/// an elapsed timeout classifies as a transport error (stale-if-error
/// eligible).
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// `hex(sha256(raw_token))` — the 64-char lowercase cache/wire key. The raw
/// token is never stored or transmitted; only this hash is.
pub fn token_hash(raw_token: &str) -> String {
    let digest = Sha256::digest(raw_token.as_bytes());
    hex::encode(digest)
}

/// Newtype wrapper around [`token_hash`] for call sites that prefer a type.
pub struct TokenHash(pub String);

impl TokenHash {
    pub fn from_raw(raw_token: &str) -> Self {
        TokenHash(token_hash(raw_token))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A resolved session: the principal UUID, its tenant, and the wall-clock
/// instant the session stops being valid.
#[derive(Clone, Debug)]
pub struct ResolvedSession {
    pub principal: String,
    pub tenant_id: String,
    pub expires_at: DateTime<Utc>,
}

/// A resolution failure. `not_found` is *not* an error — it is `Ok(None)`.
/// Only genuine faults (transport, backend) are errors; `Transport` marks the
/// class eligible for stale-if-error fallback.
#[derive(Clone, Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("session resolve transport error: {0}")]
    Transport(String),
    #[error("session resolve backend error: {0}")]
    Backend(String),
}

impl ResolveError {
    fn is_transport(&self) -> bool {
        matches!(self, ResolveError::Transport(_))
    }
}

pub type ResolveFuture<'a> = BoxFuture<'a, Result<Option<ResolvedSession>, ResolveError>>;

/// The backend fill for a cache miss. Implementations do the actual point
/// read; `Ok(None)` means the token is unknown.
pub trait SessionFetcher: Send + Sync + 'static {
    fn fetch<'a>(&'a self, token_hash: &'a str) -> ResolveFuture<'a>;
}

/// What callers use: an already-cache-tiered resolve. Object-safe so state
/// structs can hold `Arc<dyn SessionResolver>` without a type parameter.
pub trait SessionResolver: Send + Sync + 'static {
    fn resolve<'a>(&'a self, token_hash: &'a str) -> ResolveFuture<'a>;
    /// Drop any cached entry for this hash (sign-out / revoke on the local node).
    fn evict(&self, token_hash: &str);
}

/// Session-resolution cache tunables (issue #243). The library does not read
/// environment variables; the process supplies the config.
#[derive(Clone, Debug)]
pub struct ResolverConfig {
    /// L1 LRU capacity.
    pub capacity: usize,
    /// Positive entry TTL (hard staleness/revocation cap).
    pub l1_ttl: Duration,
    /// Negative tombstone TTL for unknown tokens.
    pub neg_ttl: Duration,
    /// Serve stale on transport error for this window; zero = off.
    pub stale_if_error: Duration,
}

impl Default for ResolverConfig {
    /// The #243 defaults: capacity 10000, L1 TTL 30s, neg TTL 2s,
    /// stale-if-error off.
    fn default() -> Self {
        ResolverConfig {
            capacity: 10_000,
            l1_ttl: Duration::from_secs(30),
            neg_ttl: Duration::from_secs(2),
            stale_if_error: Duration::ZERO,
        }
    }
}

/// One cache slot. `outcome == None` is a negative tombstone.
#[derive(Clone)]
struct Entry {
    outcome: Option<ResolvedSession>,
    fetched_at: Instant,
    fresh_until: Instant,
    stale_until: Instant,
    effective_ttl: Duration,
}

/// Bounded LRU keyed by token hash. A monotonically increasing recency
/// generation orders entries in a `BTreeMap`, so eviction is `O(log n)` and
/// `get` promotes to most-recently-used.
struct Lru {
    map: HashMap<String, (Entry, u64)>,
    recency: BTreeMap<u64, String>,
    next_gen: u64,
    capacity: usize,
}

impl Lru {
    fn new(capacity: usize) -> Self {
        Lru {
            map: HashMap::new(),
            recency: BTreeMap::new(),
            next_gen: 0,
            capacity,
        }
    }

    fn get(&mut self, key: &str) -> Option<Entry> {
        if self.capacity == 0 {
            return None;
        }
        let (entry, old_gen) = self.map.get(key)?;
        let entry = entry.clone();
        let old_gen = *old_gen;
        self.recency.remove(&old_gen);
        let gen = self.next_gen;
        self.next_gen += 1;
        self.recency.insert(gen, key.to_string());
        if let Some(e) = self.map.get_mut(key) {
            e.1 = gen;
        }
        Some(entry)
    }

    fn peek(&self, key: &str) -> Option<Entry> {
        self.map.get(key).map(|(e, _)| e.clone())
    }

    fn put(&mut self, key: String, entry: Entry) {
        if self.capacity == 0 {
            return;
        }
        if let Some((_, old_gen)) = self.map.get(&key) {
            let old_gen = *old_gen;
            self.recency.remove(&old_gen);
        }
        let gen = self.next_gen;
        self.next_gen += 1;
        self.recency.insert(gen, key.clone());
        self.map.insert(key, (entry, gen));
        while self.map.len() > self.capacity {
            let Some((&lru_gen, lru_key)) = self.recency.iter().next() else {
                break;
            };
            let lru_key = lru_key.clone();
            self.recency.remove(&lru_gen);
            self.map.remove(&lru_key);
        }
    }

    fn remove(&mut self, key: &str) {
        if let Some((_, gen)) = self.map.remove(key) {
            self.recency.remove(&gen);
        }
    }
}

type FillResult = Result<Option<ResolvedSession>, Arc<ResolveError>>;
type SharedFill = Shared<BoxFuture<'static, FillResult>>;

/// Single-flight de-duplication of identical concurrent fills (an SPA firing
/// 20 parallel XHRs on a cold token triggers one fill, 19 waiters share it).
#[derive(Clone, Default)]
struct SingleFlight {
    inflight: Arc<Mutex<HashMap<String, (u64, SharedFill)>>>,
    next_id: Arc<AtomicU64>,
}

impl SingleFlight {
    async fn run<F, Fut>(&self, key: &str, make: F) -> Result<Option<ResolvedSession>, ResolveError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<ResolvedSession>, ResolveError>> + Send + 'static,
    {
        let shared = {
            let mut map = self.inflight.lock().expect("singleflight mutex poisoned");
            if let Some((_, existing)) = map.get(key) {
                existing.clone()
            } else {
                let id = self.next_id.fetch_add(1, Ordering::Relaxed);
                let inflight = Arc::clone(&self.inflight);
                let owned_key = key.to_string();
                let inner = make().map(|r| r.map_err(Arc::new));
                // The map entry is removed inside the shared future so cleanup
                // runs no matter which task drives the fill to completion — a
                // leader dropped mid-await (client disconnect) must not leak
                // the entry and freeze this hash on a memoized result.
                let fut: SharedFill = async move {
                    let result = inner.await;
                    let mut map = inflight.lock().expect("singleflight mutex poisoned");
                    if map
                        .get(&owned_key)
                        .map(|(gid, _)| *gid == id)
                        .unwrap_or(false)
                    {
                        map.remove(&owned_key);
                    }
                    result
                }
                .boxed()
                .shared();
                map.insert(key.to_string(), (id, fut.clone()));
                // Detach the fill (Go: detached context): it completes and
                // populates the cache even if every waiter is cancelled.
                tokio::spawn(fut.clone());
                fut
            }
        };

        shared.await.map_err(|e| (*e).clone())
    }
}

struct ResolverInner {
    fetcher: Arc<dyn SessionFetcher>,
    cache: Mutex<Lru>,
    flight: SingleFlight,
    cfg: ResolverConfig,
}

impl ResolverInner {
    fn effective_ttl(&self) -> Duration {
        // Downward-only jitter U(0.8, 1.0): l1_ttl is a hard cap.
        let jitter = 0.8 + 0.2 * rand::random::<f64>();
        Duration::from_secs_f64(self.cfg.l1_ttl.as_secs_f64() * jitter)
    }

    async fn resolve(
        self: Arc<Self>,
        hash: String,
    ) -> Result<Option<ResolvedSession>, ResolveError> {
        let now = Instant::now();
        let now_wall = Utc::now();

        // 1. L1 lookup (guard dropped before any await).
        let cached = {
            let mut guard = self.cache.lock().expect("session cache mutex poisoned");
            guard.get(&hash)
        };
        if let Some(entry) = cached {
            let wall_valid = match &entry.outcome {
                Some(s) => s.expires_at > now_wall,
                None => true,
            };
            if !wall_valid {
                // Positive entry past its session expiry: forced miss.
                self.cache
                    .lock()
                    .expect("session cache mutex poisoned")
                    .remove(&hash);
            } else if now < entry.fresh_until {
                // Hit. Refresh-ahead for hot positive entries.
                if entry.outcome.is_some() {
                    let remaining = entry.fresh_until.saturating_duration_since(now);
                    if remaining.as_secs_f64() < 0.10 * entry.effective_ttl.as_secs_f64() {
                        self.clone().spawn_refresh(hash.clone());
                    }
                }
                return Ok(entry.outcome);
            }
        }

        // 2. Miss (or stale): capture a stale candidate, then single-flight fill.
        let stale = self.stale_candidate(&hash, now, now_wall);
        let this = self.clone();
        let key = hash.clone();
        let outcome = self
            .flight
            .run(&hash, move || {
                let this = this.clone();
                async move { this.fill(key).await }
            })
            .await;

        match outcome {
            Ok(v) => Ok(v),
            Err(e) => {
                if e.is_transport() {
                    if let Some((s, _fetched_at)) = stale {
                        log::warn!("session resolver: serving stale entry on transport error: {e}");
                        return Ok(Some(s));
                    }
                }
                Err(e)
            }
        }
    }

    async fn fill(self: Arc<Self>, hash: String) -> Result<Option<ResolvedSession>, ResolveError> {
        let fetched = tokio::time::timeout(RESOLVE_TIMEOUT, self.fetcher.fetch(&hash))
            .await
            .map_err(|_| {
                ResolveError::Transport("session resolve timed out after 5s".to_string())
            })??;
        let now = Instant::now();
        let entry = match &fetched {
            Some(s) => {
                let eff = self.effective_ttl();
                let wall_remaining = (s.expires_at - Utc::now())
                    .to_std()
                    .unwrap_or(Duration::ZERO);
                let ttl = eff.min(wall_remaining);
                Entry {
                    outcome: Some(s.clone()),
                    fetched_at: now,
                    fresh_until: now + ttl,
                    stale_until: now + ttl + self.cfg.stale_if_error,
                    effective_ttl: eff,
                }
            }
            None => Entry {
                outcome: None,
                fetched_at: now,
                fresh_until: now + self.cfg.neg_ttl,
                stale_until: now + self.cfg.neg_ttl,
                effective_ttl: self.cfg.neg_ttl,
            },
        };
        {
            let mut guard = self.cache.lock().expect("session cache mutex poisoned");
            guard.put(hash, entry);
        }
        Ok(fetched)
    }

    fn stale_candidate(
        &self,
        hash: &str,
        now: Instant,
        now_wall: DateTime<Utc>,
    ) -> Option<(ResolvedSession, Instant)> {
        if self.cfg.stale_if_error.is_zero() {
            return None;
        }
        let guard = self.cache.lock().expect("session cache mutex poisoned");
        let entry = guard.peek(hash)?;
        match entry.outcome {
            Some(s) if s.expires_at > now_wall && now < entry.stale_until => {
                Some((s, entry.fetched_at))
            }
            _ => None,
        }
    }

    fn spawn_refresh(self: Arc<Self>, hash: String) {
        tokio::spawn(async move {
            let this = self.clone();
            let key = hash.clone();
            let _ = self
                .flight
                .run(&hash, move || {
                    let this = this.clone();
                    async move { this.fill(key).await }
                })
                .await;
        });
    }
}

/// The cache-tiered resolver. Constructed over any [`SessionFetcher`].
#[derive(Clone)]
pub struct CachedResolver {
    shared: Arc<ResolverInner>,
}

impl CachedResolver {
    pub fn new(fetcher: Arc<dyn SessionFetcher>, cfg: ResolverConfig) -> Self {
        CachedResolver {
            shared: Arc::new(ResolverInner {
                cache: Mutex::new(Lru::new(cfg.capacity)),
                flight: SingleFlight::default(),
                fetcher,
                cfg,
            }),
        }
    }

    /// Erase to the object-safe trait for storage in state structs.
    pub fn into_dyn(self) -> Arc<dyn SessionResolver> {
        Arc::new(self)
    }
}

impl SessionResolver for CachedResolver {
    fn resolve<'a>(&'a self, token_hash: &'a str) -> ResolveFuture<'a> {
        let shared = self.shared.clone();
        let hash = token_hash.to_string();
        Box::pin(async move { shared.resolve(hash).await })
    }

    fn evict(&self, token_hash: &str) {
        let mut guard = self
            .shared
            .cache
            .lock()
            .expect("session cache mutex poisoned");
        guard.remove(token_hash);
    }
}

/// Fleet path: resolve over `am.SessionService` on nio-client. The relying
/// party supplies a connected [`Channel`] (see [`crate::connect_channel`];
/// check and session are always distinct endpoints).
pub struct GrpcSessionResolver;

impl GrpcSessionResolver {
    // Factory returning the object-safe trait; not a `Self` ctor.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(channel: Channel, cfg: ResolverConfig) -> Arc<dyn SessionResolver> {
        let client = SessionServiceClient::new(channel);
        let fetcher: Arc<dyn SessionFetcher> = Arc::new(GrpcFetcher { client });
        CachedResolver::new(fetcher, cfg).into_dyn()
    }
}

struct GrpcFetcher {
    client: SessionServiceClient<Channel>,
}

impl SessionFetcher for GrpcFetcher {
    fn fetch<'a>(&'a self, token_hash: &'a str) -> ResolveFuture<'a> {
        let mut client = self.client.clone();
        let token_hash = token_hash.to_string();
        Box::pin(async move {
            let resp = client
                .resolve(ResolveRequest { token_hash })
                .await
                .map_err(classify_status)?;
            match resp.into_inner().outcome {
                Some(resolve_response::Outcome::Session(s)) => Ok(Some(ResolvedSession {
                    principal: s.principal,
                    tenant_id: s.tenant_id,
                    expires_at: DateTime::from_timestamp(s.expires_at_unix_seconds, 0)
                        .unwrap_or_else(Utc::now),
                })),
                // unknown / expired / revoked — deliberately indistinguishable.
                Some(resolve_response::Outcome::NotFound(_)) | None => Ok(None),
            }
        })
    }
}

fn classify_status(status: tonic::Status) -> ResolveError {
    match status.code() {
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded => {
            ResolveError::Transport(status.message().to_string())
        }
        _ => ResolveError::Backend(status.message().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct CountingFetcher {
        calls: Arc<AtomicUsize>,
        session: Option<ResolvedSession>,
    }

    impl SessionFetcher for CountingFetcher {
        fn fetch<'a>(&'a self, _token_hash: &'a str) -> ResolveFuture<'a> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let session = self.session.clone();
            Box::pin(async move { Ok(session) })
        }
    }

    struct FailingFetcher {
        calls: Arc<AtomicUsize>,
    }

    impl SessionFetcher for FailingFetcher {
        fn fetch<'a>(&'a self, _token_hash: &'a str) -> ResolveFuture<'a> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move { Err(ResolveError::Transport("down".into())) })
        }
    }

    fn session_valid_for(mins: i64) -> ResolvedSession {
        ResolvedSession {
            principal: "11111111-1111-1111-1111-111111111111".to_string(),
            tenant_id: String::new(),
            expires_at: Utc::now() + chrono::TimeDelta::minutes(mins),
        }
    }

    fn cfg() -> ResolverConfig {
        ResolverConfig {
            capacity: 100,
            l1_ttl: Duration::from_secs(30),
            neg_ttl: Duration::from_secs(2),
            stale_if_error: Duration::ZERO,
        }
    }

    #[test]
    fn token_hash_is_hex_sha256() {
        // sha256("") — a known vector.
        assert_eq!(
            token_hash(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(token_hash("abc").len(), 64);
    }

    #[test]
    fn default_config_matches_243() {
        let cfg = ResolverConfig::default();
        assert_eq!(cfg.capacity, 10_000);
        assert_eq!(cfg.l1_ttl, Duration::from_secs(30));
        assert_eq!(cfg.neg_ttl, Duration::from_secs(2));
        assert_eq!(cfg.stale_if_error, Duration::ZERO);
    }

    #[tokio::test]
    async fn hit_does_not_refetch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = Arc::new(CountingFetcher {
            calls: calls.clone(),
            session: Some(session_valid_for(120)),
        });
        let r = CachedResolver::new(fetcher, cfg());
        let first = r.resolve("deadbeef").await.unwrap();
        assert!(first.is_some());
        let _ = r.resolve("deadbeef").await.unwrap();
        let _ = r.resolve("deadbeef").await.unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1, "L1 hit must not refetch");
    }

    #[tokio::test]
    async fn unknown_token_is_tombstoned() {
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = Arc::new(CountingFetcher {
            calls: calls.clone(),
            session: None,
        });
        let r = CachedResolver::new(fetcher, cfg());
        assert!(r.resolve("nope").await.unwrap().is_none());
        assert!(r.resolve("nope").await.unwrap().is_none());
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "tombstone must not refetch"
        );
    }

    #[tokio::test]
    async fn evict_forces_refetch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = Arc::new(CountingFetcher {
            calls: calls.clone(),
            session: Some(session_valid_for(120)),
        });
        let r = CachedResolver::new(fetcher, cfg());
        let _ = r.resolve("k").await.unwrap();
        r.evict("k");
        let _ = r.resolve("k").await.unwrap();
        assert_eq!(
            calls.load(Ordering::Relaxed),
            2,
            "evict must force a refetch"
        );
    }

    #[tokio::test]
    async fn expired_session_is_forced_miss() {
        let calls = Arc::new(AtomicUsize::new(0));
        // Session already expired: every lookup must be a forced miss.
        let fetcher = Arc::new(CountingFetcher {
            calls: calls.clone(),
            session: Some(session_valid_for(-1)),
        });
        let r = CachedResolver::new(fetcher, cfg());
        let _ = r.resolve("k").await.unwrap();
        let _ = r.resolve("k").await.unwrap();
        assert_eq!(
            calls.load(Ordering::Relaxed),
            2,
            "expired entry must not serve from L1"
        );
    }

    #[tokio::test]
    async fn transport_error_propagates_without_stale_window() {
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = Arc::new(FailingFetcher {
            calls: calls.clone(),
        });
        let r = CachedResolver::new(fetcher, cfg());
        let err = r.resolve("k").await.expect_err("must fail");
        assert!(matches!(err, ResolveError::Transport(_)));
    }

    #[tokio::test]
    async fn zero_capacity_disables_cache() {
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = Arc::new(CountingFetcher {
            calls: calls.clone(),
            session: Some(session_valid_for(120)),
        });
        let mut c = cfg();
        c.capacity = 0;
        let r = CachedResolver::new(fetcher, c);
        let _ = r.resolve("k").await.unwrap();
        let _ = r.resolve("k").await.unwrap();
        assert_eq!(
            calls.load(Ordering::Relaxed),
            2,
            "capacity 0 must not cache"
        );
    }

    #[tokio::test]
    async fn lru_evicts_oldest() {
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = Arc::new(CountingFetcher {
            calls: calls.clone(),
            session: Some(session_valid_for(120)),
        });
        let mut c = cfg();
        c.capacity = 2;
        let r = CachedResolver::new(fetcher, c);
        let _ = r.resolve("a").await.unwrap();
        let _ = r.resolve("b").await.unwrap();
        let _ = r.resolve("c").await.unwrap(); // evicts "a"
        let _ = r.resolve("a").await.unwrap(); // refetch
        assert_eq!(calls.load(Ordering::Relaxed), 4, "lru must evict oldest");
    }

    struct GatedFirstFetcher {
        calls: Arc<AtomicUsize>,
        gate: Arc<tokio::sync::Semaphore>,
        session: Option<ResolvedSession>,
    }

    impl SessionFetcher for GatedFirstFetcher {
        fn fetch<'a>(&'a self, _token_hash: &'a str) -> ResolveFuture<'a> {
            let n = self.calls.fetch_add(1, Ordering::Relaxed);
            let gate = self.gate.clone();
            let session = self.session.clone();
            Box::pin(async move {
                if n == 0 {
                    let _permit = gate.acquire_owned().await.expect("gate closed");
                }
                Ok(session)
            })
        }
    }

    // Regression: a leader future dropped mid-fill (client disconnect) must
    // not leak the inflight entry and freeze this hash on a memoized result —
    // the fill runs detached and cleans up the flight map itself.
    #[tokio::test]
    async fn cancelled_leader_does_not_poison_future_resolves() {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let fetcher = Arc::new(GatedFirstFetcher {
            calls: calls.clone(),
            gate: gate.clone(),
            session: Some(session_valid_for(120)),
        });
        let r = CachedResolver::new(fetcher, cfg());

        let leader = {
            let r = r.clone();
            tokio::spawn(async move { r.resolve("k").await })
        };
        while calls.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
        leader.abort();
        let _ = leader.await;

        gate.add_permits(1);
        let got = r.resolve("k").await.unwrap();
        assert!(got.is_some());
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        r.evict("k");
        let got = r.resolve("k").await.unwrap();
        assert!(got.is_some());
        assert_eq!(
            calls.load(Ordering::Relaxed),
            2,
            "resolve after evict must refetch even after a cancelled leader"
        );
    }

    struct HangingFetcher;

    impl SessionFetcher for HangingFetcher {
        fn fetch<'a>(&'a self, _token_hash: &'a str) -> ResolveFuture<'a> {
            Box::pin(futures::future::pending())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fill_timeout_is_transport_error() {
        let r = CachedResolver::new(Arc::new(HangingFetcher), cfg());
        let err = r
            .resolve("k")
            .await
            .expect_err("hung backend must time out");
        assert!(matches!(err, ResolveError::Transport(_)));
    }

    struct SwitchableFetcher {
        session: ResolvedSession,
        err: Mutex<Option<ResolveError>>,
    }

    impl SessionFetcher for SwitchableFetcher {
        fn fetch<'a>(&'a self, _token_hash: &'a str) -> ResolveFuture<'a> {
            let err = self.err.lock().unwrap().clone();
            let session = self.session.clone();
            Box::pin(async move {
                match err {
                    Some(e) => Err(e),
                    None => Ok(Some(session)),
                }
            })
        }
    }

    fn stale_cfg() -> ResolverConfig {
        ResolverConfig {
            capacity: 100,
            l1_ttl: Duration::from_millis(1),
            neg_ttl: Duration::from_secs(2),
            stale_if_error: Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn transport_error_serves_stale_within_window() {
        let fetcher = Arc::new(SwitchableFetcher {
            session: session_valid_for(120),
            err: Mutex::new(None),
        });
        let r = CachedResolver::new(fetcher.clone(), stale_cfg());
        assert!(r.resolve("k").await.unwrap().is_some());
        tokio::time::sleep(Duration::from_millis(20)).await; // past fresh_until
        *fetcher.err.lock().unwrap() = Some(ResolveError::Transport("unavailable".into()));
        let got = r
            .resolve("k")
            .await
            .expect("transport error must serve stale");
        assert!(got.is_some());
    }

    #[tokio::test]
    async fn backend_error_propagates_despite_stale_window() {
        let fetcher = Arc::new(SwitchableFetcher {
            session: session_valid_for(120),
            err: Mutex::new(None),
        });
        let r = CachedResolver::new(fetcher.clone(), stale_cfg());
        assert!(r.resolve("k").await.unwrap().is_some());
        tokio::time::sleep(Duration::from_millis(20)).await;
        *fetcher.err.lock().unwrap() = Some(ResolveError::Backend("boom".into()));
        r.resolve("k")
            .await
            .expect_err("backend error must propagate, not serve stale");
    }

    #[test]
    fn classify_status_transport_vs_backend() {
        assert!(matches!(
            classify_status(tonic::Status::unavailable("x")),
            ResolveError::Transport(_)
        ));
        assert!(matches!(
            classify_status(tonic::Status::deadline_exceeded("x")),
            ResolveError::Transport(_)
        ));
        assert!(matches!(
            classify_status(tonic::Status::internal("x")),
            ResolveError::Backend(_)
        ));
        assert!(matches!(
            classify_status(tonic::Status::permission_denied("x")),
            ResolveError::Backend(_)
        ));
    }

    #[test]
    fn token_hash_newtype_matches_fn() {
        assert_eq!(TokenHash::from_raw("tok").as_str(), token_hash("tok"));
    }
}
