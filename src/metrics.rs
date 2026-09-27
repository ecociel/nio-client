//! Prometheus series for the session resolver (`nio_session_resolver_*`) and
//! the check RPCs (`nio_check_client_*`), with the same names, labels and
//! buckets as nio's `check_client`. Behind the `metrics` feature: call
//! `register` once and export the registry.
//!
//! The families are process-global. Registering into a second registry
//! exports the same counters twice, so register into one registry per
//! process.

#[cfg(feature = "metrics")]
mod real {
    use prometheus_client::encoding::EncodeLabelSet;
    use prometheus_client::metrics::counter::Counter;
    use prometheus_client::metrics::family::Family;
    use prometheus_client::metrics::gauge::Gauge;
    use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
    use prometheus_client::registry::Registry;
    use std::sync::OnceLock;
    use std::time::Duration;

    #[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
    struct EventLabels {
        event: &'static str,
    }

    #[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
    struct ResultLabels {
        result: &'static str,
    }

    #[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
    struct RpcLabels {
        rpc: &'static str,
    }

    #[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
    struct RpcCodeLabels {
        rpc: &'static str,
        code: &'static str,
    }

    struct Families {
        resolver_events: Family<EventLabels, Counter>,
        resolver_resolve_duration: Histogram,
        resolver_fetch_duration: Family<ResultLabels, Histogram, fn() -> Histogram>,
        resolver_served_age: Histogram,
        resolver_singleflight: Family<EventLabels, Counter>,
        resolver_inflight: Gauge,
        resolver_entries: Gauge,
        check_requests: Family<RpcCodeLabels, Counter>,
        check_duration: Family<RpcLabels, Histogram, fn() -> Histogram>,
    }

    fn rpc_hist() -> Histogram {
        // Identical to check's server-side buckets so client-observed minus
        // server-observed subtracts cleanly.
        Histogram::new(exponential_buckets(0.00025, 2.0, 16))
    }

    fn families() -> &'static Families {
        static FAMILIES: OnceLock<Families> = OnceLock::new();
        FAMILIES.get_or_init(|| Families {
            resolver_events: Family::default(),
            resolver_resolve_duration: Histogram::new(exponential_buckets(0.00005, 2.0, 18)),
            resolver_fetch_duration: Family::new_with_constructor(rpc_hist),
            resolver_served_age: Histogram::new(exponential_buckets(1.0, 2.0, 8)),
            resolver_singleflight: Family::default(),
            resolver_inflight: Gauge::default(),
            resolver_entries: Gauge::default(),
            check_requests: Family::default(),
            check_duration: Family::new_with_constructor(rpc_hist),
        })
    }

    /// Registers this crate's families into the host's registry. Call once.
    pub fn register(registry: &mut Registry) {
        let f = families();
        registry.register(
            "nio_session_resolver_events",
            "Session resolver cache events (hit|negative_hit|miss|stale_if_error|refresh_ahead)",
            f.resolver_events.clone(),
        );
        registry.register(
            "nio_session_resolver_resolve_duration_seconds",
            "End-to-end resolve duration incl. cache hits and singleflight waits",
            f.resolver_resolve_duration.clone(),
        );
        registry.register(
            "nio_session_resolver_fetch_duration_seconds",
            "Backend fill duration by result (leader's call only)",
            f.resolver_fetch_duration.clone(),
        );
        registry.register(
            "nio_session_resolver_served_age_seconds",
            "Age of the cache entry at serve time — the effective revocation window",
            f.resolver_served_age.clone(),
        );
        registry.register(
            "nio_session_resolver_singleflight",
            "Single-flight participations by role (leader|follower)",
            f.resolver_singleflight.clone(),
        );
        registry.register(
            "nio_session_resolver_inflight",
            "Fills currently in flight (stuck > 0 with fetch rate 0 = frozen resolver)",
            f.resolver_inflight.clone(),
        );
        registry.register(
            "nio_session_resolver_entries",
            "Resident L1 entries",
            f.resolver_entries.clone(),
        );
        registry.register(
            "nio_check_client_requests",
            "check RPCs issued by this process, by rpc and status code",
            f.check_requests.clone(),
        );
        registry.register(
            "nio_check_client_request_duration_seconds",
            "check RPC duration as observed by this process",
            f.check_duration.clone(),
        );
    }

    pub(crate) fn resolver_event(event: &'static str) {
        families()
            .resolver_events
            .get_or_create(&EventLabels { event })
            .inc();
    }

    pub(crate) fn resolver_resolve_duration(d: Duration) {
        families()
            .resolver_resolve_duration
            .observe(d.as_secs_f64());
    }

    pub(crate) fn resolver_fetch(result: &'static str, d: Duration) {
        families()
            .resolver_fetch_duration
            .get_or_create(&ResultLabels { result })
            .observe(d.as_secs_f64());
    }

    pub(crate) fn resolver_served_age(age: Duration) {
        families().resolver_served_age.observe(age.as_secs_f64());
    }

    pub(crate) fn singleflight(event: &'static str) {
        families()
            .resolver_singleflight
            .get_or_create(&EventLabels { event })
            .inc();
    }

    pub(crate) fn singleflight_inflight(n: usize) {
        families().resolver_inflight.set(n as i64);
    }

    pub(crate) fn resolver_entries(n: usize) {
        families().resolver_entries.set(n as i64);
    }

    pub(crate) fn check_rpc<T>(rpc: &'static str, res: &Result<T, tonic::Status>, d: Duration) {
        let code = match res {
            Ok(_) => "ok",
            Err(status) => code_name(status.code()),
        };
        families()
            .check_requests
            .get_or_create(&RpcCodeLabels { rpc, code })
            .inc();
        families()
            .check_duration
            .get_or_create(&RpcLabels { rpc })
            .observe(d.as_secs_f64());
    }

    fn code_name(code: tonic::Code) -> &'static str {
        match code {
            tonic::Code::Ok => "ok",
            tonic::Code::Cancelled => "cancelled",
            tonic::Code::Unknown => "unknown",
            tonic::Code::InvalidArgument => "invalid_argument",
            tonic::Code::DeadlineExceeded => "deadline_exceeded",
            tonic::Code::NotFound => "not_found",
            tonic::Code::AlreadyExists => "already_exists",
            tonic::Code::PermissionDenied => "permission_denied",
            tonic::Code::ResourceExhausted => "resource_exhausted",
            tonic::Code::FailedPrecondition => "failed_precondition",
            tonic::Code::Aborted => "aborted",
            tonic::Code::OutOfRange => "out_of_range",
            tonic::Code::Unimplemented => "unimplemented",
            tonic::Code::Internal => "internal",
            tonic::Code::Unavailable => "unavailable",
            tonic::Code::DataLoss => "data_loss",
            tonic::Code::Unauthenticated => "unauthenticated",
        }
    }
}

#[cfg(feature = "metrics")]
pub use real::*;

/// The `prometheus-client` this crate registers into, so a host builds its
/// [`Registry`](prometheus_client::registry::Registry) against the same
/// version.
#[cfg(feature = "metrics")]
pub use prometheus_client;

#[cfg(not(feature = "metrics"))]
mod noop {
    use std::time::Duration;

    pub(crate) fn resolver_event(_event: &'static str) {}
    pub(crate) fn resolver_resolve_duration(_d: Duration) {}
    pub(crate) fn resolver_fetch(_result: &'static str, _d: Duration) {}
    pub(crate) fn resolver_served_age(_age: Duration) {}
    pub(crate) fn singleflight(_event: &'static str) {}
    pub(crate) fn singleflight_inflight(_n: usize) {}
    pub(crate) fn resolver_entries(_n: usize) {}
    pub(crate) fn check_rpc<T>(_rpc: &'static str, _res: &Result<T, tonic::Status>, _d: Duration) {}
}

#[cfg(not(feature = "metrics"))]
pub(crate) use noop::*;
