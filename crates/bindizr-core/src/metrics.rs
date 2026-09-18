//! Process-wide Prometheus registry shared by the HTTP API and DNS layers.

use std::{
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use prometheus::{
    Gauge, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder, core::Collector,
};

use crate::dns::message::{Rcode, Rtype};

/// Content type of the Prometheus text exposition format.
pub const TEXT_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

pub struct Metrics {
    registry: Registry,
    pub database_up: IntGauge,
    db_connections: IntGaugeVec,
    db_connections_max: IntGauge,
    pub zones_total: IntGauge,
    pub records_total: IntGauge,
    pub http_requests_total: IntCounterVec,
    pub http_request_duration_seconds: HistogramVec,
    xfr_total: IntCounterVec,
    soa_queries_total: IntCounterVec,
    notify_sent_total: IntCounterVec,
    nsupdate_requests_total: IntCounterVec,
    zone_serial_bumps_total: IntCounter,
    pruned_rows_total: IntCounterVec,
    pub dnssec_zones_total: IntGauge,
    pub dnssec_keys_total: IntGaugeVec,
    pub dnssec_rrsigs_expiring_total: IntGauge,
    pub dnssec_rrsigs_expired_total: IntGauge,
    dnssec_scheduler_runs_total: IntCounterVec,
    zone_cache_lookups_total: IntCounterVec,
    zone_cache_evictions_total: IntCounter,
    zone_cache_records: IntGauge,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Global registry. First touched at daemon startup so
/// `bindizr_started_at_seconds` reflects process start.
pub fn metrics() -> &'static Metrics {
    METRICS.get_or_init(Metrics::new)
}

/// Register a shared clone of a metric collector.
fn register<C: Collector + Clone + 'static>(registry: &Registry, collector: &C) {
    registry
        .register(Box::new(collector.clone()))
        .expect("metric registered twice");
}

impl Metrics {
    /// Create and register the daemon's metric collectors.
    fn new() -> Self {
        let registry = Registry::new();

        let build_info = IntGaugeVec::new(
            Opts::new(
                "bindizr_build_info",
                "Build metadata; the value is always 1.",
            ),
            &["version"],
        )
        .expect("valid metric definition");
        build_info
            .with_label_values(&[env!("CARGO_PKG_VERSION")])
            .set(1);
        register(&registry, &build_info);

        let started_at_seconds = Gauge::new(
            "bindizr_started_at_seconds",
            "Unix time the process started.",
        )
        .expect("valid metric definition");
        started_at_seconds.set(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs_f64())
                .unwrap_or(0.0),
        );
        register(&registry, &started_at_seconds);

        let database_up = IntGauge::new(
            "bindizr_database_up",
            "Whether the database probe of the last scrape succeeded (1) or failed (0).",
        )
        .expect("valid metric definition");
        register(&registry, &database_up);

        let db_connections = IntGaugeVec::new(
            Opts::new(
                "bindizr_db_connections",
                "Pooled database connections by state; `in_use` reaching \
                 `bindizr_db_connections_max` is the saturation every request then queues behind",
            ),
            &["state"],
        )
        .expect("valid metric definition");
        register(&registry, &db_connections);

        let db_connections_max = IntGauge::new(
            "bindizr_db_connections_max",
            "Connection ceiling the pool was built with, scaled to the host's cores",
        )
        .expect("valid metric definition");
        register(&registry, &db_connections_max);

        let zones_total = IntGauge::new(
            "bindizr_zones_total",
            "Number of zones, refreshed at scrape time.",
        )
        .expect("valid metric definition");
        register(&registry, &zones_total);

        let records_total = IntGauge::new(
            "bindizr_records_total",
            "Number of records, refreshed at scrape time.",
        )
        .expect("valid metric definition");
        register(&registry, &records_total);

        let http_requests_total = IntCounterVec::new(
            Opts::new("bindizr_http_requests_total", "HTTP API requests served."),
            &["method", "route", "status"],
        )
        .expect("valid metric definition");
        register(&registry, &http_requests_total);

        let http_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "bindizr_http_request_duration_seconds",
                "HTTP API request latency in seconds.",
            ),
            &["method", "route"],
        )
        .expect("valid metric definition");
        register(&registry, &http_request_duration_seconds);

        let xfr_total = IntCounterVec::new(
            Opts::new(
                "bindizr_xfr_total",
                "Zone transfer requests served, by query type and outcome.",
            ),
            &["type", "result"],
        )
        .expect("valid metric definition");
        register(&registry, &xfr_total);

        let soa_queries_total = IntCounterVec::new(
            Opts::new(
                "bindizr_soa_queries_total",
                "SOA queries answered, by outcome; secondaries poll these on their refresh \
                 timer, so a rise in `refused` means one stopped being a configured secondary",
            ),
            &["result"],
        )
        .expect("valid metric definition");
        register(&registry, &soa_queries_total);

        let notify_sent_total = IntCounterVec::new(
            Opts::new(
                "bindizr_notify_sent_total",
                "NOTIFY delivery attempts to secondaries, by outcome.",
            ),
            &["result"],
        )
        .expect("valid metric definition");
        register(&registry, &notify_sent_total);

        let nsupdate_requests_total = IntCounterVec::new(
            Opts::new(
                "bindizr_nsupdate_requests_total",
                "RFC 2136 dynamic update requests processed, by outcome.",
            ),
            &["result"],
        )
        .expect("valid metric definition");
        register(&registry, &nsupdate_requests_total);

        let zone_serial_bumps_total = IntCounter::new(
            "bindizr_zone_serial_bumps_total",
            "Zone serial writes across every update path.",
        )
        .expect("valid metric definition");
        register(&registry, &zone_serial_bumps_total);

        let pruned_rows_total = IntCounterVec::new(
            Opts::new(
                "bindizr_pruned_rows_total",
                "Rows the retention pass deleted, by table; a rate of zero while zones keep \
                 changing means the journal is growing without bound",
            ),
            &["table"],
        )
        .expect("valid metric definition");
        register(&registry, &pruned_rows_total);

        let dnssec_zones_total = IntGauge::new(
            "bindizr_dnssec_zones_total",
            "Number of DNSSEC-signed zones, refreshed at scrape time.",
        )
        .expect("valid metric definition");
        register(&registry, &dnssec_zones_total);

        let dnssec_keys_total = IntGaugeVec::new(
            Opts::new(
                "bindizr_dnssec_keys_total",
                "Number of DNSSEC keys by state, refreshed at scrape time.",
            ),
            &["state"],
        )
        .expect("valid metric definition");
        register(&registry, &dnssec_keys_total);

        let dnssec_rrsigs_expiring_total = IntGauge::new(
            "bindizr_dnssec_rrsigs_expiring_total",
            "Signatures inside the refresh window at scrape time; a value that \
             persists across scrapes means re-signing is falling behind.",
        )
        .expect("valid metric definition");
        register(&registry, &dnssec_rrsigs_expiring_total);

        let dnssec_rrsigs_expired_total = IntGauge::new(
            "bindizr_dnssec_rrsigs_expired_total",
            "Signatures already past their expiration; any at all mean resolvers are failing \
             part of a zone",
        )
        .expect("valid metric definition");
        register(&registry, &dnssec_rrsigs_expired_total);

        let dnssec_scheduler_runs_total = IntCounterVec::new(
            Opts::new(
                "bindizr_dnssec_scheduler_runs_total",
                "Hourly DNSSEC scheduler passes, by outcome.",
            ),
            &["result"],
        )
        .expect("valid metric definition");
        register(&registry, &dnssec_scheduler_runs_total);

        let zone_cache_lookups_total = IntCounterVec::new(
            Opts::new(
                "bindizr_zone_cache_lookups_total",
                "Zone-cache reads by outcome; a low hit ratio means transfers \
                 are reaching the database anyway.",
            ),
            &["result"],
        )
        .expect("valid metric definition");
        register(&registry, &zone_cache_lookups_total);

        let zone_cache_evictions_total = IntCounter::new(
            "bindizr_zone_cache_evictions_total",
            "Zones dropped to make room; a rising count beside a low hit ratio \
             means dns.transfer_cache.max_records is too small for the working set.",
        )
        .expect("valid metric definition");
        register(&registry, &zone_cache_evictions_total);

        let zone_cache_records = IntGauge::new(
            "bindizr_zone_cache_records",
            "Records the zone cache holds, against dns.transfer_cache.max_records.",
        )
        .expect("valid metric definition");
        register(&registry, &zone_cache_records);

        // Prometheus emits a labelled series only once it is touched, so an
        // alert on a counter staying at zero reads "no data" until the first
        // event. Every label set here is small and fully known.
        for result in XfrResult::ALL {
            for xfr_type in ["axfr", "ixfr"] {
                xfr_total.with_label_values(&[xfr_type, result.label()]);
            }
        }
        for result in SoaResult::ALL {
            soa_queries_total.with_label_values(&[result.label()]);
        }
        for result in NsupdateResult::ALL {
            nsupdate_requests_total.with_label_values(&[result.label()]);
        }
        for result in NotifyResult::ALL {
            notify_sent_total.with_label_values(&[result.label()]);
        }
        for result in SchedulerResult::ALL {
            dnssec_scheduler_runs_total.with_label_values(&[result.label()]);
        }
        for table in ["journal", "version"] {
            pruned_rows_total.with_label_values(&[table]);
        }
        for result in ["hit", "miss"] {
            zone_cache_lookups_total.with_label_values(&[result]);
        }

        Self {
            registry,
            database_up,
            db_connections,
            db_connections_max,
            zones_total,
            records_total,
            http_requests_total,
            http_request_duration_seconds,
            xfr_total,
            soa_queries_total,
            notify_sent_total,
            nsupdate_requests_total,
            zone_serial_bumps_total,
            pruned_rows_total,
            dnssec_zones_total,
            dnssec_keys_total,
            dnssec_rrsigs_expiring_total,
            dnssec_rrsigs_expired_total,
            dnssec_scheduler_runs_total,
            zone_cache_lookups_total,
            zone_cache_evictions_total,
            zone_cache_records,
        }
    }

    /// Encode every registered metric in the Prometheus text format.
    pub fn encode(&self) -> String {
        TextEncoder::new()
            .encode_to_string(&self.registry.gather())
            .unwrap_or_default()
    }
}

pub enum XfrResult {
    Ok,
    Refused,
    NotAuth,
    /// Answered over UDP with TC set; the transfer follows over TCP.
    Truncated,
    Error,
}

impl XfrResult {
    const ALL: [Self; 5] = [
        Self::Ok,
        Self::Refused,
        Self::NotAuth,
        Self::Truncated,
        Self::Error,
    ];

    /// The metric label value of this xfr result.
    fn label(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Refused => "refused",
            Self::NotAuth => "notauth",
            Self::Truncated => "truncated",
            Self::Error => "error",
        }
    }
}

/// A zone transfer's outcome, by query type. Non-transfer types are not
/// counted here, so the caller may pass whatever it was asked for.
pub fn track_xfr(qtype: Rtype, result: XfrResult) {
    let xfr_type = match qtype {
        Rtype::AXFR => "axfr",
        Rtype::IXFR => "ixfr",
        _ => return,
    };
    metrics()
        .xfr_total
        .with_label_values(&[xfr_type, result.label()])
        .inc();
}

pub enum SoaResult {
    Ok,
    Refused,
    NotAuth,
    Error,
}

impl SoaResult {
    const ALL: [Self; 4] = [Self::Ok, Self::Refused, Self::NotAuth, Self::Error];

    /// The metric label value of this SOA result.
    fn label(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Refused => "refused",
            Self::NotAuth => "notauth",
            Self::Error => "error",
        }
    }
}

/// Secondaries poll SOA on their refresh timer, so this is the question
/// bindizr answers most; the result says whether they are getting a serial.
pub fn track_soa(result: SoaResult) {
    metrics()
        .soa_queries_total
        .with_label_values(&[result.label()])
        .inc();
}

pub enum NsupdateResult {
    /// A TSIG failure answers with its own NOTAUTH, so it is kept apart from
    /// the NOTAUTH an update refused on its merits gets.
    TsigFailed,
    /// Every other outcome is named by the response code, a bounded set,
    /// never the free-form message.
    Rcode(Rcode),
}

impl NsupdateResult {
    const ALL: [Self; 11] = [
        Self::TsigFailed,
        Self::Rcode(Rcode::NOERROR),
        Self::Rcode(Rcode::FORMERR),
        Self::Rcode(Rcode::REFUSED),
        Self::Rcode(Rcode::YXDOMAIN),
        Self::Rcode(Rcode::YXRRSET),
        Self::Rcode(Rcode::NXDOMAIN),
        Self::Rcode(Rcode::NXRRSET),
        Self::Rcode(Rcode::NOTZONE),
        Self::Rcode(Rcode::SERVFAIL),
        Self::Rcode(Rcode::NOTIMP),
    ];

    /// The metric label value of this nsupdate result.
    fn label(&self) -> &'static str {
        let rcode = match self {
            Self::TsigFailed => return "tsig_failed",
            Self::Rcode(rcode) => *rcode,
        };
        match rcode {
            Rcode::NOERROR => "noerror",
            Rcode::FORMERR => "formerr",
            Rcode::REFUSED => "refused",
            Rcode::YXDOMAIN => "yxdomain",
            Rcode::YXRRSET => "yxrrset",
            Rcode::NXDOMAIN => "nxdomain",
            Rcode::NXRRSET => "nxrrset",
            Rcode::NOTZONE => "notzone",
            Rcode::SERVFAIL => "servfail",
            _ => "other",
        }
    }
}

/// Increment the counter for a dynamic update result.
pub fn track_nsupdate(result: NsupdateResult) {
    metrics()
        .nsupdate_requests_total
        .with_label_values(&[result.label()])
        .inc();
}

pub enum NotifyResult {
    Ok,
    Error,
    /// Nothing was sent, so it is kept apart from the send failures it would
    /// otherwise inflate.
    ResolveError,
}

impl NotifyResult {
    const ALL: [Self; 3] = [Self::Ok, Self::Error, Self::ResolveError];

    /// The metric label value of this notify result.
    fn label(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
            Self::ResolveError => "resolve_error",
        }
    }
}

/// Record a NOTIFY delivery result.
pub fn track_notify(result: NotifyResult) {
    metrics()
        .notify_sent_total
        .with_label_values(&[result.label()])
        .inc();
}

/// Count pruned journal and version rows separately so differences expose gaps that break IXFR
/// history.
pub fn track_pruned_rows(journal_rows: u64, version_rows: u64) {
    let metrics = metrics();
    metrics
        .pruned_rows_total
        .with_label_values(&["journal"])
        .inc_by(journal_rows);
    metrics
        .pruned_rows_total
        .with_label_values(&["version"])
        .inc_by(version_rows);
}

/// Increment the serial-advance counter before commit; rollbacks can therefore overcount advances.
pub fn track_serial_bump() {
    metrics().zone_serial_bumps_total.inc();
}

pub enum SchedulerResult {
    Ok,
    Error,
    /// The pass unwound; the scheduler itself survived.
    Panic,
}

impl SchedulerResult {
    const ALL: [Self; 3] = [Self::Ok, Self::Error, Self::Panic];

    /// The metric label value of this scheduler result.
    fn label(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Panic => "panic",
        }
    }
}

/// Increment the counter for a DNSSEC scheduler pass result.
pub fn track_dnssec_scheduler(result: SchedulerResult) {
    metrics()
        .dnssec_scheduler_runs_total
        .with_label_values(&[result.label()])
        .inc();
}

/// The pool's occupancy at scrape time.
pub fn track_db_pool(connections: u32, idle: u32, max: u32) {
    let metrics = metrics();
    metrics
        .db_connections
        .with_label_values(&["idle"])
        .set(i64::from(idle));
    metrics
        .db_connections
        .with_label_values(&["in_use"])
        .set(i64::from(connections.saturating_sub(idle)));
    metrics.db_connections_max.set(i64::from(max));
}

/// Record a zone-cache hit or miss.
pub fn track_zone_cache_lookup(hit: bool) {
    metrics()
        .zone_cache_lookups_total
        .with_label_values(&[if hit { "hit" } else { "miss" }])
        .inc();
}

/// What the cache holds after a store, and what it dropped to fit.
pub fn track_zone_cache_store(records: usize, evicted: usize) {
    let metrics = metrics();
    metrics.zone_cache_records.set(records as i64);
    metrics.zone_cache_evictions_total.inc_by(evicted as u64);
}
