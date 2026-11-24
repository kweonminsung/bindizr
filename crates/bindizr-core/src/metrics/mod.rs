//! The daemon's Prometheus registry, held by its `Context` and shared by the
//! HTTP API and DNS layers.

mod notify_result;
mod nsupdate_result;
mod pruned_table;
mod scheduler_result;
mod soa_result;
mod xfr_result;
mod zone_cache_lookup;

pub use notify_result::NotifyResult;
pub use nsupdate_result::NsupdateResult;
use prometheus::core::Collector;
use prometheus::{
    Gauge, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder,
};
pub use scheduler_result::SchedulerResult;
pub use soa_result::SoaResult;
use thiserror::Error;
pub use xfr_result::XfrResult;

use crate::dns::DnsTransport;
use crate::metrics::pruned_table::PrunedTable;
use crate::metrics::zone_cache_lookup::ZoneCacheLookup;
use crate::model::transfer::TransferKind;

/// Content type of the Prometheus text exposition format.
pub const TEXT_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

/// The daemon's registered collectors, one set per process.
#[derive(Debug)]
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
    access_log_dropped_total: IntCounter,
    pub dnssec_zones_total: IntGauge,
    pub dnssec_keys_total: IntGaugeVec,
    pub dnssec_rrsigs_expiring_total: IntGauge,
    pub dnssec_rrsigs_expired_total: IntGauge,
    dnssec_scheduler_runs_total: IntCounterVec,
    zone_cache_lookups_total: IntCounterVec,
    zone_cache_evictions_total: IntCounter,
    zone_cache_records: IntGauge,
    /// Set by the daemon once every front end serves.
    pub started_at_seconds: Gauge,
}

/// A metric definition or registration the registry refused: a programming
/// error, since every definition is static.
#[derive(Debug, Error)]
#[error("failed to register a metric: {0}")]
pub struct RegisterMetricsError(#[source] prometheus::Error);

/// The Prometheus text encoder refused a gathered family.
#[derive(Debug, Error)]
#[error("failed to encode metrics: {0}")]
pub struct EncodeMetricsError(#[source] prometheus::Error);

/// Register a shared clone of a metric collector.
fn register<C: Collector + Clone + 'static>(
    registry: &Registry,
    collector: &C,
) -> Result<(), RegisterMetricsError> {
    registry
        .register(Box::new(collector.clone()))
        .map_err(RegisterMetricsError)
}

impl Metrics {
    /// Create and register the daemon's metric collectors.
    pub fn new() -> Result<Self, RegisterMetricsError> {
        let registry = Registry::new();

        let build_info = IntGaugeVec::new(
            Opts::new(
                "bindizr_build_info",
                "Build metadata; the value is always 1.",
            ),
            &["version"],
        )
        .map_err(RegisterMetricsError)?;
        build_info
            .with_label_values(&[env!("CARGO_PKG_VERSION")])
            .set(1);
        register(&registry, &build_info)?;

        let started_at_seconds = Gauge::new(
            "bindizr_started_at_seconds",
            "Unix time the daemon began serving.",
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &started_at_seconds)?;

        let database_up = IntGauge::new(
            "bindizr_database_up",
            "Whether the database probe of the last scrape succeeded (1) or failed (0).",
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &database_up)?;

        let db_connections = IntGaugeVec::new(
            Opts::new(
                "bindizr_db_connections",
                "Pooled database connections by state; `in_use` reaching \
                 `bindizr_db_connections_max` is the saturation every request then queues behind",
            ),
            &["state"],
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &db_connections)?;

        let db_connections_max = IntGauge::new(
            "bindizr_db_connections_max",
            "Connection ceiling the pool was built with, scaled to the host's cores",
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &db_connections_max)?;

        let zones_total = IntGauge::new(
            "bindizr_zones_total",
            "Number of zones, refreshed at scrape time.",
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &zones_total)?;

        let records_total = IntGauge::new(
            "bindizr_records_total",
            "Number of records, refreshed at scrape time.",
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &records_total)?;

        let http_requests_total = IntCounterVec::new(
            Opts::new("bindizr_http_requests_total", "HTTP API requests served."),
            &["method", "route", "status"],
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &http_requests_total)?;

        let http_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "bindizr_http_request_duration_seconds",
                "HTTP API request latency in seconds.",
            ),
            &["method", "route"],
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &http_request_duration_seconds)?;

        let xfr_total = IntCounterVec::new(
            Opts::new(
                "bindizr_xfr_total",
                "Zone transfer requests by kind, result, and transport.",
            ),
            &["kind", "result", "transport"],
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &xfr_total)?;

        let soa_queries_total = IntCounterVec::new(
            Opts::new(
                "bindizr_soa_queries_total",
                "SOA queries answered, by outcome; secondaries poll these on their refresh \
                 timer, so a rise in `refused` means one stopped being an enabled secondary",
            ),
            &["result"],
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &soa_queries_total)?;

        let notify_sent_total = IntCounterVec::new(
            Opts::new(
                "bindizr_notify_sent_total",
                "NOTIFY send attempts to secondaries, by outcome.",
            ),
            &["result"],
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &notify_sent_total)?;

        let nsupdate_requests_total = IntCounterVec::new(
            Opts::new(
                "bindizr_nsupdate_requests_total",
                "nsupdate requests processed (RFC 2136), by outcome.",
            ),
            &["result"],
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &nsupdate_requests_total)?;

        let zone_serial_bumps_total = IntCounter::new(
            "bindizr_zone_serial_bumps_total",
            "Committed zone serial writes across every update path.",
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &zone_serial_bumps_total)?;

        let pruned_rows_total = IntCounterVec::new(
            Opts::new(
                "bindizr_pruned_rows_total",
                "Rows the retention pass deleted, by table; a rate of zero while zones keep \
                 changing means the journal is growing without bound",
            ),
            &["table"],
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &pruned_rows_total)?;

        let access_log_dropped_total = IntCounter::new(
            "bindizr_access_log_dropped_total",
            "Access log rows dropped unsaved because the write queue was full or had \
             stopped; the requests were answered, only their rows are missing",
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &access_log_dropped_total)?;

        let dnssec_zones_total = IntGauge::new(
            "bindizr_dnssec_zones_total",
            "Number of DNSSEC-signed zones, refreshed at scrape time.",
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &dnssec_zones_total)?;

        let dnssec_keys_total = IntGaugeVec::new(
            Opts::new(
                "bindizr_dnssec_keys_total",
                "Number of DNSSEC keys by state, refreshed at scrape time.",
            ),
            &["state"],
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &dnssec_keys_total)?;

        let dnssec_rrsigs_expiring_total = IntGauge::new(
            "bindizr_dnssec_rrsigs_expiring_total",
            "Signatures inside the refresh window at scrape time; a value that \
             persists across scrapes means re-signing is falling behind.",
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &dnssec_rrsigs_expiring_total)?;

        let dnssec_rrsigs_expired_total = IntGauge::new(
            "bindizr_dnssec_rrsigs_expired_total",
            "Signatures already past their expiration; any at all mean resolvers are failing \
             part of a zone",
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &dnssec_rrsigs_expired_total)?;

        let dnssec_scheduler_runs_total = IntCounterVec::new(
            Opts::new(
                "bindizr_dnssec_scheduler_runs_total",
                "Hourly DNSSEC scheduler passes, by outcome.",
            ),
            &["result"],
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &dnssec_scheduler_runs_total)?;

        let zone_cache_lookups_total = IntCounterVec::new(
            Opts::new(
                "bindizr_zone_cache_lookups_total",
                "Zone-cache reads by outcome; a low hit ratio means transfers \
                 are reaching the database anyway.",
            ),
            &["result"],
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &zone_cache_lookups_total)?;

        let zone_cache_evictions_total = IntCounter::new(
            "bindizr_zone_cache_evictions_total",
            "Zones dropped to make room; a rising count beside a low hit ratio \
             means dns.transfer.cache_max_records is too small for the working set.",
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &zone_cache_evictions_total)?;

        let zone_cache_records = IntGauge::new(
            "bindizr_zone_cache_records",
            "Records the zone cache holds, against dns.transfer.cache_max_records.",
        )
        .map_err(RegisterMetricsError)?;
        register(&registry, &zone_cache_records)?;

        // Initialize every known label set so zero counters appear in metrics
        // instead of reading as missing data until the first event.
        for result in XfrResult::ALL {
            for kind in TransferKind::ALL {
                for transport in DnsTransport::ALL {
                    xfr_total.with_label_values(&[
                        kind.as_str(),
                        result.as_str(),
                        transport.as_str(),
                    ]);
                }
            }
        }

        for result in SoaResult::ALL {
            soa_queries_total.with_label_values(&[result.as_str()]);
        }

        for result in NsupdateResult::ALL {
            nsupdate_requests_total.with_label_values(&[result.metric_label()]);
        }

        for result in NotifyResult::ALL {
            notify_sent_total.with_label_values(&[result.as_str()]);
        }

        for result in SchedulerResult::ALL {
            dnssec_scheduler_runs_total.with_label_values(&[result.as_str()]);
        }

        for table in PrunedTable::ALL {
            pruned_rows_total.with_label_values(&[table.as_str()]);
        }

        for result in ZoneCacheLookup::ALL {
            zone_cache_lookups_total.with_label_values(&[result.as_str()]);
        }

        Ok(Self {
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
            access_log_dropped_total,
            dnssec_zones_total,
            dnssec_keys_total,
            dnssec_rrsigs_expiring_total,
            dnssec_rrsigs_expired_total,
            dnssec_scheduler_runs_total,
            zone_cache_lookups_total,
            zone_cache_evictions_total,
            zone_cache_records,
            started_at_seconds,
        })
    }

    /// Encode every registered metric in the Prometheus text format.
    pub fn encode(&self) -> Result<String, EncodeMetricsError> {
        TextEncoder::new()
            .encode_to_string(&self.registry.gather())
            .map_err(EncodeMetricsError)
    }
}

impl Metrics {
    /// Count a zone transfer's result by its kind and transport.
    pub fn track_xfr(&self, kind: TransferKind, transport: DnsTransport, result: XfrResult) {
        self.xfr_total
            .with_label_values(&[kind.as_str(), result.as_str(), transport.as_str()])
            .inc();
    }

    /// Count an SOA answer: secondaries poll SOA on their refresh timer, so this is
    /// the question bindizr answers most; the result says whether they are getting a serial.
    pub fn track_soa(&self, result: SoaResult) {
        self.soa_queries_total
            .with_label_values(&[result.as_str()])
            .inc();
    }

    /// Count an nsupdate result.
    pub fn track_nsupdate(&self, result: NsupdateResult) {
        self.nsupdate_requests_total
            .with_label_values(&[result.metric_label()])
            .inc();
    }

    /// Count a NOTIFY send result.
    pub fn track_notify(&self, result: NotifyResult) {
        self.notify_sent_total
            .with_label_values(&[result.as_str()])
            .inc();
    }

    /// Count pruned journal and version rows separately so differences expose gaps that break IXFR
    /// history.
    pub fn track_pruned_rows(&self, journal_rows: u64, version_rows: u64) {
        self.pruned_rows_total
            .with_label_values(&[PrunedTable::Journal.as_str()])
            .inc_by(journal_rows);
        self.pruned_rows_total
            .with_label_values(&[PrunedTable::Version.as_str()])
            .inc_by(version_rows);
    }

    /// Count the activity log rows the retention pass pruned.
    pub fn track_pruned_activity_log_rows(&self, rows: u64) {
        self.pruned_rows_total
            .with_label_values(&[PrunedTable::Activity.as_str()])
            .inc_by(rows);
    }

    /// Count the access log rows the retention pass pruned.
    pub fn track_pruned_access_log_rows(&self, rows: u64) {
        self.pruned_rows_total
            .with_label_values(&[PrunedTable::Access.as_str()])
            .inc_by(rows);
    }

    /// Count an access log row dropped because the write queue was full.
    pub fn track_access_log_dropped(&self) {
        self.access_log_dropped_total.inc();
    }

    /// Count the transfer log rows the retention pass pruned.
    pub fn track_pruned_transfer_log_rows(&self, rows: u64) {
        self.pruned_rows_total
            .with_label_values(&[PrunedTable::Transfer.as_str()])
            .inc_by(rows);
    }

    /// Count serial versions only after their transaction commits.
    pub fn track_serial_bumps(&self, count: u64) {
        self.zone_serial_bumps_total.inc_by(count);
    }

    /// Count a DNSSEC scheduler pass result.
    pub fn track_dnssec_scheduler(&self, result: SchedulerResult) {
        self.dnssec_scheduler_runs_total
            .with_label_values(&[result.as_str()])
            .inc();
    }

    /// Set the pool's occupancy at scrape time.
    pub fn set_db_pool_gauges(&self, connections: u32, idle: u32, max: u32) {
        self.db_connections
            .with_label_values(&["idle"])
            .set(i64::from(idle));
        self.db_connections
            .with_label_values(&["in_use"])
            .set(i64::from(connections.saturating_sub(idle)));
        self.db_connections_max.set(i64::from(max));
    }

    /// Count a zone-cache hit or miss.
    pub fn track_zone_cache_lookup(&self, hit: bool) {
        self.zone_cache_lookups_total
            .with_label_values(&[if hit {
                ZoneCacheLookup::Hit
            } else {
                ZoneCacheLookup::Miss
            }
            .as_str()])
            .inc();
    }

    /// Count what the cache dropped to fit after a store, and set what it now holds.
    pub fn track_zone_cache_store(&self, records: usize, evicted: usize) {
        self.zone_cache_records.set(records as i64);
        self.zone_cache_evictions_total.inc_by(evicted as u64);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// Collect one label's distinct values from the actual Prometheus exposition.
    pub(crate) fn metric_labels(metric_name: &str, label_name: &str) -> Vec<String> {
        let output = Metrics::new().unwrap().encode().unwrap();
        let prefix = format!("{metric_name}{{");
        let label_prefix = format!("{label_name}=\"");
        let mut labels = BTreeSet::new();

        for line in output.lines().filter(|line| line.starts_with(&prefix)) {
            let (_, fields) = line.split_once('{').unwrap();
            let (fields, _) = fields.split_once('}').unwrap();
            for field in fields.split(',') {
                if let Some(value) = field.strip_prefix(&label_prefix) {
                    labels.insert(value.strip_suffix('"').unwrap().to_string());
                }
            }
        }

        labels.into_iter().collect()
    }
}
