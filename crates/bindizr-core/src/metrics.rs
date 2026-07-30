//! Process-wide Prometheus registry shared by the HTTP API and DNS layers.

use std::{
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use prometheus::{
    Gauge, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder, core::Collector,
};

/// Content type of the Prometheus text exposition format.
pub const TEXT_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

pub struct Metrics {
    registry: Registry,
    pub database_up: IntGauge,
    pub zones_total: IntGauge,
    pub records_total: IntGauge,
    pub http_requests_total: IntCounterVec,
    pub http_request_duration_seconds: HistogramVec,
    pub xfr_total: IntCounterVec,
    pub notify_sent_total: IntCounterVec,
    pub nsupdate_requests_total: IntCounterVec,
    pub zone_serial_bumps_total: IntCounter,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Global registry. First touched at daemon startup so
/// `bindizr_started_at_seconds` reflects process start.
pub fn metrics() -> &'static Metrics {
    METRICS.get_or_init(Metrics::new)
}

fn register<C: Collector + Clone + 'static>(registry: &Registry, collector: &C) {
    registry
        .register(Box::new(collector.clone()))
        .expect("metric registered twice");
}

impl Metrics {
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

        Self {
            registry,
            database_up,
            zones_total,
            records_total,
            http_requests_total,
            http_request_duration_seconds,
            xfr_total,
            notify_sent_total,
            nsupdate_requests_total,
            zone_serial_bumps_total,
        }
    }

    /// Encode every registered metric in the Prometheus text format.
    pub fn encode(&self) -> String {
        TextEncoder::new()
            .encode_to_string(&self.registry.gather())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_includes_build_info_and_startup_gauges() {
        let text = metrics().encode();
        assert!(text.contains("bindizr_build_info"));
        assert!(text.contains("bindizr_started_at_seconds"));
    }
}
