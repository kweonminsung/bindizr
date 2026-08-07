//! Adapter-local Prometheus metrics, served on the health listener.

use std::sync::OnceLock;

use prometheus::{Encoder, HistogramVec, IntCounterVec, Registry, TextEncoder};

/// Prometheus text exposition content type.
pub(crate) const TEXT_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

pub(crate) struct AdapterMetrics {
    registry: Registry,
    pub requests_total: IntCounterVec,
    pub request_duration_seconds: HistogramVec,
}

static METRICS: OnceLock<AdapterMetrics> = OnceLock::new();

/// Process-wide adapter metrics, created on first use.
pub(crate) fn metrics() -> &'static AdapterMetrics {
    METRICS.get_or_init(|| {
        let registry = Registry::new();

        let requests_total = IntCounterVec::new(
            prometheus::Opts::new(
                "bindizr_external_dns_requests_total",
                "Webhook requests handled by the bindizr ExternalDNS adapter",
            ),
            &["endpoint", "result"],
        )
        .expect("valid metric definition");
        registry
            .register(Box::new(requests_total.clone()))
            .expect("metric registers once");

        let request_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "bindizr_external_dns_request_duration_seconds",
                "Webhook request duration in the bindizr ExternalDNS adapter",
            ),
            &["endpoint"],
        )
        .expect("valid metric definition");
        registry
            .register(Box::new(request_duration_seconds.clone()))
            .expect("metric registers once");

        // Pre-create every label combination `server::track` emits: an empty
        // metric family fails text encoding, which would blank /metrics until
        // the first webhook request.
        let endpoints = [
            "negotiate",
            "records_get",
            "records_apply",
            "adjustendpoints",
        ];
        let results = ["ok", "client_error", "upstream_error", "error"];
        for endpoint in endpoints {
            for result in results {
                requests_total.with_label_values(&[endpoint, result]);
            }
            request_duration_seconds.with_label_values(&[endpoint]);
        }

        AdapterMetrics {
            registry,
            requests_total,
            request_duration_seconds,
        }
    })
}

impl AdapterMetrics {
    pub fn encode(&self) -> String {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        if encoder
            .encode(&self.registry.gather(), &mut buffer)
            .is_err()
        {
            return String::new();
        }
        String::from_utf8(buffer).unwrap_or_default()
    }
}
