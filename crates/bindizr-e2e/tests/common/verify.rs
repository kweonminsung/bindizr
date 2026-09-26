//! The compose-mode check that the DNS secondaries agree with the API, and the
//! record a mutation is about to replace so its removal is checked too.

use std::collections::{HashMap, HashSet};

use reqwest::{Method, StatusCode};
use serde_json::Value;

use crate::common::{
    RECORD_PAGE_LIMIT, TestApp,
    dns::{build_dns_expected_value, dns_record_type, extract_dns_key, wait_for_dns_records},
};

/// Render a name with the trailing dot record payloads carry, so a zone taken
/// from a request path compares against the one a record names.
pub(crate) fn to_fqdn(name: &str) -> String {
    format!("{}.", name.trim_end_matches('.'))
}

/// The record a mutation is about to replace or remove, kept with the zone it
/// sits in, which decides whether DNS can be asked about it at all.
pub(crate) struct PreviousDnsKey {
    pub(crate) zone_name: String,
    pub(crate) name: String,
    pub(crate) record_type: u16,
}

impl TestApp {
    /// Capture the record owner, type, and zone before an API mutation.
    pub(crate) async fn read_previous_dns_key(
        &self,
        method: &Method,
        path: &str,
    ) -> Option<PreviousDnsKey> {
        if !matches!(*method, Method::PUT | Method::DELETE) {
            return None;
        }

        if path.starts_with("/records/") {
            let (status, body) = self.send_http(Method::GET, path, None).await;
            return status.is_success().then(|| {
                let record = &body["record"];
                let (name, record_type) = extract_dns_key(record);
                PreviousDnsKey {
                    zone_name: record["zone_name"]
                        .as_str()
                        .expect("record did not contain a zone name")
                        .to_string(),
                    name,
                    record_type,
                }
            });
        }

        if let Some(zone_name) = path.strip_prefix("/zones/") {
            return Some(PreviousDnsKey {
                zone_name: to_fqdn(zone_name),
                name: to_fqdn(zone_name),
                record_type: 6,
            });
        }

        None
    }

    /// Wait until secondary DNS answers match the API's records.
    pub(crate) async fn assert_dns_matches_api(&self, previous_dns_key: Option<PreviousDnsKey>) {
        if self.dns_secondary_ports.is_empty() {
            return;
        }

        // Use the API's current records as the expected state for all
        // secondaries. Read every page: one short of the whole set would call
        // a propagated record missing, or a split record set half-served.
        let mut records = Vec::new();
        let mut offset = 0u64;
        loop {
            let (status, body) = self
                .send_http(
                    Method::GET,
                    &format!(
                        "/records?search={}&limit={RECORD_PAGE_LIMIT}&offset={offset}",
                        self.namespace
                    ),
                    None,
                )
                .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "failed to list records for DNS verification"
            );
            let page = body["items"]
                .as_array()
                .expect("record list response did not contain items")
                .clone();
            let read = page.len();
            records.extend(page);
            let total = body["pagination"]["total"]
                .as_u64()
                .expect("record list response did not contain a total");
            offset += read as u64;
            if read == 0 || offset >= total {
                break;
            }
        }

        // BIND9 loads no zone whose apex carries no NS, and bindizr leaves
        // that record to the operator, so such a zone reaches no secondary.
        let served_zones = records
            .iter()
            .filter(|record| record["type"] == "NS" && record["name"] == record["zone_name"])
            .filter_map(|record| record["zone_name"].as_str().map(str::to_string))
            .collect::<HashSet<_>>();

        let mut expected = HashMap::<(String, u16), Vec<Value>>::new();
        for record in &records {
            let zone_name = record["zone_name"]
                .as_str()
                .expect("record did not contain a zone name");
            if !served_zones.contains(zone_name) {
                continue;
            }
            let name = record["name"]
                .as_str()
                .expect("record did not contain a name")
                .to_string();
            let record_type = record["type"]
                .as_str()
                .and_then(dns_record_type)
                .expect("record contained an unsupported DNS type");
            expected
                .entry((name, record_type))
                .or_default()
                .push(build_dns_expected_value(record, record_type));
        }

        // Wait for each name and type to converge on every configured secondary.
        for ((name, record_type), values) in &expected {
            for port in &self.dns_secondary_ports {
                wait_for_dns_records(*port, name, *record_type, values).await;
            }
        }

        // A deleted name/type is absent from the API list but must also disappear in DNS.
        if let Some(previous) = previous_dns_key
            && served_zones.contains(&previous.zone_name)
            && !expected.contains_key(&(previous.name.clone(), previous.record_type))
        {
            for port in &self.dns_secondary_ports {
                wait_for_dns_records(*port, &previous.name, previous.record_type, &[]).await;
            }
        }
    }
}
