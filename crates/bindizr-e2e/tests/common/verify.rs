//! The compose-mode check that the DNS secondaries agree with the API, and the
//! record a mutation is about to replace so its removal is checked too.

use std::collections::{HashMap, HashSet};

use reqwest::{Method, StatusCode};
use serde_json::Value;

use crate::common::{RECORD_PAGE_LIMIT, TestApp, dns};

/// The record a mutation is about to replace or remove, kept with the zone it
/// sits in, which decides whether DNS can be asked about it at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreviousRecordKey {
    zone_name: String,
    name: String,
    record_type: u16,
}

impl TestApp {
    /// Capture the record owner, type, and zone before an API mutation.
    pub(crate) async fn read_previous_record_key(
        &self,
        method: &Method,
        path: &str,
    ) -> Option<PreviousRecordKey> {
        if !matches!(*method, Method::PUT | Method::DELETE) || !path.starts_with("/records/") {
            return None;
        }

        let (status, body) = self.send_http(Method::GET, path, None).await;

        status.is_success().then(|| {
            let record = &body["record"];
            let (name, record_type) = dns::extract_record_key(record);

            PreviousRecordKey {
                zone_name: record["zone_name"]
                    .as_str()
                    .expect("record did not contain a zone name")
                    .to_string(),
                name,
                record_type,
            }
        })
    }

    /// Wait until secondary DNS answers match the API's records.
    pub(crate) async fn assert_dns_matches_api(
        &self,
        previous_record_key: Option<PreviousRecordKey>,
    ) {
        if self.dns_secondary_ports.is_empty() {
            return;
        }

        // Read every API page so all secondaries are checked against the complete zone.
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
                "failed to list records for DNS verification: {body}"
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

        // BIND9 will not load a catalog member without an apex NS, which a zone
        // created with apex_ns disabled, or stripped of it, lacks.
        // Listed record names are absolute, while zone names are bare.
        let is_apex = |record: &Value| {
            record["name"]
                .as_str()
                .map(|name| name.trim_end_matches('.'))
                == record["zone_name"].as_str()
        };
        let served_zone_names: HashSet<_> = records
            .iter()
            .filter(|record| record["type"] == "NS" && is_apex(record))
            .filter_map(|record| record["zone_name"].as_str().map(str::to_string))
            .collect();

        let mut expected: HashMap<(String, u16), Vec<Value>> = HashMap::new();

        for record in &records {
            let zone_name = record["zone_name"]
                .as_str()
                .expect("record did not contain a zone name");

            if !served_zone_names.contains(zone_name) {
                continue;
            }

            let name = record["name"]
                .as_str()
                .expect("record did not contain a name")
                .to_string();
            let record_type = record["type"]
                .as_str()
                .and_then(dns::parse_record_type)
                .expect("record contained an unsupported DNS type");
            expected
                .entry((name, record_type))
                .or_default()
                .push(dns::build_dns_expected_value(record, record_type));
        }

        // Wait for each name and type to converge on every configured secondary.
        for ((name, record_type), values) in &expected {
            for port in &self.dns_secondary_ports {
                dns::wait_for_dns_records(*port, name, *record_type, values).await;
            }
        }

        // A deleted name/type is absent from the API list but must also disappear in DNS.
        if let Some(previous) = previous_record_key
            && served_zone_names.contains(&previous.zone_name)
            && !expected.contains_key(&(previous.name.clone(), previous.record_type))
        {
            for port in &self.dns_secondary_ports {
                dns::wait_for_dns_records(*port, &previous.name, previous.record_type, &[]).await;
            }
        }
    }
}
