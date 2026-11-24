//! The compose-mode check that the DNS secondaries agree with the API, and the
//! record a mutation is about to replace so its removal is checked too.

use std::collections::{HashMap, HashSet};

use reqwest::Method;
use serde_json::Value;

use crate::common::{TestApp, dns};

/// The record a mutation is about to replace or remove, kept with the zone it
/// sits in, which decides whether DNS can be asked about it at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreviousRecordKey {
    zone_name: String,
    name: String,
    record_type: u16,
}

impl TestApp {
    /// Capture the record owner, type, and zone before a mutation addressed by ID.
    pub(crate) async fn read_previous_record_key(&self, path: &str) -> Option<PreviousRecordKey> {
        if !self.has_dns_secondaries() {
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

        let records = self
            .list_all_items(&format!("/records?search={}", self.namespace))
            .await;

        // The catalog lists the enabled zones alone, so only they are served.
        let enabled_zone_names: HashSet<_> = self
            .list_all_items(&format!("/zones?enabled=true&search={}", self.namespace))
            .await
            .into_iter()
            .map(|zone| zone["name"].as_str().expect("zone has a name").to_string())
            .collect();

        // An enabled zone is served only with an apex NS: BIND9 will not load
        // a catalog member without one, which a zone stripped of it lacks.
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
            .filter(|zone_name| enabled_zone_names.contains(zone_name))
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
