use crate::cli::output::{OutputFormat, RecordRow, ZoneRow, print_output_with_table};
use crate::socket::client::DaemonSocketClient;
use crate::socket::dto::DaemonCommandKind;
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand, Debug)]
pub enum GetCommand {
    /// Get zones
    #[command(
        aliases = ["zone"]
    )]
    Zones {
        /// The name of the zone (optional)
        name: Option<String>,
        /// Filter by zone ID
        #[arg(long)]
        id: Option<i64>,
        /// Filter by primary name server
        #[arg(long)]
        primary_ns: Option<String>,
        /// Filter by admin email
        #[arg(long)]
        admin_email: Option<String>,
        /// Filter by TTL
        #[arg(long)]
        ttl: Option<i64>,
        /// Filter by serial
        #[arg(long)]
        serial: Option<i64>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Get records
    #[command(
        aliases = ["record"]
    )]
    Records {
        /// The record ID (optional)
        id: Option<i32>,
        /// Filter by zone name
        #[arg(short, long)]
        zone: Option<String>,
        /// Filter by record name
        #[arg(long)]
        name: Option<String>,
        /// Filter by record type
        #[arg(long, aliases = ["type"])]
        record_type: Option<String>,
        /// Filter by record value
        #[arg(long)]
        value: Option<String>,
        /// Filter by TTL
        #[arg(long)]
        ttl: Option<i64>,
        /// Filter by priority
        #[arg(long)]
        priority: Option<i64>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
}

pub async fn handle_command(subcommand: GetCommand) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    match subcommand {
        GetCommand::Zones {
            name,
            id,
            primary_ns,
            admin_email,
            ttl,
            serial,
            output,
        } => {
            let has_filters = id.is_some()
                || primary_ns.is_some()
                || admin_email.is_some()
                || ttl.is_some()
                || serial.is_some();
            let mut data = if let Some(name) = name.as_deref() {
                if has_filters {
                    client
                        .send_command(DaemonCommandKind::ListZones, None)
                        .await?
                        .data
                } else {
                    client
                        .send_command(DaemonCommandKind::GetZone, Some(json!({ "name": name })))
                        .await?
                        .data
                }
            } else {
                client
                    .send_command(DaemonCommandKind::ListZones, None)
                    .await?
                    .data
            };

            if has_filters || matches!(data, serde_json::Value::Array(_)) {
                data = filter_zones(
                    data,
                    name.as_deref(),
                    id,
                    primary_ns.as_deref(),
                    admin_email.as_deref(),
                    ttl,
                    serial,
                );
            }

            print_output_with_table(&data, output, |data| {
                if let Some(arr) = data.as_array() {
                    arr.iter()
                        .filter_map(|v| ZoneRow::from_json(v).ok())
                        .collect()
                } else {
                    vec![
                        ZoneRow::from_json(data).unwrap_or_else(|_| panic!("Failed to parse zone")),
                    ]
                }
            })?;
        }
        GetCommand::Records {
            id,
            zone,
            name,
            record_type,
            value,
            ttl,
            priority,
            output,
        } => {
            let has_filters = zone.is_some()
                || name.is_some()
                || record_type.is_some()
                || value.is_some()
                || ttl.is_some()
                || priority.is_some();

            let mut data = if let Some(id) = id {
                client
                    .send_command(DaemonCommandKind::GetRecord, Some(json!({ "id": id })))
                    .await?
                    .data
            } else if let Some(zone_name) = zone.as_deref() {
                client
                    .send_command(
                        DaemonCommandKind::ListRecords,
                        Some(json!({ "zone_name": zone_name })),
                    )
                    .await?
                    .data
            } else {
                client
                    .send_command(DaemonCommandKind::ListRecords, None)
                    .await?
                    .data
            };

            if has_filters || matches!(data, serde_json::Value::Array(_)) {
                data = filter_records(
                    data,
                    zone.as_deref(),
                    name.as_deref(),
                    record_type.as_deref(),
                    value.as_deref(),
                    ttl,
                    priority,
                );
            }

            print_output_with_table(&data, output, |data| {
                if let Some(arr) = data.as_array() {
                    arr.iter()
                        .filter_map(|v| RecordRow::from_json(v).ok())
                        .collect()
                } else {
                    vec![
                        RecordRow::from_json(data)
                            .unwrap_or_else(|_| panic!("Failed to parse record")),
                    ]
                }
            })?;
        }
    }

    Ok(())
}

fn filter_zones(
    data: serde_json::Value,
    name: Option<&str>,
    id: Option<i64>,
    primary_ns: Option<&str>,
    admin_email: Option<&str>,
    ttl: Option<i64>,
    serial: Option<i64>,
) -> serde_json::Value {
    filter_items(data, |item| {
        matches_string(item, "name", name)
            && matches_i64(item, "id", id)
            && matches_string(item, "primary_ns", primary_ns)
            && matches_string(item, "admin_email", admin_email)
            && matches_i64(item, "ttl", ttl)
            && matches_i64(item, "serial", serial)
    })
}

fn filter_records(
    data: serde_json::Value,
    zone: Option<&str>,
    name: Option<&str>,
    record_type: Option<&str>,
    value: Option<&str>,
    ttl: Option<i64>,
    priority: Option<i64>,
) -> serde_json::Value {
    filter_items(data, |item| {
        matches_string(item, "zone_name", zone)
            && matches_string(item, "name", name)
            && matches_string(item, "record_type", record_type)
            && matches_record_value(item, value)
            && matches_i64(item, "ttl", ttl)
            && matches_i64(item, "priority", priority)
    })
}

fn filter_items(
    data: serde_json::Value,
    matches: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    match data {
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().filter(matches).collect())
        }
        item if matches(&item) => item,
        _ => serde_json::Value::Array(Vec::new()),
    }
}

fn matches_string(item: &serde_json::Value, key: &str, expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| {
        item.get(key)
            .and_then(|value| value.as_str())
            .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
    })
}

fn matches_record_value(item: &serde_json::Value, expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| match item.get("value") {
        Some(serde_json::Value::String(actual)) => actual.eq_ignore_ascii_case(expected),
        Some(serde_json::Value::Array(values)) => {
            let segments = values
                .iter()
                .map(|value| value.as_str())
                .collect::<Option<Vec<_>>>();
            segments.is_some_and(|segments| {
                segments
                    .iter()
                    .any(|segment| segment.eq_ignore_ascii_case(expected))
                    || segments.join("").eq_ignore_ascii_case(expected)
            })
        }
        _ => false,
    })
}

fn matches_i64(item: &serde_json::Value, key: &str, expected: Option<i64>) -> bool {
    expected.is_none_or(|expected| {
        item.get(key)
            .and_then(|value| value.as_i64())
            .is_some_and(|actual| actual == expected)
    })
}

#[cfg(test)]
mod tests {
    use super::filter_records;
    use serde_json::json;

    #[test]
    fn filter_records_matches_txt_value_array_segment() {
        let data = json!([
            {"record_type": "TXT", "value": ["v=spf1 ", "include:example.net"], "ttl": 300},
            {"record_type": "TXT", "value": ["other"], "ttl": 300}
        ]);

        let filtered = filter_records(
            data,
            None,
            None,
            None,
            Some("include:example.net"),
            None,
            None,
        );

        assert_eq!(filtered.as_array().unwrap().len(), 1);
    }

    #[test]
    fn filter_records_matches_txt_value_array_joined_segments() {
        let data = json!([
            {"record_type": "TXT", "value": ["v=spf1 ", "include:example.net"], "ttl": 300},
            {"record_type": "TXT", "value": ["other"], "ttl": 300}
        ]);

        let filtered = filter_records(
            data,
            None,
            None,
            None,
            Some("v=spf1 include:example.net"),
            None,
            None,
        );

        assert_eq!(filtered.as_array().unwrap().len(), 1);
    }
}
