use crate::cli::output::{OutputFormat, RecordRow, ZoneRow, print_output_with_table};
use crate::socket::client::DaemonSocketClient;
use crate::socket::types::DaemonCommandKind;
use bindizr_core::dns::name::to_fqdn_lowercase;
use bindizr_core::model::record::RecordType;
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand, Debug)]
pub(crate) enum GetCommand {
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
        /// Filter by minimum TTL
        #[arg(long)]
        min_ttl: Option<i64>,
        /// Filter by maximum TTL
        #[arg(long)]
        max_ttl: Option<i64>,
        /// Filter by serial
        #[arg(long)]
        serial: Option<i64>,
        /// Search zones by partial text
        #[arg(short = 'q', long)]
        search: Option<String>,
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
        /// Filter by minimum TTL
        #[arg(long)]
        min_ttl: Option<i64>,
        /// Filter by maximum TTL
        #[arg(long)]
        max_ttl: Option<i64>,
        /// Filter by priority
        #[arg(long)]
        priority: Option<i64>,
        /// Filter by minimum priority
        #[arg(long)]
        min_priority: Option<i64>,
        /// Filter by maximum priority
        #[arg(long)]
        max_priority: Option<i64>,
        /// Search records by partial text
        #[arg(short = 'q', long)]
        search: Option<String>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
}

pub(crate) async fn handle_command(subcommand: GetCommand) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    match subcommand {
        GetCommand::Zones {
            name,
            id,
            primary_ns,
            admin_email,
            ttl,
            min_ttl,
            max_ttl,
            serial,
            search,
            output,
        } => {
            let has_filters = id.is_some()
                || primary_ns.is_some()
                || admin_email.is_some()
                || ttl.is_some()
                || min_ttl.is_some()
                || max_ttl.is_some()
                || serial.is_some()
                || search.is_some();
            let filter_payload = || {
                json!({
                    "name": name,
                    "id": id,
                    "primary_ns": primary_ns,
                    "admin_email": admin_email,
                    "ttl": ttl,
                    "min_ttl": min_ttl,
                    "max_ttl": max_ttl,
                    "serial": serial,
                    "search": search,
                })
            };
            let mut data = if let Some(name) = name.as_deref() {
                if has_filters {
                    client
                        .send_command(DaemonCommandKind::ListZones, Some(filter_payload()))
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
                    .send_command(
                        DaemonCommandKind::ListZones,
                        has_filters.then(filter_payload),
                    )
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
                    min_ttl,
                    max_ttl,
                    serial,
                    search.as_deref(),
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
            min_ttl,
            max_ttl,
            priority,
            min_priority,
            max_priority,
            search,
            output,
        } => {
            let has_filters = zone.is_some()
                || name.is_some()
                || record_type.is_some()
                || value.is_some()
                || ttl.is_some()
                || min_ttl.is_some()
                || max_ttl.is_some()
                || priority.is_some()
                || min_priority.is_some()
                || max_priority.is_some()
                || search.is_some();
            let filter_payload = || {
                json!({
                    "zone_name": zone,
                    "name": name,
                    "record_type": record_type,
                    "value": value,
                    "ttl": ttl,
                    "min_ttl": min_ttl,
                    "max_ttl": max_ttl,
                    "priority": priority,
                    "min_priority": min_priority,
                    "max_priority": max_priority,
                    "search": search,
                })
            };

            let mut data = if let Some(id) = id {
                client
                    .send_command(DaemonCommandKind::GetRecord, Some(json!({ "id": id })))
                    .await?
                    .data
            } else if has_filters {
                client
                    .send_command(DaemonCommandKind::ListRecords, Some(filter_payload()))
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
                    RecordFilterArgs {
                        zone: zone.as_deref(),
                        name: name.as_deref(),
                        record_type: record_type.as_deref(),
                        value: value.as_deref(),
                        ttl,
                        min_ttl,
                        max_ttl,
                        priority,
                        min_priority,
                        max_priority,
                        search: search.as_deref(),
                    },
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
    min_ttl: Option<i64>,
    max_ttl: Option<i64>,
    serial: Option<i64>,
    search: Option<&str>,
) -> serde_json::Value {
    filter_items(data, |item| {
        matches_string(item, "name", name)
            && matches_i64(item, "id", id)
            && matches_string(item, "primary_ns", primary_ns)
            && matches_string(item, "admin_email", admin_email)
            && matches_i64(item, "ttl", ttl)
            && matches_min_i64(item, "ttl", min_ttl)
            && matches_max_i64(item, "ttl", max_ttl)
            && matches_i64(item, "serial", serial)
            && matches_search(item, &["name", "primary_ns", "admin_email"], search)
    })
}

struct RecordFilterArgs<'a> {
    zone: Option<&'a str>,
    name: Option<&'a str>,
    record_type: Option<&'a str>,
    value: Option<&'a str>,
    ttl: Option<i64>,
    min_ttl: Option<i64>,
    max_ttl: Option<i64>,
    priority: Option<i64>,
    min_priority: Option<i64>,
    max_priority: Option<i64>,
    search: Option<&'a str>,
}

fn filter_records(data: serde_json::Value, args: RecordFilterArgs<'_>) -> serde_json::Value {
    filter_items(data, |item| {
        matches_dns_string(item, "zone_name", args.zone)
            && matches_string(item, "name", args.name)
            && matches_string(item, "record_type", args.record_type)
            && matches_record_value(item, args.value)
            && matches_i64(item, "ttl", args.ttl)
            && matches_min_i64(item, "ttl", args.min_ttl)
            && matches_max_i64(item, "ttl", args.max_ttl)
            && matches_i64(item, "priority", args.priority)
            && matches_min_i64(item, "priority", args.min_priority)
            && matches_max_i64(item, "priority", args.max_priority)
            && matches_record_search(item, args.search)
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

fn matches_dns_string(item: &serde_json::Value, key: &str, expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| {
        item.get(key)
            .and_then(|value| value.as_str())
            .is_some_and(|actual| to_fqdn_lowercase(actual) == to_fqdn_lowercase(expected))
    })
}

fn matches_record_value(item: &serde_json::Value, expected: Option<&str>) -> bool {
    let ignore_case = item
        .get("record_type")
        .and_then(|value| value.as_str())
        .is_some_and(is_name_like_record_type);

    expected.is_none_or(|expected| match item.get("value") {
        Some(serde_json::Value::String(actual)) => values_match(actual, expected, ignore_case),
        Some(serde_json::Value::Array(values)) => {
            let segments = values
                .iter()
                .map(|value| value.as_str())
                .collect::<Option<Vec<_>>>();
            segments.is_some_and(|segments| {
                segments
                    .iter()
                    .any(|segment| values_match(segment, expected, ignore_case))
                    || values_match(&segments.join(""), expected, ignore_case)
            })
        }
        _ => false,
    })
}

fn matches_record_search(item: &serde_json::Value, expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| {
        let expected = expected.trim().to_ascii_lowercase();
        !expected.is_empty()
            && (["zone_name", "name", "record_type"].iter().any(|key| {
                item.get(key)
                    .and_then(|value| value.as_str())
                    .is_some_and(|actual| actual.to_ascii_lowercase().contains(&expected))
            }) || record_value_text(item)
                .is_some_and(|value| value.to_ascii_lowercase().contains(&expected)))
    })
}

fn matches_search(item: &serde_json::Value, keys: &[&str], expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| {
        let expected = expected.trim().to_ascii_lowercase();
        !expected.is_empty()
            && keys.iter().any(|key| {
                item.get(key)
                    .and_then(|value| value.as_str())
                    .is_some_and(|actual| actual.to_ascii_lowercase().contains(&expected))
            })
    })
}

fn record_value_text(item: &serde_json::Value) -> Option<String> {
    match item.get("value") {
        Some(serde_json::Value::String(value)) => Some(value.clone()),
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .map(|value| value.as_str())
            .collect::<Option<Vec<_>>>()
            .map(|segments| segments.join("")),
        _ => None,
    }
}

fn is_name_like_record_type(record_type: &str) -> bool {
    record_type
        .parse::<RecordType>()
        .is_ok_and(|record_type| record_type.is_name_like_value())
}

fn values_match(actual: &str, expected: &str, ignore_case: bool) -> bool {
    if ignore_case {
        actual
            .to_ascii_lowercase()
            .contains(&expected.trim().to_ascii_lowercase())
    } else {
        actual.contains(expected.trim())
    }
}

fn matches_i64(item: &serde_json::Value, key: &str, expected: Option<i64>) -> bool {
    expected.is_none_or(|expected| {
        item.get(key)
            .and_then(|value| value.as_i64())
            .is_some_and(|actual| actual == expected)
    })
}

fn matches_min_i64(item: &serde_json::Value, key: &str, expected: Option<i64>) -> bool {
    expected.is_none_or(|expected| {
        item.get(key)
            .and_then(|value| value.as_i64())
            .is_some_and(|actual| actual >= expected)
    })
}

fn matches_max_i64(item: &serde_json::Value, key: &str, expected: Option<i64>) -> bool {
    expected.is_none_or(|expected| {
        item.get(key)
            .and_then(|value| value.as_i64())
            .is_some_and(|actual| actual <= expected)
    })
}
