pub mod utils;

use crate::config::BINDIZR_CONF_DIR;
use crate::database::get_zone_repository;
use crate::database::{
    get_record_repository,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
};
use crate::{log_error, log_info};
use crate::serializer::utils::{to_bind_rname, to_fqdn, to_relative_domain};

use std::collections::HashMap;
use std::fmt::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use tokio::fs;
use tokio::sync::Mutex;

pub fn initialize() {
    log_info!("Serializer initialized");
    SERIALIZER.get_or_init(Serializer::new);
}

pub struct Serializer {
    writing: Mutex<()>,
}

impl Serializer {
    fn new() -> Self {
        Serializer {
            writing: Mutex::new(()),
        }
    }

    pub async fn write_config_sync(&self) -> Result<(), String> {
        let _guard = self.writing.lock().await;
        Self::write_config().await
    }

    // Write DNS configuration files
    async fn write_config() -> Result<(), String> {
        let zones = Self::get_zones().await;

        let bindizr_config_dir = PathBuf::from(BINDIZR_CONF_DIR);
        match fs::try_exists(&bindizr_config_dir).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(format!(
                    "Bindizr config directory does not exist: {}",
                    BINDIZR_CONF_DIR
                ));
            }
            Err(e) => {
                return Err(format!(
                    "Failed to check bindizr config directory: {}: {}",
                    BINDIZR_CONF_DIR, e
                ));
            }
        }

        // Prepare directory for writing
        let zone_config_dir = bindizr_config_dir.join("zones");
        match fs::try_exists(&zone_config_dir).await {
            Ok(true) => {
                if let Err(e) = fs::remove_dir_all(&zone_config_dir).await {
                    return Err(format!(
                        "Failed to remove existing zone config directory: {}: {}",
                        zone_config_dir.display(),
                        e
                    ));
                }
            }
            Ok(false) => {} // Directory doesn't exist, will be created next
            Err(e) => {
                return Err(format!(
                    "Failed to check zone config directory: {}: {}",
                    zone_config_dir.display(),
                    e
                ));
            }
        }
        if let Err(e) = fs::create_dir_all(&zone_config_dir).await {
            return Err(format!(
                "Failed to create zone config directory: {}: {}",
                zone_config_dir.display(),
                e
            ));
        }

        // Write include zone config file
        let include_zone_config =
            Self::serialize_include_zone_config(&zone_config_dir.display().to_string(), &zones);
        let named_conf_path = zone_config_dir.join("named.conf");
        if let Err(e) = fs::write(&named_conf_path, include_zone_config).await {
            return Err(format!(
                "Failed to write to file: {}: {}",
                named_conf_path.display(),
                e
            ));
        }

        // Fetch all records at once to avoid N+1 query problem
        let all_records = Self::get_all_records().await;

        // Group records by zone_id for efficient lookup
        let mut records_by_zone: HashMap<i32, Vec<Record>> = HashMap::new();
        for record in all_records {
            records_by_zone
                .entry(record.zone_id)
                .or_default()
                .push(record);
        }

        // Write zone files
        for zone in zones {
            let records = records_by_zone
                .get(&zone.id)
                .map_or(&[][..], |v| v.as_slice());
            let serialized_data = Self::serialize_zone(&zone, records);

            let file_path = zone_config_dir.join(format!("{}.zone", zone.name));
            if let Err(e) = fs::write(&file_path, serialized_data).await {
                return Err(format!(
                    "Failed to write to file: {}: {}",
                    file_path.display(),
                    e
                ));
            }
        }

        Ok(())
    }

    async fn get_zones() -> Vec<Zone> {
        let zone_repository = get_zone_repository();

        zone_repository.get_all().await.unwrap_or_else(|e| {
            log_error!("Failed to fetch zones: {}", e);
            Vec::new()
        })
    }

    async fn get_all_records() -> Vec<Record> {
        let record_repository = get_record_repository();

        record_repository.get_all().await.unwrap_or_else(|e| {
            log_error!("Failed to fetch all records: {}", e);
            Vec::new()
        })
    }

    fn serialize_include_zone_config(zone_config_dir: &str, zones: &[Zone]) -> String {
        let mut output = String::new();

        for zone in zones {
            writeln!(
                &mut output,
                "zone \"{}\" {{ type master; file \"{}/{}.zone\"; }};",
                zone.name, zone_config_dir, zone.name
            )
            .unwrap();
        }

        output
    }

    pub fn serialize_zone(zone: &Zone, records: &[Record]) -> String {
        let mut output = String::new();

        // SOA record
        writeln!(
            &mut output,
            r#"; Automatically generated zone file
$TTL {}
{} IN SOA {} {} (
        {} ; serial
        {} ; refresh
        {} ; retry
        {} ; expire
        {} ) ; minimum TTL
"#,
            zone.ttl,
            to_fqdn(&zone.name),
            to_fqdn(&zone.primary_ns),
            to_bind_rname(&zone.admin_email),
            zone.serial,
            zone.refresh,
            zone.retry,
            zone.expire,
            zone.minimum_ttl,
        )
        .unwrap();

        // Add NS, A, AAAA records for the primary NS
        writeln!(
            &mut output,
            "@ IN NS {}",
            to_fqdn(&zone.primary_ns)
        )
        .unwrap();

        if let Some(ip) = &zone.primary_ns_ip {
            writeln!(
                &mut output,
                "{} IN A {}",
                to_relative_domain(&to_fqdn(&zone.primary_ns), &zone.name),
                ip
            )
            .unwrap();
        }
        if let Some(ipv6) = &zone.primary_ns_ipv6 {
            writeln!(
                &mut output,
                "{} IN AAAA {}",
                to_relative_domain(&to_fqdn(&zone.primary_ns), &zone.name),
                ipv6
            )
            .unwrap();
        }

        for record in records {
            let name = if record.name == "@" {
                "@"
            } else {
                &record.name
            };

            match record.record_type {
                RecordType::A | RecordType::AAAA => {
                    if let Some(ttl) = record.ttl {
                        writeln!(
                            &mut output,
                            "{} {} IN {} {}",
                            name, ttl, record.record_type, record.value
                        )
                    } else {
                        writeln!(
                            &mut output,
                            "{} IN {} {}",
                            name, record.record_type, record.value
                        )
                    }
                    .unwrap();
                }
                // NS, CNAME, PTR use FQDN for value
                RecordType::CNAME | RecordType::NS | RecordType::PTR => {
                    if let Some(ttl) = record.ttl {
                        writeln!(
                            &mut output,
                            "{} {} IN {} {}",
                            name,
                            record.record_type,
                            ttl,
                            to_fqdn(&record.value)
                        )
                    } else {
                        writeln!(
                            &mut output,
                            "{} IN {} {}",
                            name,
                            record.record_type,
                            to_fqdn(&record.value)
                        )
                    }
                    .unwrap();
                }
                RecordType::MX => {
                    let priority = record.priority.unwrap_or(10);
                    if let Some(ttl) = record.ttl {
                        writeln!(
                            &mut output,
                            "{} {} IN MX {} {}",
                            name,
                            ttl,
                            priority,
                            to_fqdn(&record.value)
                        )
                    } else {
                        writeln!(
                            &mut output,
                            "{} IN MX {} {}",
                            name,
                            priority,
                            to_fqdn(&record.value)
                        )
                    }
                    .unwrap();
                }
                RecordType::SRV => {
                    // SRV is in the order of priority, weight, port, and target.
                    // e.g.: _sip._tcp 3600 IN SRV 10 60 5060 sipserver.example.com.
                    let parts: Vec<&str> = record.value.split_whitespace().collect();
                    if parts.len() == 3 {
                        let priority = record.priority.unwrap_or(10);
                        if let Some(ttl) = record.ttl {
                            writeln!(
                                &mut output,
                                "{} {} IN SRV {} {} {} {}",
                                name,
                                ttl,
                                priority,                 // default priority
                                parts[0],                 // weight
                                parts[1],                 // port
                                to_fqdn(parts[2]), // target
                            )
                        } else {
                            writeln!(
                                &mut output,
                                "{} IN SRV {} {} {} {}",
                                name,
                                priority,                 // default priority
                                parts[0],                 // weight
                                parts[1],                 // port
                                to_fqdn(parts[2]), // target
                            )
                        }
                        .unwrap();
                    }
                }
                RecordType::SOA => {
                    // Mostly SOA is automatically generated, so ignore it or process it separately.
                    if let Some(ttl) = record.ttl {
                        writeln!(
                            &mut output,
                            "{} {} IN SOA {}",
                            to_fqdn(name),
                            ttl,
                            record.value
                        )
                    } else {
                        writeln!(
                            &mut output,
                            "{} IN SOA {}",
                            to_fqdn(name),
                            record.value
                        )
                    }
                    .unwrap();
                }
                RecordType::TXT => {
                    let value = record.value.trim_matches('"'); // Remove surrounding quotes if any

                    // RFC 1035: A single TXT record can have multiple segments, each up to 255 bytes.
                    const MAX_TXT_SEGMENT_LEN: usize = 255;

                    let mut segments = Vec::new();
                    let mut current = String::new();
                    for ch in value.chars() {
                        if current.len() + ch.len_utf8() > MAX_TXT_SEGMENT_LEN {
                            segments.push(current);
                            current = String::new();
                        }
                        current.push(ch);
                    }
                    if !current.is_empty() {
                        segments.push(current);
                    }

                    if segments.len() == 1 {
                        // Single-segment TXT record
                        if let Some(ttl) = record.ttl {
                            writeln!(&mut output, "{} {} IN TXT \"{}\"", name, ttl, segments[0])
                        } else {
                            writeln!(&mut output, "{} IN TXT \"{}\"", name, segments[0])
                        }
                        .unwrap();
                    } else {
                        // Multi-segment TXT record
                        write!(&mut output, "{} ", name).unwrap();
                        if let Some(ttl) = record.ttl {
                            write!(&mut output, "{} ", ttl).unwrap();
                        }
                        write!(&mut output, "IN TXT").unwrap();
                        for seg in &segments {
                            write!(&mut output, " \"{}\"", seg).unwrap();
                        }
                        writeln!(&mut output).unwrap();
                    }
                }
            }
        }

        output
    }
}

pub static SERIALIZER: OnceLock<Serializer> = OnceLock::new();

pub fn get_serializer() -> &'static Serializer {
    SERIALIZER.get().expect("Serializer is not initialized")
}
