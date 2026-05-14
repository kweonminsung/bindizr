use crate::database::model::record::{Record, RecordType};
use chrono::Utc;

/// Generate next serial number in YYYYMMDDNN format.
pub fn generate_serial(current_serial: Option<i32>) -> i32 {
    let now = Utc::now();
    let date_prefix = now.format("%Y%m%d").to_string().parse::<i32>().unwrap();
    let base_serial = date_prefix * 100;

    // If current serial is from today, increment it. Otherwise, start fresh with today's date.
    match current_serial {
        Some(serial) if serial >= base_serial => serial + 1,
        _ => base_serial,
    }
}

/// Convert name to FQDN by normalizing to a single trailing dot.
pub fn to_fqdn(name: &str) -> String {
    name.trim_end_matches('.').to_string() + "."
}

/// Convert FQDN to relative domain name within a zone.
pub fn to_relative_domain(fqdn: &str, zone_name: &str) -> String {
    let fqdn = to_fqdn(fqdn);
    let zone = to_fqdn(zone_name);

    if fqdn.eq_ignore_ascii_case(&zone) {
        return "@".to_string();
    }

    let fqdn_lower = fqdn.to_ascii_lowercase();
    let zone_lower = zone.to_ascii_lowercase();

    if fqdn_lower.ends_with(&zone_lower) {
        let relative_part = &fqdn[..fqdn.len() - zone.len()];
        relative_part.trim_end_matches('.').to_string()
    } else {
        fqdn.trim_end_matches('.').to_string()
    }
}

/// Check if a given name is within the bailiwick of a zone.
pub fn is_in_bailiwick(name: &str, zone_name: &str) -> bool {
    to_fqdn(name)
        .to_ascii_lowercase()
        .ends_with(&to_fqdn(zone_name).to_ascii_lowercase())
}

pub fn is_apex_name(name: &str, zone_name: &str) -> bool {
    name == "@" || to_fqdn(name).eq_ignore_ascii_case(&to_fqdn(zone_name))
}

/// Check if there are any A or AAAA records for the given host name (relative to the zone) in the provided record set.
pub fn has_glue_records_for(
    records: &[Record],
    host_relative_name: &str,
    except_id: Option<i32>,
) -> bool {
    records.iter().any(|r| {
        if except_id == Some(r.id) {
            return false;
        }

        r.name.eq_ignore_ascii_case(host_relative_name)
            && (r.record_type == RecordType::A || r.record_type == RecordType::AAAA)
    })
}
