use crate::model::record::{Record, RecordType};
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

    if is_same_or_subdomain_fqdn(&fqdn_lower, &zone_lower) {
        let relative_part = &fqdn[..fqdn.len() - zone.len()];
        relative_part.trim_end_matches('.').to_string()
    } else {
        fqdn.trim_end_matches('.').to_string()
    }
}

/// Check if a given name is within the bailiwick of a zone.
pub fn is_in_bailiwick(name: &str, zone_name: &str) -> bool {
    let name = to_fqdn(name).to_ascii_lowercase();
    let zone = to_fqdn(zone_name).to_ascii_lowercase();

    is_same_or_subdomain_fqdn(&name, &zone)
}

fn is_same_or_subdomain_fqdn(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{}", zone))
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

#[cfg(test)]
mod tests {
    use super::{is_in_bailiwick, to_relative_domain};

    #[test]
    fn is_in_bailiwick_accepts_apex_and_subdomain() {
        assert!(is_in_bailiwick("example.com.", "example.com."));
        assert!(is_in_bailiwick("ns.example.com.", "example.com."));
    }

    #[test]
    fn is_in_bailiwick_rejects_sibling_suffix_match() {
        assert!(!is_in_bailiwick("notexample.com.", "example.com."));
        assert!(!is_in_bailiwick("ns.notexample.com.", "example.com."));
    }

    #[test]
    fn to_relative_domain_converts_only_zone_apex_and_subdomains() {
        assert_eq!(to_relative_domain("example.com.", "example.com."), "@");
        assert_eq!(to_relative_domain("ns.example.com.", "example.com."), "ns");
        assert_eq!(
            to_relative_domain("notexample.com.", "example.com."),
            "notexample.com"
        );
    }
}
