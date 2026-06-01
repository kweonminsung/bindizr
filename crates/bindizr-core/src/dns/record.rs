use crate::model::record::RecordType;

use super::{name::to_fqdn_lowercase, txt};

pub fn display_record_owner_name(stored_name: &str, zone_name: &str) -> String {
    let zone_fqdn = to_fqdn_lowercase(zone_name);
    let trimmed = stored_name.trim();

    if trimmed == "@" {
        return zone_fqdn;
    }

    if trimmed.ends_with('.') {
        return to_fqdn_lowercase(trimmed);
    }

    let candidate = to_fqdn_lowercase(trimmed);
    if candidate == zone_fqdn || candidate.ends_with(&format!(".{}", zone_fqdn)) {
        candidate
    } else {
        to_fqdn_lowercase(&format!("{}.{}", trimmed, zone_fqdn))
    }
}

pub fn display_record_value(value: &str, record_type: &RecordType) -> String {
    if *record_type == RecordType::TXT {
        return match txt::decode_raw_txt_value(value) {
            Some(txt::DecodedTxtValue::String(value)) => value,
            Some(txt::DecodedTxtValue::Segments(segments)) => segments.join(""),
            None => value.to_string(),
        };
    }

    match record_type {
        RecordType::CNAME | RecordType::NS | RecordType::PTR => to_fqdn_lowercase(value),
        RecordType::MX | RecordType::SRV => display_last_name_field(value),
        _ => value.to_string(),
    }
}

fn display_last_name_field(value: &str) -> String {
    let mut fields = value
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let Some(last) = fields.pop() else {
        return value.to_string();
    };

    fields.push(to_fqdn_lowercase(&last));
    fields.join(" ")
}

#[cfg(test)]
mod tests {
    use super::{display_record_owner_name, display_record_value};
    use crate::model::record::RecordType;

    #[test]
    fn display_record_owner_name_returns_absolute_fqdn() {
        let zone = "test.example.com";

        assert_eq!(display_record_owner_name("@", zone), "test.example.com.");
        assert_eq!(
            display_record_owner_name("a1", zone),
            "a1.test.example.com."
        );
        assert_eq!(
            display_record_owner_name("_acme-challenge", zone),
            "_acme-challenge.test.example.com."
        );
        assert_eq!(
            display_record_owner_name("a1.test.example.com.", zone),
            "a1.test.example.com."
        );
    }

    #[test]
    fn display_record_value_adds_trailing_dot_for_name_like_values() {
        assert_eq!(
            display_record_value("ns.test.example.com", &RecordType::NS),
            "ns.test.example.com."
        );
        assert_eq!(
            display_record_value("Target.Example.Net", &RecordType::CNAME),
            "target.example.net."
        );
        assert_eq!(
            display_record_value("10 mail.example.com", &RecordType::MX),
            "10 mail.example.com."
        );
        assert_eq!(
            display_record_value("10 5 5060 sip.example.com", &RecordType::SRV),
            "10 5 5060 sip.example.com."
        );
        assert_eq!(
            display_record_value("host.example.com", &RecordType::PTR),
            "host.example.com."
        );
    }

    #[test]
    fn display_record_value_keeps_non_name_values_unchanged() {
        assert_eq!(
            display_record_value("127.0.0.1", &RecordType::A),
            "127.0.0.1"
        );
        assert_eq!(
            display_record_value("2001:db8::1", &RecordType::AAAA),
            "2001:db8::1"
        );
        assert_eq!(
            display_record_value("v=spf1 include:example.net", &RecordType::TXT),
            "v=spf1 include:example.net"
        );
    }
}
