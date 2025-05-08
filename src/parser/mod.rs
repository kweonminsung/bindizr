use crate::database::model::{record::Record, record::RecordType, zone::Zone};
use std::fmt::Write;

pub fn serialize_zone(zone: &Zone, records: &[Record]) -> String {
    let mut output = String::new();

    // SOA 레코드
    writeln!(
        &mut output,
        r#"
$TTL {}
{}   IN  SOA {} {} (
        {} ; serial
        {} ; refresh
        {} ; retry
        {} ; expire
        {} ) ; minimum TTL
"#,
        zone.ttl,
        zone.name,
        zone.primary_ns,
        zone.admin_email.replace("@", "."),
        zone.serial,
        zone.refresh,
        zone.retry,
        zone.expire,
        zone.minimum_ttl,
    )
    .unwrap();

    // NS 레코드
    writeln!(&mut output, "@   IN  NS  ns1.{}.", zone.name).unwrap();

    for record in records {
        let name = if record.name == "@" {
            "@".to_string()
        } else {
            format!("{}.", record.name)
        };

        match record.record_type {
            RecordType::A
            | RecordType::AAAA
            | RecordType::CNAME
            | RecordType::TXT
            | RecordType::NS
            | RecordType::PTR => {
                writeln!(
                    &mut output,
                    "{} {} IN {:?} {}",
                    name, record.ttl, record.record_type, record.value
                )
                .unwrap();
            }
            RecordType::MX => {
                let priority = record.priority.unwrap_or(10);
                writeln!(
                    &mut output,
                    "{} {} IN MX {} {}",
                    name, record.ttl, priority, record.value
                )
                .unwrap();
            }
            RecordType::SRV => {
                // SRV는 priority, weight, port, target 순
                // 예: _sip._tcp 3600 IN SRV 10 60 5060 sipserver.example.com.
                let parts: Vec<&str> = record.value.split_whitespace().collect();
                if parts.len() == 3 {
                    writeln!(
                        &mut output,
                        "{} {} IN SRV {} {} {} {}",
                        name,
                        record.ttl,
                        record.priority.unwrap_or(10), // default priority
                        parts[0],                      // weight
                        parts[1],                      // port
                        parts[2],                      // target
                    )
                    .unwrap();
                }
            }
            RecordType::SOA => {
                // 보통 SOA는 자동 생성되므로 무시하거나 따로 처리
                writeln!(
                    &mut output,
                    "{} {} IN SOA {}",
                    name, record.ttl, record.value
                )
                .unwrap();
            }
        }
    }

    output
}
