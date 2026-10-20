mod parent;
mod transfer;
mod transport;
pub(crate) mod tsig;

use std::{str::FromStr, time::Duration};

use domain::{
    base::{Message, MessageBuilder, Name, Rtype, iana::Rcode, name::ParsedName},
    rdata::AllRecordData,
};
pub(crate) use parent::{DsRecord, FakeParent};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
pub(crate) use transfer::{TransferResult, axfr, xot};
pub(crate) use transport::{
    connect_tcp, connect_tls, exchange_request, exchange_tcp, exchange_udp, exchange_xot,
    read_frame, write_frame,
};

use super::TestApp;

pub(crate) mod notify;
pub(crate) mod nsupdate;
mod tests;

/// Build the DNS comparison form of an API record value.
pub(crate) fn build_dns_expected_value(record: &Value, record_type: u16) -> Value {
    let value = record["value"].clone();
    if !matches!(record_type, 15 | 33) {
        return value;
    }

    let Some(target) = value.as_str() else {
        return value;
    };

    let fields = target.split_whitespace().collect::<Vec<_>>();
    let expects_priority_fallback = match record_type {
        15 => fields.len() == 1,
        33 => fields.len() == 3,
        _ => false,
    };
    if !expects_priority_fallback {
        return value;
    }

    let priority = record["priority"].as_u64().unwrap_or(10);
    json!(format!("{priority} {target}"))
}

/// Extract the DNS owner and type used to identify a record.
pub(crate) fn extract_record_key(record: &Value) -> (String, u16) {
    let name = record["name"]
        .as_str()
        .expect("record did not contain a name")
        .to_string();
    let record_type = record["type"]
        .as_str()
        .and_then(dns_record_type)
        .expect("record contained an unsupported DNS type");
    (name, record_type)
}

/// Map a supported record mnemonic to its wire type number.
pub(crate) fn dns_record_type(record_type: &str) -> Option<u16> {
    record_type
        .parse::<domain::base::Rtype>()
        .ok()
        .map(|rtype| rtype.to_int())
}

/// Poll DNS until its answers match the expected record values.
pub(crate) async fn wait_for_dns_records(
    port: u16,
    name: &str,
    record_type: u16,
    expected: &[Value],
) {
    let expected_count = expected.len();
    eprintln!(
        "Waiting for {expected_count} type {record_type} record(s) for {name} on 127.0.0.1:{port}..."
    );
    for attempt in 1..=120 {
        match query_dns_records(port, name, record_type) {
            Ok(records)
                if records
                    .iter()
                    .filter(|answer| answer.record_type == record_type)
                    .count()
                    == expected_count
                    && matches_dns_values(record_type, expected, &records) =>
            {
                eprintln!("{name} type {record_type} propagated through 127.0.0.1:{port}.");
                return;
            }
            Err(error) if is_deleted_zone_absence(record_type, expected, &error) => {
                eprintln!("{name} type {record_type} is absent from 127.0.0.1:{port} ({error}).");
                return;
            }
            _ => {}
        }

        if attempt % 10 == 0 {
            eprintln!(
                "Still waiting for DNS type {record_type} on 127.0.0.1:{port}... {attempt}s elapsed"
            );
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    panic!(
        "{expected_count} type {record_type} record(s) for {name} did not propagate to 127.0.0.1:{port}"
    );
}

/// Check whether a DNS failure represents an expected deleted zone.
fn is_deleted_zone_absence(record_type: u16, expected: &[Value], error: &str) -> bool {
    record_type == 6 && expected.is_empty() && error.contains("REFUSED RCODE")
}

/// A response record, including referrals, in the harness comparison form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsRecord {
    pub(crate) record_type: u16,
    pub(crate) value: Option<Value>,
}

/// Compare response records with expected values for the record type.
fn matches_dns_values(record_type: u16, expected: &[Value], records: &[DnsRecord]) -> bool {
    if record_type == 6 {
        return true;
    }
    let normalize = |value: &Value| {
        let value = value.to_string();
        if matches!(record_type, 2 | 5 | 12 | 15 | 33 | 39) {
            value.to_ascii_lowercase()
        } else {
            value
        }
    };
    let mut expected = expected.iter().map(normalize).collect::<Vec<_>>();
    let mut actual = records
        .iter()
        .filter(|answer| answer.record_type == record_type)
        .filter_map(|answer| answer.value.as_ref().map(normalize))
        .collect::<Vec<_>>();
    expected.sort();
    actual.sort();
    expected == actual
}

/// Wait for at least one matching record; DNSKEY/RRSIG checks assert presence
/// without decoding RDATA.
pub(crate) async fn wait_for_any_dns_record(port: u16, name: &str, record_type: u16) {
    eprintln!("Waiting for a type {record_type} record for {name} on 127.0.0.1:{port}...");
    for attempt in 1..=120 {
        if matches!(query_dns_record_count(port, name, record_type), Ok(count) if count > 0) {
            eprintln!("{name} type {record_type} is served by 127.0.0.1:{port}.");
            return;
        }

        if attempt % 10 == 0 {
            eprintln!(
                "Still waiting for DNS type {record_type} on 127.0.0.1:{port}... {attempt}s elapsed"
            );
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    panic!("no type {record_type} record for {name} appeared on 127.0.0.1:{port}");
}

/// Whether the DNS plane serves `zone_name`: a zone it does not know answers
/// REFUSED, which `validate_response_header` reports as an error.
pub(crate) fn probe_zone_soa(port: u16, zone_name: &str) -> bool {
    matches!(query_dns_records(port, zone_name, 6), Ok(records) if !records.is_empty())
}

/// Query DNS and decode answer or referral records.
fn query_dns_records(port: u16, name: &str, record_type: u16) -> Result<Vec<DnsRecord>, String> {
    let (query_id, response) = exchange_dns_query(port, name, record_type)?;
    extract_dns_records(query_id, &response)
}

/// Query DNS and count the returned answers.
fn query_dns_record_count(port: u16, name: &str, record_type: u16) -> Result<usize, String> {
    let (query_id, response) = exchange_dns_query(port, name, record_type)?;
    let message = Message::from_octets(response.as_slice()).map_err(|e| e.to_string())?;
    if !validate_response_header(query_id, &message)? {
        return Ok(0);
    }

    let answer = message.answer().map_err(|e| e.to_string())?;
    let mut count = 0;
    for record in answer {
        if record.map_err(|e| e.to_string())?.rtype().to_int() == record_type {
            count += 1;
        }
    }
    Ok(count)
}

/// Send a DNS query and return its ID and response bytes.
pub(crate) fn exchange_dns_query(
    port: u16,
    name: &str,
    record_type: u16,
) -> Result<(u16, Vec<u8>), String> {
    let query_id = (std::process::id() as u16).wrapping_add(port);
    let query = build_dns_query(query_id, name, record_type)?;
    Ok((query_id, exchange_udp(port, &query)?))
}

/// Encode a DNS query for the requested owner and type.
fn build_dns_query(query_id: u16, name: &str, record_type: u16) -> Result<Vec<u8>, String> {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(query_id);

    let mut question = builder.question();
    question
        .push((&parse_name(name)?, Rtype::from_int(record_type)))
        .map_err(|e| e.to_string())?;

    Ok(question.finish())
}

/// Parse a DNS name into its wire form, a bare or trailing dot reading as the root.
pub(crate) fn parse_name(name: &str) -> Result<Name<Vec<u8>>, String> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return Ok(Name::root_vec());
    }
    Name::from_str(trimmed).map_err(|e| format!("invalid DNS name '{name}': {e}"))
}

/// Validate a DNS response and extract answer or referral records.
pub(crate) fn extract_dns_records(
    query_id: u16,
    response: &[u8],
) -> Result<Vec<DnsRecord>, String> {
    let message = Message::from_octets(response).map_err(|e| e.to_string())?;
    if !validate_response_header(query_id, &message)? {
        return Ok(Vec::new());
    }

    let answer = message.answer().map_err(|e| e.to_string())?;
    let mut records = Vec::new();
    for record in answer.limit_to::<AllRecordData<_, _>>() {
        let record = record.map_err(|e| e.to_string())?;
        let record_type = record.rtype().to_int();
        records.push(DnsRecord {
            record_type,
            value: decode_dns_value(record.data(), record_type)?,
        });
    }

    // A delegation NS record set comes back as a referral: NOERROR with an empty
    // answer section and the NS rows in authority (RFC 1034, Section 4.3.2).
    if records.is_empty() {
        let authority = message.authority().map_err(|e| e.to_string())?;
        for record in authority.limit_to::<AllRecordData<_, _>>() {
            let record = record.map_err(|e| e.to_string())?;
            let record_type = record.rtype().to_int();
            records.push(DnsRecord {
                record_type,
                value: decode_dns_value(record.data(), record_type)?,
            });
        }
    }

    Ok(records)
}

/// Validate the response's id, QR bit, and rcode; `false` is a well-formed
/// NXDOMAIN, i.e. the name holds no records.
fn validate_response_header(query_id: u16, message: &Message<&[u8]>) -> Result<bool, String> {
    let header = message.header();

    if header.id() != query_id {
        return Err("DNS response query id mismatch".to_string());
    }
    if !header.qr() {
        return Err("DNS response is not marked as a response".to_string());
    }
    match header.rcode() {
        Rcode::NOERROR => Ok(true),
        Rcode::NXDOMAIN => Ok(false),
        code => Err(format!(
            "DNS response returned {} RCODE ({})",
            code,
            code.to_int()
        )),
    }
}

/// Convert supported wire record data into the comparison value.
fn decode_dns_value(
    data: &AllRecordData<&[u8], ParsedName<&[u8]>>,
    record_type: u16,
) -> Result<Option<Value>, String> {
    let value = match data {
        AllRecordData::A(a) => Value::String(a.addr().to_string()),
        AllRecordData::Aaaa(aaaa) => Value::String(aaaa.addr().to_string()),
        AllRecordData::Ns(ns) => Value::String(to_presentation_name(ns.nsdname())),
        AllRecordData::Cname(cname) => Value::String(to_presentation_name(cname.cname())),
        AllRecordData::Ptr(ptr) => Value::String(to_presentation_name(ptr.ptrdname())),
        AllRecordData::Dname(dname) => Value::String(to_presentation_name(dname.dname())),
        // `domain` renders a root replacement as `..`, so the name is composed
        // the way the record types do rather than taken from its Display.
        AllRecordData::Naptr(naptr) => Value::String(format!(
            "{} {} {} {} {} {}",
            naptr.order(),
            naptr.preference(),
            to_quoted_string(naptr.flags().as_slice()),
            to_quoted_string(naptr.services().as_slice()),
            to_quoted_string(naptr.regexp().as_slice()),
            to_presentation_name(naptr.replacement())
        )),
        AllRecordData::Mx(mx) => Value::String(format!(
            "{} {}",
            mx.preference(),
            to_presentation_name(mx.exchange())
        )),
        AllRecordData::Srv(srv) => Value::String(format!(
            "{} {} {} {}",
            srv.priority(),
            srv.weight(),
            srv.port(),
            to_presentation_name(srv.target())
        )),
        AllRecordData::Txt(txt) => {
            let segments = txt
                .iter_charstrs()
                .map(|charstr| charstr.as_slice())
                .collect::<Vec<_>>();
            let text = segments
                .iter()
                .map(|segment| std::str::from_utf8(segment))
                .collect::<Result<Vec<_>, _>>();
            if let Ok(text) = text {
                if let [value] = text.as_slice() {
                    json!(value)
                } else {
                    json!(text)
                }
            } else {
                json!({ "presentation": segments.into_iter().map(to_quoted_string).collect::<Vec<_>>().join(" ") })
            }
        }
        AllRecordData::Ds(ds) => Value::String(format!(
            "{} {} {} {}",
            ds.key_tag(),
            u8::from(ds.algorithm()),
            u8::from(ds.digest_type()),
            hex_upper(ds.digest())
        )),
        AllRecordData::Sshfp(sshfp) => Value::String(format!(
            "{} {} {}",
            u8::from(sshfp.algorithm()),
            u8::from(sshfp.fingerprint_type()),
            hex_upper(sshfp.fingerprint())
        )),
        AllRecordData::Tlsa(tlsa) => Value::String(format!(
            "{} {} {} {}",
            u8::from(tlsa.usage()),
            u8::from(tlsa.selector()),
            u8::from(tlsa.matching_type()),
            hex_upper(tlsa.data())
        )),
        // CAA values are opaque octets, escaped losslessly (RFC 8659, Section 4.1).
        AllRecordData::Caa(caa) => Value::String(caa.to_string()),
        AllRecordData::Unknown(unknown) => {
            let bytes = unknown.data();
            let mut value = format!(r"\# {}", bytes.len());
            if !bytes.is_empty() {
                value.push(' ');
                value.push_str(&hex_upper(bytes));
            }
            Value::String(value)
        }
        AllRecordData::Soa(_) => return Ok(None),
        _ => return Err(format!("unsupported DNS answer type {record_type}")),
    };
    Ok(Some(value))
}

/// Encode bytes as uppercase hexadecimal text.
fn hex_upper(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

/// Render the API's escaped FQDN form without losing label octets or boundaries.
fn to_presentation_name(name: &ParsedName<&[u8]>) -> String {
    let mut out = String::new();
    for label in name.iter() {
        if label.is_root() {
            break;
        }
        for &byte in label.as_slice() {
            match byte {
                b'.' => out.push_str(r"\046"),
                b'\\' | b'@' | b';' | b'(' | b')' | b'"' | b'$' => {
                    out.push('\\');
                    out.push(char::from(byte));
                }
                0x21..=0x7e => out.push(char::from(byte)),
                _ => out.push_str(&format!("\\{byte:03}")),
            }
        }
        out.push('.');
    }
    if out.is_empty() {
        out.push('.');
    }
    out
}

/// Quote a value the way the record types render it: `"` and `\` escaped,
/// control and non-ASCII bytes as `\DDD`, so it matches what the API reports.
fn to_quoted_string(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for &byte in bytes {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(byte)),
            _ => out.push_str(&format!("\\{byte:03}")),
        }
    }
    out.push('"');
    out
}

/// Read published RRsets with an independent zone-file parser.
pub(crate) async fn fetch_exported_record_sets(
    app: &TestApp,
    zone_name: &str,
) -> std::collections::BTreeMap<(String, Rtype), Vec<Vec<u8>>> {
    use domain::{
        base::rdata::ComposeRecordData,
        zonefile::inplace::{Entry, Zonefile},
    };

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/zones/{zone_name}/export?signed=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut file = Zonefile::new();
    file.extend_from_slice(generic_wks_export(body.as_str().unwrap()).as_bytes());
    let mut sets = std::collections::BTreeMap::<_, Vec<_>>::new();
    while let Some(entry) = file.next_entry().unwrap() {
        if let Entry::Record(record) = entry {
            let name = format!("{}.", record.owner().to_string().trim_end_matches('.'));
            let mut rdata = Vec::new();
            let Ok(()) = record.data().compose_rdata(&mut rdata);
            sets.entry((name, record.rtype())).or_default().push(rdata);
        }
    }
    sets
}

/// Encode exported WKS independently for `domain`, which lacks a native scanner.
fn generic_wks_export(text: &str) -> String {
    let mut normalized = text
        .lines()
        .map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.get(3) != Some(&"WKS") || fields.get(4) == Some(&r"\#") {
                return line.to_owned();
            }
            let address: std::net::Ipv4Addr = fields[4].parse().unwrap();
            let protocol: u8 = fields[5].parse().unwrap();
            let mut bitmap = vec![0u8; 8192];
            for port in &fields[6..] {
                let port = usize::from(port.parse::<u16>().unwrap());
                bitmap[port / 8] |= 1 << (7 - port % 8);
            }
            bitmap.truncate(
                bitmap
                    .iter()
                    .rposition(|byte| *byte != 0)
                    .map_or(0, |last| last + 1),
            );
            let mut bytes = address.octets().to_vec();
            bytes.push(protocol);
            bytes.extend(bitmap);
            let hex: String = bytes.iter().map(|byte| format!("{byte:02X}")).collect();
            format!(r"{} \# {} {}", fields[..4].join(" "), bytes.len(), hex)
        })
        .collect::<Vec<_>>()
        .join("\n");
    normalized.push('\n');
    normalized
}
