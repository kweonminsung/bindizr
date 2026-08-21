use std::{net::UdpSocket, str::FromStr, time::Duration};

use domain::{
    base::{Message, MessageBuilder, Name, Rtype, iana::Rcode, name::ParsedName},
    rdata::AllRecordData,
};
use serde_json::{Value, json};

pub(super) fn dns_expected_value(record: &Value, record_type: u16) -> Value {
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

pub(super) fn dns_key_from_record(record: &Value) -> (String, u16) {
    let name = record["name"]
        .as_str()
        .expect("record did not contain a name")
        .to_string();
    let record_type = record["record_type"]
        .as_str()
        .and_then(dns_record_type)
        .expect("record contained an unsupported DNS type");
    (name, record_type)
}

pub(super) fn dns_record_type(record_type: &str) -> Option<u16> {
    match record_type {
        "A" => Some(1),
        "NS" => Some(2),
        "CNAME" => Some(5),
        "SOA" => Some(6),
        "PTR" => Some(12),
        "MX" => Some(15),
        "TXT" => Some(16),
        "AAAA" => Some(28),
        "SRV" => Some(33),
        _ => None,
    }
}

pub(super) async fn wait_for_dns_records(
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
        match query_dns_record(port, name, record_type) {
            Ok(answers)
                if answers
                    .iter()
                    .filter(|answer| answer.record_type == record_type)
                    .count()
                    == expected_count
                    && dns_values_match(record_type, expected, &answers) =>
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

fn is_deleted_zone_absence(record_type: u16, expected: &[Value], error: &str) -> bool {
    record_type == 6 && expected.is_empty() && error.contains("REFUSED RCODE")
}

#[derive(Debug)]
struct DnsAnswer {
    record_type: u16,
    value: Option<Value>,
}

fn dns_values_match(record_type: u16, expected: &[Value], answers: &[DnsAnswer]) -> bool {
    if record_type == 6 {
        return true;
    }
    let normalize = |value: &Value| {
        let value = value.to_string();
        if matches!(record_type, 2 | 5 | 12 | 15 | 33) {
            value.to_ascii_lowercase()
        } else {
            value
        }
    };
    let mut expected = expected.iter().map(normalize).collect::<Vec<_>>();
    let mut actual = answers
        .iter()
        .filter(|answer| answer.record_type == record_type)
        .filter_map(|answer| answer.value.as_ref().map(normalize))
        .collect::<Vec<_>>();
    expected.sort();
    actual.sort();
    expected == actual
}

/// Wait until the secondary answers `name`/`record_type` with at least one
/// record. For the DNSSEC types this harness cannot render (DNSKEY, RRSIG),
/// presence is the assertion, so rdata stays undecoded.
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

fn query_dns_record(port: u16, name: &str, record_type: u16) -> Result<Vec<DnsAnswer>, String> {
    let (query_id, response) = exchange_dns_query(port, name, record_type)?;
    parse_dns_response(query_id, &response)
}

fn query_dns_record_count(port: u16, name: &str, record_type: u16) -> Result<usize, String> {
    let (query_id, response) = exchange_dns_query(port, name, record_type)?;
    let message = Message::from_octets(response.as_slice()).map_err(|e| e.to_string())?;
    if !check_response_header(query_id, &message)? {
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

fn exchange_dns_query(port: u16, name: &str, record_type: u16) -> Result<(u16, Vec<u8>), String> {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;

    let query_id = (std::process::id() as u16).wrapping_add(port);
    let query = build_dns_query(query_id, name, record_type)?;
    socket
        .send_to(&query, ("127.0.0.1", port))
        .map_err(|e| e.to_string())?;

    let mut response = [0_u8; 1500];
    let (len, _) = socket.recv_from(&mut response).map_err(|e| e.to_string())?;

    Ok((query_id, response[..len].to_vec()))
}

fn build_dns_query(query_id: u16, name: &str, record_type: u16) -> Result<Vec<u8>, String> {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(query_id);

    let mut question = builder.question();
    question
        .push((&query_name(name)?, Rtype::from_int(record_type)))
        .map_err(|e| e.to_string())?;

    Ok(question.finish())
}

fn query_name(name: &str) -> Result<Name<Vec<u8>>, String> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return Ok(Name::root_vec());
    }
    Name::from_str(trimmed).map_err(|e| format!("invalid DNS name '{name}': {e}"))
}

fn parse_dns_response(query_id: u16, response: &[u8]) -> Result<Vec<DnsAnswer>, String> {
    let message = Message::from_octets(response).map_err(|e| e.to_string())?;
    if !check_response_header(query_id, &message)? {
        return Ok(Vec::new());
    }

    let answer = message.answer().map_err(|e| e.to_string())?;
    let mut answers = Vec::new();
    for record in answer.limit_to::<AllRecordData<_, _>>() {
        let record = record.map_err(|e| e.to_string())?;
        let record_type = record.rtype().to_int();
        answers.push(DnsAnswer {
            record_type,
            value: decode_dns_value(record.data(), record_type)?,
        });
    }

    Ok(answers)
}

/// Validate the response's id, QR bit, and rcode; `false` is a well-formed
/// NXDOMAIN, i.e. the name holds no records.
fn check_response_header(query_id: u16, message: &Message<&[u8]>) -> Result<bool, String> {
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

fn decode_dns_value(
    data: &AllRecordData<&[u8], ParsedName<&[u8]>>,
    record_type: u16,
) -> Result<Option<Value>, String> {
    let value = match data {
        AllRecordData::A(a) => Value::String(a.addr().to_string()),
        AllRecordData::Aaaa(aaaa) => Value::String(aaaa.addr().to_string()),
        AllRecordData::Ns(ns) => Value::String(presentation_name(ns.nsdname())),
        AllRecordData::Cname(cname) => Value::String(presentation_name(cname.cname())),
        AllRecordData::Ptr(ptr) => Value::String(presentation_name(ptr.ptrdname())),
        AllRecordData::Mx(mx) => Value::String(format!(
            "{} {}",
            mx.preference(),
            presentation_name(mx.exchange())
        )),
        AllRecordData::Srv(srv) => Value::String(format!(
            "{} {} {} {}",
            srv.priority(),
            srv.weight(),
            srv.port(),
            presentation_name(srv.target())
        )),
        AllRecordData::Txt(txt) => {
            let mut segments = txt
                .iter_charstrs()
                .map(|charstr| String::from_utf8_lossy(charstr.as_slice()).into())
                .collect::<Vec<String>>();
            if segments.len() == 1 {
                Value::String(segments.remove(0))
            } else {
                serde_json::to_value(segments).map_err(|error| error.to_string())?
            }
        }
        AllRecordData::Soa(_) => return Ok(None),
        _ => return Err(format!("unsupported DNS answer type {record_type}")),
    };
    Ok(Some(value))
}

/// Renders names the way records are compared here: labels joined with '.',
/// trailing dot, lossy UTF-8 (never `Display`, which escapes label bytes).
fn presentation_name(name: &ParsedName<&[u8]>) -> String {
    let mut out = String::new();
    for label in name.iter() {
        if label.is_root() {
            break;
        }
        out.push_str(&String::from_utf8_lossy(label.as_slice()));
        out.push('.');
    }
    if out.is_empty() {
        out.push('.');
    }
    out
}

#[cfg(test)]
mod tests;
