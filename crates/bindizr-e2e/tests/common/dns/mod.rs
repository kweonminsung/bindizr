use std::{
    net::{Ipv4Addr, Ipv6Addr, UdpSocket},
    time::Duration,
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

fn query_dns_record(port: u16, name: &str, record_type: u16) -> Result<Vec<DnsAnswer>, String> {
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

    parse_dns_response(query_id, &response[..len])
}

fn build_dns_query(query_id: u16, name: &str, record_type: u16) -> Result<Vec<u8>, String> {
    let mut query = Vec::new();
    query.extend_from_slice(&query_id.to_be_bytes());
    query.extend_from_slice(&0x0000_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    encode_dns_name(name, &mut query)?;
    query.extend_from_slice(&record_type.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());

    Ok(query)
}

fn encode_dns_name(name: &str, out: &mut Vec<u8>) -> Result<(), String> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        out.push(0);
        return Ok(());
    }

    for label in name.split('.') {
        let len = u8::try_from(label.len()).map_err(|_| format!("label too long: {label}"))?;
        if len > 63 {
            return Err(format!("label too long: {label}"));
        }

        out.push(len);
        out.extend_from_slice(label.as_bytes());
    }

    out.push(0);
    Ok(())
}

fn parse_dns_response(query_id: u16, response: &[u8]) -> Result<Vec<DnsAnswer>, String> {
    if response.len() < 12 {
        return Err("DNS response header is too short".to_string());
    }

    if u16::from_be_bytes([response[0], response[1]]) != query_id {
        return Err("DNS response query id mismatch".to_string());
    }

    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 {
        return Err("DNS response is not marked as a response".to_string());
    }
    let response_code = flags & 0x000f;
    match response_code {
        0 => {}
        3 => return Ok(Vec::new()), // NXDOMAIN
        code => {
            return Err(format!(
                "DNS response returned {} RCODE ({code})",
                dns_response_code_name(code)
            ));
        }
    }

    let question_count = u16::from_be_bytes([response[4], response[5]]) as usize;
    let answer_count = u16::from_be_bytes([response[6], response[7]]) as usize;
    let mut offset = 12;

    for _ in 0..question_count {
        offset = skip_dns_name(response, offset)?;
        offset = offset
            .checked_add(4)
            .ok_or_else(|| "DNS question offset overflow".to_string())?;
        if offset > response.len() {
            return Err("DNS question extends beyond response".to_string());
        }
    }

    let mut answers = Vec::new();
    for _ in 0..answer_count {
        offset = skip_dns_name(response, offset)?;
        if offset + 10 > response.len() {
            return Err("DNS answer header extends beyond response".to_string());
        }

        let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let rdlen = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlen > response.len() {
            return Err("DNS answer rdata extends beyond response".to_string());
        }

        answers.push(DnsAnswer {
            record_type,
            value: decode_dns_value(response, record_type, offset, rdlen)?,
        });
        offset += rdlen;
    }

    Ok(answers)
}

fn dns_response_code_name(code: u16) -> &'static str {
    match code {
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests;

fn decode_dns_value(
    response: &[u8],
    record_type: u16,
    offset: usize,
    rdlen: usize,
) -> Result<Option<Value>, String> {
    let end = offset + rdlen;
    let value = match record_type {
        1 if rdlen == 4 => Value::String(
            Ipv4Addr::new(
                response[offset],
                response[offset + 1],
                response[offset + 2],
                response[offset + 3],
            )
            .to_string(),
        ),
        28 if rdlen == 16 => {
            let bytes: [u8; 16] = response[offset..end]
                .try_into()
                .map_err(|_| "invalid AAAA")?;
            Value::String(Ipv6Addr::from(bytes).to_string())
        }
        2 | 5 | 12 => Value::String(decode_dns_name(response, offset)?),
        15 => {
            if rdlen < 2 {
                return Err("invalid MX rdlen".to_string());
            }
            Value::String(format!(
                "{} {}",
                u16::from_be_bytes([response[offset], response[offset + 1]]),
                decode_dns_name(response, offset + 2)?
            ))
        }
        33 => {
            if rdlen < 6 {
                return Err("invalid SRV rdlen".to_string());
            }
            Value::String(format!(
                "{} {} {} {}",
                u16::from_be_bytes([response[offset], response[offset + 1]]),
                u16::from_be_bytes([response[offset + 2], response[offset + 3]]),
                u16::from_be_bytes([response[offset + 4], response[offset + 5]]),
                decode_dns_name(response, offset + 6)?
            ))
        }
        16 => {
            let mut position = offset;
            let mut segments = Vec::new();
            while position < end {
                let len = response[position] as usize;
                position += 1;
                if position + len > end {
                    return Err("invalid TXT rdata".to_string());
                }
                segments.push(String::from_utf8_lossy(&response[position..position + len]).into());
                position += len;
            }
            if segments.len() == 1 {
                Value::String(segments.remove(0))
            } else {
                serde_json::to_value(segments).map_err(|error| error.to_string())?
            }
        }
        6 => return Ok(None),
        _ => return Err(format!("unsupported DNS answer type {record_type}")),
    };
    Ok(Some(value))
}

fn decode_dns_name(response: &[u8], mut offset: usize) -> Result<String, String> {
    let mut labels = Vec::<String>::new();
    for _ in 0..128 {
        let len = *response.get(offset).ok_or("DNS name out of bounds")?;
        if len == 0 {
            return Ok(format!("{}.", labels.join(".")));
        }
        if len & 0xc0 == 0xc0 {
            let next = *response
                .get(offset + 1)
                .ok_or("DNS pointer out of bounds")?;
            offset = (((len & 0x3f) as usize) << 8) | next as usize;
            continue;
        }
        let start = offset + 1;
        let end = start + len as usize;
        labels.push(
            String::from_utf8_lossy(response.get(start..end).ok_or("DNS label out of bounds")?)
                .into(),
        );
        offset = end;
    }
    Err("DNS compression pointer loop".to_string())
}

fn skip_dns_name(response: &[u8], mut offset: usize) -> Result<usize, String> {
    loop {
        let len = *response
            .get(offset)
            .ok_or_else(|| "DNS name extends beyond response".to_string())?;

        if len & 0xc0 == 0xc0 {
            if offset + 1 >= response.len() {
                return Err("DNS compression pointer extends beyond response".to_string());
            }
            return Ok(offset + 2);
        }

        if len == 0 {
            return Ok(offset + 1);
        }

        if len & 0xc0 != 0 {
            return Err("DNS name has unsupported label format".to_string());
        }

        offset = offset
            .checked_add(1 + len as usize)
            .ok_or_else(|| "DNS name offset overflow".to_string())?;
    }
}
