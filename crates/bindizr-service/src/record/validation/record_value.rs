use std::net::{Ipv4Addr, Ipv6Addr};

use bindizr_core::dns::name::{split_presentation_labels, to_fqdn};

use super::{MAX_DNS_LABEL_LEN, MAX_DOMAIN_LEN, has_whitespace_or_control};
use crate::{error::ServiceError, model::record::RecordType};

struct ARecordValue(Ipv4Addr);

struct AaaaRecordValue(Ipv6Addr);

struct CnameRecordValue<'a> {
    target: &'a str,
}

struct MxRecordValue<'a> {
    priority: u16,
    target: &'a str,
}

struct TxtRecordValue<'a> {
    value: &'a str,
}

struct NsRecordValue<'a> {
    target: &'a str,
}

struct SoaRecordValue<'a> {
    value: &'a str,
}

struct SrvRecordValue<'a> {
    priority: u16,
    weight: u16,
    port: u16,
    target: &'a str,
}

struct PtrRecordValue<'a> {
    target: &'a str,
}

impl ARecordValue {
    fn parse(value: &str) -> Result<Self, ServiceError> {
        value.parse::<Ipv4Addr>().map(Self).map_err(|_| {
            ServiceError::BadRequest(format!(
                "A record value must be a valid IPv4 address: {}",
                value
            ))
        })
    }

    fn canonical(&self) -> String {
        self.0.to_string()
    }
}

impl AaaaRecordValue {
    fn parse(value: &str) -> Result<Self, ServiceError> {
        value.parse::<Ipv6Addr>().map(Self).map_err(|_| {
            ServiceError::BadRequest(format!(
                "AAAA record value must be a valid IPv6 address: {}",
                value
            ))
        })
    }

    fn canonical(&self) -> String {
        self.0.to_string()
    }
}

impl<'a> CnameRecordValue<'a> {
    fn parse(value: &'a str) -> Result<Self, ServiceError> {
        validate_domain_record_value("CNAME record value", value)?;
        Ok(Self { target: value })
    }

    fn canonical(&self) -> String {
        canonical_domain_value(self.target)
    }
}

impl<'a> MxRecordValue<'a> {
    fn parse(value: &'a str, fallback_priority: Option<i32>) -> Result<Self, ServiceError> {
        let fields = value.split_whitespace().collect::<Vec<_>>();
        match fields.as_slice() {
            [priority, target] => {
                reject_duplicate_priority_field("MX", fallback_priority)?;
                Ok(Self {
                    priority: parse_u16_record_field("MX priority", priority)?,
                    target,
                })
            }
            [target] => Ok(Self {
                priority: parse_optional_u16_record_field("MX priority", fallback_priority)?,
                target,
            }),
            _ => Err(ServiceError::BadRequest(format!(
                "MX record value must be '<priority> <target>' or '<target>': {value}"
            ))),
        }
    }

    fn validate(&self) -> Result<(), ServiceError> {
        validate_mx_record_target(self.target)
    }

    fn canonical(&self) -> String {
        format!("{} {}", self.priority, canonical_domain_value(self.target))
    }
}

impl<'a> TxtRecordValue<'a> {
    fn parse(value: &'a str) -> Self {
        Self { value }
    }

    fn canonical(&self) -> String {
        self.value.to_string()
    }
}

impl<'a> NsRecordValue<'a> {
    fn parse(value: &'a str) -> Result<Self, ServiceError> {
        validate_domain_record_value("NS record value", value)?;
        Ok(Self { target: value })
    }

    fn canonical(&self) -> String {
        canonical_domain_value(self.target)
    }
}

impl<'a> SoaRecordValue<'a> {
    fn parse(value: &'a str) -> Self {
        Self { value }
    }

    fn canonical(&self) -> String {
        self.value.to_string()
    }
}

impl<'a> SrvRecordValue<'a> {
    fn parse(value: &'a str, fallback_priority: Option<i32>) -> Result<Self, ServiceError> {
        let fields = value.split_whitespace().collect::<Vec<_>>();
        match fields.as_slice() {
            [priority, weight, port, target] => {
                reject_duplicate_priority_field("SRV", fallback_priority)?;
                Ok(Self {
                    priority: parse_u16_record_field("SRV priority", priority)?,
                    weight: parse_u16_record_field("SRV weight", weight)?,
                    port: parse_u16_record_field("SRV port", port)?,
                    target,
                })
            }
            [weight, port, target] => Ok(Self {
                priority: parse_optional_u16_record_field("SRV priority", fallback_priority)?,
                weight: parse_u16_record_field("SRV weight", weight)?,
                port: parse_u16_record_field("SRV port", port)?,
                target,
            }),
            _ => Err(ServiceError::BadRequest(format!(
                "SRV record value must be '<priority> <weight> <port> <target>' or '<weight> <port> <target>': {value}"
            ))),
        }
    }

    fn validate(&self) -> Result<(), ServiceError> {
        validate_srv_record_target(self.target)
    }

    fn canonical(&self) -> String {
        format!(
            "{} {} {} {}",
            self.priority,
            self.weight,
            self.port,
            canonical_domain_value(self.target)
        )
    }
}

impl<'a> PtrRecordValue<'a> {
    fn parse(value: &'a str) -> Result<Self, ServiceError> {
        validate_domain_record_value("PTR record value", value)?;
        Ok(Self { target: value })
    }

    fn canonical(&self) -> String {
        canonical_domain_value(self.target)
    }
}

pub(super) fn validate_record_value(
    record_type: &RecordType,
    value: &str,
    priority: Option<i32>,
) -> Result<(), ServiceError> {
    match record_type {
        RecordType::A => ARecordValue::parse(value).map(|_| ()),
        RecordType::AAAA => AaaaRecordValue::parse(value).map(|_| ()),
        RecordType::CNAME => CnameRecordValue::parse(value).map(|_| ()),
        RecordType::MX => MxRecordValue::parse(value, priority)?.validate(),
        RecordType::TXT => {
            let _ = TxtRecordValue::parse(value);
            Ok(())
        }
        RecordType::NS => NsRecordValue::parse(value).map(|_| ()),
        RecordType::SOA => {
            let _ = SoaRecordValue::parse(value);
            Ok(())
        }
        RecordType::SRV => SrvRecordValue::parse(value, priority)?.validate(),
        RecordType::PTR => PtrRecordValue::parse(value).map(|_| ()),
    }
}

pub(super) fn record_values_equal(
    left: &str,
    left_priority: Option<i32>,
    right: &str,
    right_priority: Option<i32>,
    record_type: &RecordType,
) -> bool {
    canonical_record_value(left, left_priority, record_type)
        == canonical_record_value(right, right_priority, record_type)
}

fn canonical_record_value(
    value: &str,
    fallback_priority: Option<i32>,
    record_type: &RecordType,
) -> String {
    match record_type {
        RecordType::A => ARecordValue::parse(value)
            .map(|parsed| parsed.canonical())
            .unwrap_or_else(|_| value.to_string()),
        RecordType::AAAA => AaaaRecordValue::parse(value)
            .map(|parsed| parsed.canonical())
            .unwrap_or_else(|_| value.to_string()),
        RecordType::CNAME => CnameRecordValue::parse(value)
            .map(|parsed| parsed.canonical())
            .unwrap_or_else(|_| canonical_domain_value(value)),
        RecordType::MX => MxRecordValue::parse(value, fallback_priority)
            .map(|parsed| parsed.canonical())
            .unwrap_or_else(|_| value.to_string()),
        RecordType::TXT => TxtRecordValue::parse(value).canonical(),
        RecordType::NS => NsRecordValue::parse(value)
            .map(|parsed| parsed.canonical())
            .unwrap_or_else(|_| canonical_domain_value(value)),
        RecordType::SOA => SoaRecordValue::parse(value).canonical(),
        RecordType::SRV => SrvRecordValue::parse(value, fallback_priority)
            .map(|parsed| parsed.canonical())
            .unwrap_or_else(|_| value.to_string()),
        RecordType::PTR => PtrRecordValue::parse(value)
            .map(|parsed| parsed.canonical())
            .unwrap_or_else(|_| canonical_domain_value(value)),
    }
}

fn validate_mx_record_target(target: &str) -> Result<(), ServiceError> {
    if target.trim() == "." {
        return Ok(());
    }

    validate_domain_record_value("MX record target", target)
}

fn validate_srv_record_target(target: &str) -> Result<(), ServiceError> {
    if target.trim() == "." {
        return Ok(());
    }

    validate_domain_record_value("SRV record target", target)
}

fn reject_duplicate_priority_field(
    record_type: &str,
    fallback_priority: Option<i32>,
) -> Result<(), ServiceError> {
    if fallback_priority.is_some() {
        return Err(ServiceError::BadRequest(format!(
            "{record_type} priority must be provided either inline or in the priority field, not both"
        )));
    }

    Ok(())
}

fn parse_optional_u16_record_field(field: &str, value: Option<i32>) -> Result<u16, ServiceError> {
    u16::try_from(value.unwrap_or(10))
        .map_err(|_| ServiceError::BadRequest(format!("{field} must be between 0 and 65535")))
}

fn parse_u16_record_field(field: &str, value: &str) -> Result<u16, ServiceError> {
    value.parse::<u16>().map_err(|_| {
        ServiceError::BadRequest(format!(
            "{field} must be an unsigned 16-bit integer: {value}"
        ))
    })
}

fn validate_domain_record_value(field: &str, value: &str) -> Result<(), ServiceError> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(ServiceError::BadRequest(format!(
            "{} must not be empty",
            field
        )));
    }

    if has_whitespace_or_control(trimmed) {
        return Err(ServiceError::BadRequest(format!(
            "{} must not contain whitespace or control characters",
            field
        )));
    }

    let without_trailing_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if without_trailing_dot.is_empty() {
        return Err(ServiceError::BadRequest(format!(
            "{} must not be the root zone",
            field
        )));
    }

    if without_trailing_dot.len() > MAX_DOMAIN_LEN {
        return Err(ServiceError::BadRequest(format!(
            "{} must be 253 bytes or fewer",
            field
        )));
    }

    for label in split_presentation_labels(without_trailing_dot)
        .map_err(|e| ServiceError::BadRequest(e.to_string()))?
    {
        validate_domain_record_label(field, &label)?;
    }

    Ok(())
}

fn validate_domain_record_label(field: &str, label: &str) -> Result<(), ServiceError> {
    if label.is_empty() {
        return Err(ServiceError::BadRequest(format!(
            "{} must not contain empty labels",
            field
        )));
    }

    if label.len() > MAX_DNS_LABEL_LEN {
        return Err(ServiceError::BadRequest(format!(
            "{} labels must be 63 bytes or fewer",
            field
        )));
    }

    if !label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ServiceError::BadRequest(format!(
            "{} labels must contain only ASCII letters, digits, hyphens, or underscores",
            field
        )));
    }

    if label.starts_with('-') || label.ends_with('-') {
        return Err(ServiceError::BadRequest(format!(
            "{} labels must not start or end with hyphens",
            field
        )));
    }

    Ok(())
}

fn canonical_domain_value(value: &str) -> String {
    to_fqdn(value).to_ascii_lowercase()
}
