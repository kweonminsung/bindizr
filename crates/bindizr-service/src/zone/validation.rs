use std::collections::HashSet;

use bindizr_core::dns::{
    Ttl,
    name::{OwnerName, ZoneName, has_whitespace_or_control},
    record::{SoaMailbox, SrvRecordValue},
};
use bindizr_db::{LockLevel, Transaction};

use crate::{
    Context,
    error::ServiceError,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    ttl::validate_default_ttl,
};

const MAX_EMAIL_LEN: usize = 254;
const MAX_EMAIL_LOCAL_LEN: usize = 64;

/// Validated SOA names and TTL, shared by API and DNS zone writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedSoa {
    pub(crate) mname: String,
    pub(crate) rname: String,
    pub(crate) ttl: Ttl,
}

/// Apply the zone policy to SOA names, mailbox encoding and default TTL.
pub(crate) fn normalize_soa(
    mname: &str,
    rname: &str,
    ttl: i64,
) -> Result<NormalizedSoa, ServiceError> {
    let mname = normalize_mname(mname)?;
    let rname = normalize_rname(rname)?;
    let ttl = validate_default_ttl(ttl)?;
    Ok(NormalizedSoa { mname, rname, ttl })
}

/// Refuse storing a zone at the virtual catalog name, which shadows SOA and transfer queries
/// and is excluded from catalog membership. Lookups remain allowed.
pub(crate) fn reject_catalog_zone_name(cx: &Context, name: &ZoneName) -> Result<(), ServiceError> {
    if cx.config().dns.is_catalog_zone(name.as_str()) {
        return Err(ServiceError::invalid_zone_field(format!(
            "'{}' is the catalog zone name (dns.catalog_zone_name); a zone cannot take it",
            name
        )));
    }
    Ok(())
}

/// Parse a zone name as a request spells it, refusing the root and a
/// wildcard. Every front end parses here before it calls the service.
pub fn normalize_name(value: &str) -> Result<ZoneName, ServiceError> {
    let trimmed = value.trim();

    if trimmed == "." {
        return Err(ServiceError::invalid_zone_field(
            "zone name must not be the root zone".to_string(),
        ));
    }

    if trimmed.starts_with("*.") || trimmed == "*" {
        return Err(ServiceError::invalid_zone_field(
            "wildcard zone names are not allowed".to_string(),
        ));
    }

    normalize_domain_name(trimmed, "zone name")
}

/// Parse a domain name, phrasing any rejection against `field`. The rules
/// live on [`ZoneName`]; this only maps the failure to a zone error.
fn normalize_domain_name(value: &str, field: &str) -> Result<ZoneName, ServiceError> {
    ZoneName::parse(value).map_err(|e| ServiceError::invalid_zone_field(format!("{} {}", field, e)))
}

/// Normalize the SOA primary server name.
pub(crate) fn normalize_mname(value: &str) -> Result<String, ServiceError> {
    Ok(normalize_domain_name(value, "mname")?.to_string())
}

/// Validate and normalize the SOA contact mailbox.
pub(crate) fn normalize_rname(value: &str) -> Result<String, ServiceError> {
    let value = value.trim();

    if value.is_empty() {
        return Err(ServiceError::invalid_zone_field(
            "rname must not be empty".to_string(),
        ));
    }

    if has_whitespace_or_control(value) {
        return Err(ServiceError::invalid_zone_field(
            "rname must not contain whitespace or control characters".to_string(),
        ));
    }

    let Some((local, domain)) = value.split_once('@') else {
        return Err(ServiceError::invalid_zone_field(
            "rname must contain exactly one @".to_string(),
        ));
    };
    if domain.contains('@') {
        return Err(ServiceError::invalid_zone_field(
            "rname must contain exactly one @".to_string(),
        ));
    }

    validate_email_local_part(local)?;
    let domain = normalize_domain_name(domain, "rname domain")?;

    let normalized = format!("{}@{}", local, domain);
    if normalized.len() > MAX_EMAIL_LEN {
        return Err(ServiceError::invalid_zone_field(
            "rname must be 254 bytes or fewer".to_string(),
        ));
    }

    SoaMailbox::from_email(&normalized)
        .map_err(|e| ServiceError::invalid_zone_field(format!("rname {}", e)))?;
    Ok(normalized)
}

/// Validate the SOA mailbox's local part.
fn validate_email_local_part(local: &str) -> Result<(), ServiceError> {
    if local.is_empty() {
        return Err(ServiceError::invalid_zone_field(
            "rname local part must not be empty".to_string(),
        ));
    }

    if local.len() > MAX_EMAIL_LOCAL_LEN {
        return Err(ServiceError::invalid_zone_field(
            "rname local part must be 64 bytes or fewer".to_string(),
        ));
    }

    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err(ServiceError::invalid_zone_field(
            "rname local part must not start, end, or contain consecutive dots".to_string(),
        ));
    }

    if !local.chars().all(is_valid_email_local_char) {
        return Err(ServiceError::invalid_zone_field(
            "rname local part contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

/// Check whether a character is permitted in an SOA mailbox local part.
fn is_valid_email_local_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '/'
                | '='
                | '?'
                | '^'
                | '_'
                | '`'
                | '{'
                | '|'
                | '}'
                | '~'
                | '.'
        )
}

/// Validate cross-owner constraints against the proposed state under the zone lock.
/// Empty changes validate the stored state, as ordered DNS UPDATE requires.
pub(crate) async fn validate_record_changes_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    removed: &[Record],
    added: &[Record],
) -> Result<(), ServiceError> {
    let removed_ids: HashSet<_> = removed.iter().map(|record| record.id).collect();
    let related_types = [
        RecordType::Ds,
        RecordType::Ns,
        RecordType::Dname,
        RecordType::Cname,
        RecordType::Mx,
        RecordType::Srv,
        RecordType::Ptr,
    ];
    let mut records = if zone.id == bindizr_core::model::zone::ZoneId::UNWRITTEN {
        Vec::new()
    } else {
        bindizr_db::record::list_by_record_types_tx(tx, zone.id, &related_types).await?
    };
    records.retain(|record| !removed_ids.contains(&record.id));
    records.extend(
        added
            .iter()
            .filter(|record| related_types.contains(&record.record_type))
            .cloned(),
    );

    let owners_of = |record_type| -> HashSet<&OwnerName> {
        records
            .iter()
            .filter(|record| record.record_type == record_type)
            .map(|record| &record.name)
            .collect()
    };
    let delegations = owners_of(RecordType::Ns);
    if records
        .iter()
        .any(|record| record.record_type == RecordType::Ds && !delegations.contains(&record.name))
    {
        return Err(ServiceError::record_conflict(
            "DS records require delegation NS records at the same name",
        ));
    }

    let dnames = owners_of(RecordType::Dname);
    if !dnames.is_empty() {
        let mut names: HashSet<_> = if zone.id == bindizr_core::model::zone::ZoneId::UNWRITTEN {
            HashSet::new()
        } else {
            bindizr_db::record::list_names_tx(tx, zone.id)
                .await?
                .into_iter()
                .collect()
        };
        let removed_names: Vec<_> = removed
            .iter()
            .map(|record| record.name.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        for name in &removed_names {
            names.remove(name);
        }
        // A removed row may share its owner with rows that survive.
        let remaining =
            bindizr_db::record::list_by_names_tx(tx, zone.id, &removed_names, LockLevel::Unlocked)
                .await?;
        names.extend(
            remaining
                .into_iter()
                .filter(|record| !removed_ids.contains(&record.id))
                .map(|record| record.name),
        );
        names.extend(added.iter().map(|record| record.name.clone()));
        let dname_labels: HashSet<_> = dnames.iter().map(|name| name.labels()).collect();
        if names.iter().any(|name| {
            let labels = name.labels();
            (1..=labels.len()).any(|depth| dname_labels.contains(&labels[depth..]))
        }) {
            return Err(ServiceError::record_conflict(
                "records cannot exist below a DNAME record (RFC 6672, Section 2.4)",
            ));
        }
    }

    let cnames = owners_of(RecordType::Cname);
    if !cnames.is_empty() {
        for record in &records {
            let target = match record.record_type {
                RecordType::Srv => SrvRecordValue::parse(&record.value, record.priority)
                    .ok()
                    .map(|srv| srv.target().to_string()),
                RecordType::Ns | RecordType::Mx | RecordType::Ptr => Some(record.value.clone()),
                _ => continue,
            };
            let Some(owner) = target
                .and_then(|target| OwnerName::parse_absolute_in_zone(&target, &zone.name).ok())
            else {
                continue;
            };
            if cnames.contains(&owner) {
                return Err(ServiceError::record_conflict(
                    "an NS, MX, PTR, or SRV record cannot name a CNAME record of this zone as its target (RFC 2181, Sections 10.2–10.3; RFC 2782)",
                ));
            }
        }
    }
    Ok(())
}
