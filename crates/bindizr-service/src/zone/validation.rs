use std::collections::HashSet;

use bindizr_core::dns::name;
use bindizr_core::dns::name::{OwnerName, ZoneName};
use bindizr_core::dns::record::{SoaMailbox, SrvRecordValue};
use bindizr_core::model::record::{Record, RecordType};
use bindizr_core::model::zone::{Zone, ZoneId};
use bindizr_db::LockLevel;

use crate::error::ServiceError;
use crate::{Context, Transaction};

/// Longest SOA mailbox address accepted, in bytes.
const MAX_EMAIL_LEN: usize = 254;

/// Longest SOA mailbox local part accepted, in bytes.
const MAX_EMAIL_LOCAL_LEN: usize = 64;

/// Refuse storing a zone at the virtual catalog name, which shadows SOA and transfer queries
/// and is excluded from catalog membership. Lookups remain allowed.
pub(crate) fn reject_catalog_zone_name(
    cx: &Context,
    zone_name: &ZoneName,
) -> Result<(), ServiceError> {
    if zone_name == &cx.config().dns.catalog_zone_name {
        return Err(ServiceError::invalid_zone_field(format!(
            "'{zone_name}' is the catalog zone name (dns.catalog_zone_name); a zone cannot take it"
        )));
    }

    Ok(())
}

/// Parse a zone name as a request spells it, refusing the root and a
/// wildcard. Every front end parses here before it calls the service.
pub fn normalize_name(value: &str) -> Result<ZoneName, ServiceError> {
    if value.trim() == "." {
        return Err(ServiceError::invalid_zone_field(
            "zone name must not be the root zone",
        ));
    }

    let zone_name = normalize_domain_name(value, "zone name")?;
    validate_name(&zone_name)?;

    Ok(zone_name)
}

/// Apply the zone policy to a name already parsed from a request or DNS records.
pub(crate) fn validate_name(zone_name: &ZoneName) -> Result<(), ServiceError> {
    if zone_name
        .labels()
        .first()
        .is_some_and(|label| label == b"*")
    {
        return Err(ServiceError::invalid_zone_field(
            "wildcard zone names are not allowed",
        ));
    }

    Ok(())
}

/// Parse a domain name, phrasing any rejection against `field`. The rules
/// live on [`ZoneName`]; this only maps the failure to a zone error.
fn normalize_domain_name(value: &str, field: &str) -> Result<ZoneName, ServiceError> {
    ZoneName::parse(value)
        .map_err(|error| ServiceError::invalid_zone_field(format!("{field} {error}")))
}

/// Normalize the SOA primary server name.
pub(crate) fn normalize_mname(value: &str) -> Result<String, ServiceError> {
    if name::trim_presentation_name(value) == "." {
        return Ok(".".to_string());
    }
    Ok(normalize_domain_name(value, "mname")?.to_string())
}

/// Validate and normalize the SOA contact mailbox.
pub(crate) fn normalize_rname(value: &str) -> Result<String, ServiceError> {
    let value = value.trim();

    if value.is_empty() {
        return Err(ServiceError::invalid_zone_field("rname must not be empty"));
    }

    if name::has_whitespace_or_control(value) {
        return Err(ServiceError::invalid_zone_field(
            "rname must not contain whitespace or control characters",
        ));
    }

    let Some((local, domain)) = value.split_once('@') else {
        return Err(ServiceError::invalid_zone_field(
            "rname must contain exactly one @",
        ));
    };

    if domain.contains('@') {
        return Err(ServiceError::invalid_zone_field(
            "rname must contain exactly one @",
        ));
    }

    validate_email_local_part(local)?;
    let domain = normalize_domain_name(domain, "rname domain")?;

    let normalized = format!("{local}@{domain}");

    if normalized.len() > MAX_EMAIL_LEN {
        return Err(ServiceError::invalid_zone_field(
            "rname must be 254 bytes or fewer",
        ));
    }

    SoaMailbox::from_email(&normalized)
        .map_err(|error| ServiceError::invalid_zone_field(format!("rname {error}")))?;

    Ok(normalized)
}

/// Validate the SOA mailbox's local part.
fn validate_email_local_part(local: &str) -> Result<(), ServiceError> {
    if local.is_empty() {
        return Err(ServiceError::invalid_zone_field(
            "rname local part must not be empty",
        ));
    }

    if local.len() > MAX_EMAIL_LOCAL_LEN {
        return Err(ServiceError::invalid_zone_field(
            "rname local part must be 64 bytes or fewer",
        ));
    }

    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err(ServiceError::invalid_zone_field(
            "rname local part must not start, end, or contain consecutive dots",
        ));
    }

    if !local.chars().all(is_valid_email_local_char) {
        return Err(ServiceError::invalid_zone_field(
            "rname local part contains invalid characters",
        ));
    }

    Ok(())
}

/// Return whether a character is permitted in an SOA mailbox local part.
fn is_valid_email_local_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(
            ch,
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

    let mut records = if zone.id == ZoneId::UNWRITTEN {
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

    if zone.enabled && !delegations.iter().any(|owner| owner.is_apex()) {
        return Err(ServiceError::record_conflict(
            "an enabled zone requires at least one apex NS record (RFC 2181, Section 6.1)",
        ));
    }

    // RFC 4035, Section 2.4 SHOULD exception: preserve explicit per-type NS/DS TTLs
    // for independent edits/imports; each RRset still requires one TTL.
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
        let mut owners: HashSet<_> = if zone.id == ZoneId::UNWRITTEN {
            HashSet::new()
        } else {
            bindizr_db::record::list_names_tx(tx, zone.id)
                .await?
                .into_iter()
                .collect()
        };

        let removed_owners: Vec<_> = removed
            .iter()
            .map(|record| record.name.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        for owner in &removed_owners {
            owners.remove(owner);
        }

        // A removed row may share its owner with rows that survive.
        let remaining =
            bindizr_db::record::list_by_names_tx(tx, zone.id, &removed_owners, LockLevel::Unlocked)
                .await?;
        owners.extend(
            remaining
                .into_iter()
                .filter(|record| !removed_ids.contains(&record.id))
                .map(|record| record.name),
        );
        owners.extend(added.iter().map(|record| record.name.clone()));
        let dname_labels: HashSet<_> = dnames.iter().map(|owner| owner.labels()).collect();

        if owners.iter().any(|owner| {
            let labels = owner.labels();
            (1..=labels.len()).any(|depth| dname_labels.contains(&labels[depth..]))
        }) {
            return Err(ServiceError::record_conflict(
                "records cannot exist below a DNAME record (RFC 6672, Section 2.4)",
            ));
        }
    }

    let cnames = owners_of(RecordType::Cname);

    // RFC 5936, Section 3.5: data below an earlier delegation is occluded.
    let authoritative_dnames: Vec<_> = dnames
        .iter()
        .copied()
        .filter(|owner| {
            !delegations
                .iter()
                .any(|cut| !cut.is_apex() && owner.is_same_or_under(cut))
        })
        .collect();

    if !cnames.is_empty() || !authoritative_dnames.is_empty() {
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
            if authoritative_dnames
                .iter()
                .any(|dname| &owner != *dname && owner.is_same_or_under(dname))
            {
                return Err(ServiceError::record_conflict(
                    "an NS, MX, PTR, or SRV record cannot name a descendant of a DNAME record of this zone as its target (RFC 6672, Section 5.1)",
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that a root MNAME is valid without loosening zone-name or label parsing.
    #[test]
    fn primary_name_preserves_root_and_literal_dot() {
        assert_eq!(normalize_mname(" . ").unwrap(), ".");
        assert_eq!(normalize_mname(r"\.").unwrap(), r"\046");
        assert_eq!(normalize_mname(" NS.Example. ").unwrap(), "ns.example");

        for invalid in ["", "..", "host..example"] {
            assert!(normalize_mname(invalid).is_err(), "{invalid:?}");
        }

        assert!(normalize_name(".").is_err());
    }

    /// Verify that escaped trailing whitespace is preserved while ordinary surrounding padding is
    /// tolerated.
    #[test]
    fn zone_name_preserves_escaped_whitespace() {
        for byte in [9u8, 10, 11, 12, 13, 32] {
            let input = format!(" tail\\{} \t", char::from(byte));
            let expected = ZoneName::parse(&format!("tail\\{byte:03}")).unwrap();
            assert_eq!(normalize_name(&input).unwrap(), expected);
        }

        assert_eq!(
            normalize_name(" example.com \t").unwrap().as_str(),
            "example.com"
        );
        assert!(
            normalize_name(" . ")
                .unwrap_err()
                .to_string()
                .contains("root zone")
        );
    }

    /// Verify that the wildcard-zone policy applies to decoded labels for every equivalent
    /// spelling.
    #[test]
    fn zone_name_rejects_equivalent_wildcards() {
        for label in ["*", r"\*", r"\042"] {
            for suffix in ["", ".", ".example.com"] {
                let input = format!("{label}{suffix}");

                assert!(
                    normalize_name(&input)
                        .unwrap_err()
                        .to_string()
                        .contains("wildcard"),
                    "{input:?}"
                );
            }
        }

        for input in ["a*.example", "a.*.example", r"\042\046example"] {
            assert!(normalize_name(input).is_ok(), "{input:?}");
        }
    }
}
