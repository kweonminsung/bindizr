//! Self-checks of a signed zone's stored state — key inventory, signature
//! freshness, per-algorithm coverage, the denial chain — plus, with a
//! resolver configured, the DS the parent actually serves.

use std::collections::{BTreeMap, BTreeSet};

use bindizr_core::{config::bindizr_config, dns::name::OwnerName};
use chrono::Utc;

use super::{DnssecService, status::ds_info};
use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    error::ServiceError,
    model::{dnssec_record::DnssecRecordType, record::RecordType, zone::DnssecDenial},
    repository::RepositoryService,
    types::{DnssecCheckInfo, DnssecDsInfo, VerifyDnssecResponse},
};

impl DnssecService {
    /// Verify the zone's stored DNSSEC state; each failed aspect becomes a
    /// failed check rather than an error.
    pub async fn verify(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<VerifyDnssecResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_read_tx("failed to verify DNSSEC state").await?;
        let result = async {
            let (zone, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Shared).await?;
            let derived =
                RepositoryService::list_dnssec_records_tx(&mut tx, zone.id, LockLevel::None)
                    .await?;
            let records =
                RepositoryService::list_records_tx(&mut tx, zone.id, LockLevel::None).await?;

            let mut checks = Vec::new();

            let has_data_signer = keys.iter().any(|key| key.signs_zone_data(&keys));
            let has_sep = keys
                .iter()
                .any(|key| key.role.is_sep() && key.wants_parent_ds());
            checks.push(DnssecCheckInfo {
                check: "keys".to_string(),
                ok: has_data_signer && has_sep,
                detail: keys
                    .iter()
                    .map(|key| format!("{} {} ({})", key.role, key.state, key.algorithm))
                    .collect::<Vec<_>>()
                    .join(", "),
            });

            let now = Utc::now();
            let rrsigs: Vec<_> = derived
                .iter()
                .filter(|row| row.record_type == DnssecRecordType::Rrsig)
                .collect();
            let expired = rrsigs
                .iter()
                .filter(|row| row.expires_at.is_some_and(|at| at <= now))
                .count();
            let earliest = rrsigs.iter().filter_map(|row| row.expires_at).min();
            checks.push(DnssecCheckInfo {
                check: "signatures".to_string(),
                ok: expired == 0 && !rrsigs.is_empty(),
                detail: match (expired, earliest) {
                    (0, Some(at)) => format!(
                        "{} RRSIGs, earliest expiry {}",
                        rrsigs.len(),
                        at.format("%Y-%m-%dT%H:%M:%SZ")
                    ),
                    (0, None) => "no stored RRSIGs".to_string(),
                    (expired, _) => format!("{} of {} RRSIGs expired", expired, rrsigs.len()),
                },
            });

            // Every algorithm in the DNSKEY RRset must sign every RRset
            // (RFC 6840, Section 5.11).
            let zone_algorithms: BTreeSet<u8> = keys
                .iter()
                .map(|key| key.algorithm.to_int() as u8)
                .collect();
            let mut covered: BTreeMap<(String, Option<i32>), BTreeSet<u8>> = BTreeMap::new();
            for row in &rrsigs {
                if let Some(&algorithm) = row.rdata.as_bytes().get(2) {
                    covered
                        .entry((row.name.to_stored(), row.covered_record_type))
                        .or_default()
                        .insert(algorithm);
                }
            }
            let offender = covered
                .iter()
                .find(|(_, algorithms)| **algorithms != zone_algorithms);

            // An unsigned RRset never reaches `covered`; completeness checks
            // what the signer must sign: user RRsets outside delegations
            // (only DS at a cut, RFC 4035, Section 2.2), SOA, derived rows.
            let delegations: Vec<&OwnerName> = records
                .iter()
                .filter(|record| record.record_type == RecordType::NS && !record.name.is_apex())
                .map(|record| &record.name)
                .collect();
            let mut expected: BTreeSet<(String, Option<i32>)> = BTreeSet::new();
            for record in &records {
                let at_cut = delegations.iter().any(|cut| record.name == **cut);
                let below_cut = delegations
                    .iter()
                    .any(|cut| record.name.is_same_or_under(cut) && record.name != **cut);
                if below_cut || (at_cut && record.record_type != RecordType::DS) {
                    continue;
                }
                expected.insert((
                    record.name.to_stored(),
                    Some(record.record_type.wire_type() as i32),
                ));
            }
            expected.insert((OwnerName::apex().to_stored(), Some(6)));
            for row in &derived {
                if row.record_type != DnssecRecordType::Rrsig {
                    expected.insert((
                        row.name.to_stored(),
                        Some(row.record_type.wire_type() as i32),
                    ));
                }
            }
            let missing = expected.iter().find(|key| !covered.contains_key(key));

            checks.push(DnssecCheckInfo {
                check: "algorithm-coverage".to_string(),
                ok: offender.is_none() && missing.is_none(),
                detail: if let Some((name, covered_type)) = missing {
                    format!("RRset '{}' (type {:?}) has no RRSIG", name, covered_type)
                } else if let Some(((name, covered_type), algorithms)) = offender {
                    format!(
                        "RRset '{}' (type {:?}) signed by {:?}, zone algorithms {:?}",
                        name, covered_type, algorithms, zone_algorithms
                    )
                } else {
                    format!(
                        "{} RRsets signed by algorithm(s) {:?}",
                        covered.len(),
                        zone_algorithms
                    )
                },
            });

            let nsec = derived
                .iter()
                .filter(|row| row.record_type == DnssecRecordType::Nsec)
                .count();
            let nsec3 = derived
                .iter()
                .filter(|row| row.record_type == DnssecRecordType::Nsec3)
                .count();
            let nsec3param = derived
                .iter()
                .filter(|row| row.record_type == DnssecRecordType::Nsec3param)
                .count();
            let (denial_ok, denial_detail) = match zone.dnssec_denial {
                DnssecDenial::Nsec => (
                    nsec > 0 && nsec3 == 0,
                    format!("{} NSEC records (mode nsec)", nsec),
                ),
                DnssecDenial::Nsec3 => (
                    nsec3 > 0 && nsec3param > 0 && nsec == 0,
                    format!(
                        "{} NSEC3 + {} NSEC3PARAM records (mode nsec3)",
                        nsec3, nsec3param
                    ),
                ),
            };
            checks.push(DnssecCheckInfo {
                check: "denial".to_string(),
                ok: denial_ok,
                detail: denial_detail,
            });

            let expected = keys
                .iter()
                .filter(|key| key.wants_parent_ds())
                .map(|key| ds_info(&zone, key))
                .collect::<Result<Vec<_>, _>>()?;
            let withdrawing = RepositoryService::get_dnssec_withdrawal_tx(&mut tx, zone.id)
                .await?
                .is_some();

            Ok::<_, ServiceError>((
                VerifyDnssecResponse {
                    zone_name: zone.name.as_str().to_string(),
                    ok: checks.iter().all(|check| check.ok),
                    checks,
                },
                expected,
                withdrawing,
            ))
        }
        .await;
        let (mut response, expected, withdrawing) =
            RepositoryService::finish_tx(tx, result, "failed to verify DNSSEC state").await?;

        // The parent check probes the network, so it runs after the read
        // transaction ends.
        let resolver = bindizr_config()
            .dnssec
            .parent_ds_resolver
            .trim()
            .to_string();
        if !resolver.is_empty() {
            let (ok, detail) = parent_ds_check(&resolver, &expected, withdrawing, zone_name).await;
            response.ok &= ok;
            response.checks.push(DnssecCheckInfo {
                check: "parent-ds".to_string(),
                ok,
                detail,
            });
        }
        Ok(response)
    }
}

/// Compare the DS RRset the resolver serves against the zone's keys; a
/// published withdrawal inverts the expectation — done once the parent
/// serves no DS (RFC 8078).
async fn parent_ds_check(
    resolver: &str,
    expected: &[DnssecDsInfo],
    withdrawing: bool,
    zone_name: &str,
) -> (bool, String) {
    match crate::dns_client::probe::probe_parent_ds(zone_name).await {
        Ok(seen) if withdrawing => (
            seen.is_empty(),
            if seen.is_empty() {
                format!("withdrawal complete: no DS at {}", resolver)
            } else {
                format!(
                    "{} DS record(s) still published at {}",
                    seen.len(),
                    resolver
                )
            },
        ),
        Ok(seen) if seen.is_empty() => (
            false,
            format!("no DS at {} (delegation is insecure)", resolver),
        ),
        Ok(seen) => {
            let matched = seen
                .iter()
                .filter(|answer| expected.iter().any(|ds| ds.matches(answer)))
                .count();
            (
                matched > 0,
                format!(
                    "{} of {} DS records at {} match this zone's keys",
                    matched,
                    seen.len(),
                    resolver
                ),
            )
        }
        Err(e) => (false, format!("probe at {} failed: {}", resolver, e)),
    }
}
