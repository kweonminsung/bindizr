//! Self-checks of a signed zone's stored state: key inventory, signature
//! freshness, per-algorithm coverage, and the denial chain.

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;

use super::DnssecService;
use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    error::ServiceError,
    model::{dnssec_record::DnssecRecordType, zone::DnssecDenial},
    repository::RepositoryService,
    types::{DnssecCheckInfo, VerifyDnssecResponse},
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
            checks.push(DnssecCheckInfo {
                check: "algorithm-coverage".to_string(),
                ok: offender.is_none(),
                detail: match offender {
                    None => format!(
                        "{} RRsets signed by algorithm(s) {:?}",
                        covered.len(),
                        zone_algorithms
                    ),
                    Some(((name, covered_type), algorithms)) => format!(
                        "RRset '{}' (type {:?}) signed by {:?}, zone algorithms {:?}",
                        name, covered_type, algorithms, zone_algorithms
                    ),
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

            Ok::<_, ServiceError>(VerifyDnssecResponse {
                zone_name: zone.name.as_str().to_string(),
                ok: checks.iter().all(|check| check.ok),
                checks,
            })
        }
        .await;
        RepositoryService::finish_tx(tx, result, "failed to verify DNSSEC state").await
    }
}
