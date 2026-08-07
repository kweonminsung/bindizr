//! Conversion of ExternalDNS change sets into per-zone record operations and
//! their atomic, idempotent application.

use std::collections::BTreeMap;

use bindizr_core::dns::name::to_encoded_owner_name;
use chrono::Utc;

use super::{
    ExternalDnsService,
    policy::{find_authoritative_zone, normalize_lookup_name},
};
use crate::{
    authorization::{Caller, RecordWrite},
    error::{ErrorCode, ServiceError},
    log_info, log_warn,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    record::{RecordService, parse_record_type, validate_record_add_constraints_normalized},
    repository::RepositoryService,
    serial::generate_serial,
    types::{ExternalDnsChangesRequest, ExternalDnsChangesResponse, ExternalDnsRrset},
    zone::ZoneService,
};

/// Record types ExternalDNS may manage through this API.
pub(super) fn is_supported_record_type(record_type: &RecordType) -> bool {
    matches!(
        record_type,
        RecordType::A | RecordType::AAAA | RecordType::CNAME | RecordType::TXT
    )
}

/// One desired RRset operation; values are row-encoded and the name stays in
/// lookup form until zone grouping rewrites it to the encoded owner name.
#[derive(Debug)]
pub(super) struct RrsetOp {
    pub name: String,
    pub record_type: RecordType,
    /// Adds only; `None` resolves to the zone TTL at apply time.
    pub ttl: Option<i32>,
    pub values: Vec<String>,
}

pub(super) struct PendingOp {
    pub op: RrsetOp,
    pub is_delete: bool,
}

/// Adds and deletes of one request that resolved to the same zone.
#[derive(Debug, Default)]
pub(super) struct ZoneOps {
    pub adds: Vec<RrsetOp>,
    pub dels: Vec<RrsetOp>,
}

/// The record rows one zone's operations resolve to.
#[derive(Debug, Default)]
pub(super) struct ZoneChangeSet {
    pub deletes: Vec<Record>,
    pub creates: Vec<Record>,
}

fn parse_supported_record_type(record_type: &str) -> Result<RecordType, ServiceError> {
    let parsed = parse_record_type(record_type)?;
    if !is_supported_record_type(&parsed) {
        return Err(ServiceError::invalid_input(format!(
            "record type '{}' is not supported by the ExternalDNS API",
            parsed
        )));
    }
    Ok(parsed)
}

/// ExternalDNS sends TTL 0 for "not configured"; both resolve to the zone TTL.
fn normalize_ttl(ttl: Option<i32>) -> Result<Option<i32>, ServiceError> {
    match ttl {
        Some(ttl) if ttl < 0 => Err(ServiceError::invalid_input(
            "TTL must not be negative".to_string(),
        )),
        Some(0) | None => Ok(None),
        Some(ttl) => Ok(Some(ttl)),
    }
}

pub(super) fn convert_rrset(rrset: &ExternalDnsRrset) -> Result<RrsetOp, ServiceError> {
    let record_type = parse_supported_record_type(&rrset.record_type)?;
    let name = normalize_lookup_name(&rrset.name)?;
    let ttl = normalize_ttl(rrset.ttl)?;

    if rrset.values.is_empty() {
        return Err(ServiceError::invalid_input(format!(
            "RRset '{}' {} must have at least one value",
            rrset.name, record_type
        )));
    }
    if record_type == RecordType::CNAME && rrset.values.len() > 1 {
        return Err(ServiceError::invalid_record_value(format!(
            "CNAME RRset '{}' must have exactly one value",
            rrset.name
        )));
    }

    // Deduplicate values that normalize identically (e.g. IPv6 spellings).
    let mut values: Vec<String> = Vec::with_capacity(rrset.values.len());
    for value in &rrset.values {
        let encoded = record_type
            .encoded_value(value, None)
            .map_err(ServiceError::invalid_record_value)?;
        if !values
            .iter()
            .any(|existing| values_equal(existing, &encoded, &record_type))
        {
            values.push(encoded);
        }
    }

    Ok(RrsetOp {
        name,
        record_type,
        ttl,
        values,
    })
}

/// Flatten the request into ordered operations; an update becomes
/// delete(old) + add(new), with unchanged pairs canceling later.
pub(super) fn convert_request(
    request: &ExternalDnsChangesRequest,
) -> Result<Vec<PendingOp>, ServiceError> {
    let mut ops = Vec::new();
    for rrset in &request.deletes {
        ops.push(PendingOp {
            op: convert_rrset(rrset)?,
            is_delete: true,
        });
    }
    for update in &request.updates {
        ops.push(PendingOp {
            op: convert_rrset(&update.old)?,
            is_delete: true,
        });
        ops.push(PendingOp {
            op: convert_rrset(&update.new)?,
            is_delete: false,
        });
    }
    for rrset in &request.creates {
        ops.push(PendingOp {
            op: convert_rrset(rrset)?,
            is_delete: false,
        });
    }
    Ok(ops)
}

/// Resolve every operation to its most-specific authoritative zone; the
/// caller's write authorization is checked per zone inside the transaction.
pub(super) fn group_ops_by_zone(
    zones: &[Zone],
    ops: Vec<PendingOp>,
) -> Result<BTreeMap<String, ZoneOps>, ServiceError> {
    let mut grouped: BTreeMap<String, ZoneOps> = BTreeMap::new();

    for pending in ops {
        let zone = find_authoritative_zone(zones, &pending.op.name).ok_or_else(|| {
            ServiceError::new(
                ErrorCode::ZoneNotFound,
                format!("No zone is authoritative for '{}'", pending.op.name),
            )
        })?;

        let mut op = pending.op;
        op.name = to_encoded_owner_name(&op.name, &zone.name)
            .expect("find_authoritative_zone matched the name inside this zone");
        let entry = grouped.entry(zone.name.clone()).or_default();
        if pending.is_delete {
            entry.dels.push(op);
        } else {
            entry.adds.push(op);
        }
    }

    Ok(grouped)
}

fn values_equal(left: &str, right: &str, record_type: &RecordType) -> bool {
    record_type.values_equal(left, None, right, None)
}

/// Resolve one zone's operations against its current records; idempotent
/// operations cancel out, so an effect-free request yields an empty set.
pub(super) fn compute_zone_change_set(
    zone: &Zone,
    existing: &[Record],
    ops: &ZoneOps,
) -> Result<ZoneChangeSet, ServiceError> {
    let mut deletes: Vec<Record> = Vec::new();
    for del in &ops.dels {
        for value in &del.values {
            for row in existing {
                if row.name.eq_ignore_ascii_case(&del.name)
                    && row.record_type == del.record_type
                    && values_equal(&row.value, value, &del.record_type)
                    && !deletes.iter().any(|d| d.id == row.id)
                {
                    deletes.push(row.clone());
                }
            }
        }
    }

    let mut creates: Vec<Record> = Vec::new();
    for add in &ops.adds {
        let ttl = add.ttl.unwrap_or(zone.ttl);
        for value in &add.values {
            let matches = |row: &Record| {
                row.name.eq_ignore_ascii_case(&add.name)
                    && row.record_type == add.record_type
                    && row.ttl == ttl
                    && values_equal(&row.value, value, &add.record_type)
            };

            // An unchanged update cancels its own delete instead of
            // rewriting the row.
            if let Some(pos) = deletes.iter().position(&matches) {
                deletes.remove(pos);
                continue;
            }
            // Idempotent create: an identical surviving row already exists.
            if existing
                .iter()
                .any(|row| deletes.iter().all(|d| d.id != row.id) && matches(row))
            {
                continue;
            }
            // Intra-request duplicate create.
            if creates.iter().any(matches) {
                continue;
            }

            creates.push(Record {
                id: 0,
                name: add.name.clone(),
                record_type: add.record_type.clone(),
                value: value.clone(),
                ttl,
                priority: None,
                zone_id: zone.id,
                created_at: Utc::now(),
            });
        }
    }

    // Validate each insert against the post-delete state plus earlier inserts,
    // so CNAME exclusivity and RRset TTL rules see the state they will land in.
    for (index, create) in creates.iter().enumerate() {
        let mut same_name: Vec<Record> = existing
            .iter()
            .filter(|row| {
                deletes.iter().all(|d| d.id != row.id)
                    && row.name.eq_ignore_ascii_case(&create.name)
            })
            .cloned()
            .collect();
        same_name.extend(
            creates[..index]
                .iter()
                .filter(|row| row.name.eq_ignore_ascii_case(&create.name))
                .cloned(),
        );

        validate_record_add_constraints_normalized(
            &same_name,
            &create.name,
            &create.record_type,
            &create.value,
            create.ttl,
            create.priority,
            None,
        )?;
    }

    Ok(ZoneChangeSet { deletes, creates })
}

impl ExternalDnsService {
    /// Apply an ExternalDNS change set atomically: every zone's changes commit
    /// together or none do. Only zones with a remaining delta advance their
    /// serial (once per request) and record IXFR history.
    pub async fn apply_changes(
        request: &ExternalDnsChangesRequest,
        caller: &Caller,
    ) -> Result<ExternalDnsChangesResponse, ServiceError> {
        let started = std::time::Instant::now();

        let ops = convert_request(request)?;
        let requested_ops = ops.len();

        if ops.is_empty() {
            log_info!("event=external_dns_apply zones= ops=0 added=0 deleted=0 noop=true ms=0.0");
            return Ok(ExternalDnsChangesResponse {
                changed_zones: Vec::new(),
                records_added: 0,
                records_deleted: 0,
            });
        }

        let mut tx = RepositoryService::begin_tx("Failed to apply ExternalDNS changes").await?;

        let apply_result = async {
            // Resolve authoritative zones from committed state inside the tx;
            // the residual race with concurrent zone creation is accepted.
            let zones = RepositoryService::get_all_zones_tx(&mut tx).await?;
            let zone_ops = group_ops_by_zone(&zones, ops)?;

            let mut changed_zones = Vec::new();
            let mut records_added = 0u32;
            let mut records_deleted = 0u32;

            // BTreeMap iteration locks zones in name order, so concurrent
            // multi-zone requests cannot deadlock on row locks.
            for (zone_name, ops) in &zone_ops {
                let zone = RepositoryService::get_zone_by_name_tx(&mut tx, zone_name)
                    .await?
                    .ok_or_else(|| ServiceError::zone_not_found(zone_name))?;

                let writes: Vec<RecordWrite<'_>> = ops
                    .adds
                    .iter()
                    .chain(ops.dels.iter())
                    .map(|op| RecordWrite {
                        relative_name: &op.name,
                        record_type: Some(&op.record_type),
                    })
                    .collect();
                caller
                    .authorize_record_writes_tx(&mut tx, &zone, &writes)
                    .await?;

                // Only records sharing an owner name with the request can be
                // touched or conflict, so load just those.
                let mut names: Vec<String> = ops
                    .adds
                    .iter()
                    .chain(ops.dels.iter())
                    .map(|op| op.name.to_ascii_lowercase())
                    .collect();
                names.sort();
                names.dedup();
                let existing = RepositoryService::get_records_by_zone_id_and_names_tx(
                    &mut tx, zone.id, &names,
                )
                .await?;

                let change_set = compute_zone_change_set(&zone, &existing, ops)?;
                if change_set.deletes.is_empty() && change_set.creates.is_empty() {
                    continue;
                }

                let new_serial = generate_serial(Some(zone.serial))?;
                RecordService::delete_records_with_changes_tx(
                    &mut tx,
                    zone.id,
                    new_serial,
                    &change_set.deletes,
                )
                .await?;
                RecordService::insert_records_with_changes_tx(
                    &mut tx,
                    zone.id,
                    new_serial,
                    &change_set.creates,
                )
                .await?;
                ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

                records_deleted += change_set.deletes.len() as u32;
                records_added += change_set.creates.len() as u32;
                changed_zones.push(zone.name.clone());
            }

            Ok::<_, ServiceError>((changed_zones, records_added, records_deleted))
        }
        .await;

        let (changed_zones, records_added, records_deleted) =
            RepositoryService::finish_tx(tx, apply_result, "Failed to apply ExternalDNS changes")
                .await?;

        for zone_name in &changed_zones {
            if let Err(e) = crate::notify::send_notify_after_update(Some(zone_name)).await {
                log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
            }
        }

        log_info!(
            "event=external_dns_apply zones={} ops={} added={} deleted={} noop={} ms={:.1}",
            changed_zones.join(","),
            requested_ops,
            records_added,
            records_deleted,
            changed_zones.is_empty(),
            started.elapsed().as_secs_f64() * 1000.0,
        );

        Ok(ExternalDnsChangesResponse {
            changed_zones,
            records_added,
            records_deleted,
        })
    }
}
