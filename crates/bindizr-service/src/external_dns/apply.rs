//! Applying an ExternalDNS change set atomically and idempotently; the change
//! set itself is computed in `change_set`.

use bindizr_core::dns::name::OwnerName;
use bindizr_db::repository::LockLevel;

use super::{
    ExternalDnsService,
    change_set::{compute_zone_change_set, group_ops_by_zone, parse_changes_request},
};
use crate::{
    authorization::{Caller, RecordWrite},
    dnssec::DnssecService,
    error::ServiceError,
    log_info, log_warn,
    record::RecordService,
    repository::RepositoryService,
    serial::generate_serial,
    types::{ExternalDnsChangesRequest, ExternalDnsChangesResponse},
    zone::ZoneService,
};

impl ExternalDnsService {
    /// Apply an ExternalDNS change set atomically: every zone's changes commit
    /// together or none do. Only zones with a remaining delta advance their
    /// serial (once per request) and record IXFR history.
    pub async fn apply_changes(
        caller: &Caller,
        request: &ExternalDnsChangesRequest,
    ) -> Result<ExternalDnsChangesResponse, ServiceError> {
        let started = std::time::Instant::now();

        let ops = parse_changes_request(request)?;
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
            let zones = RepositoryService::list_zones_tx(&mut tx, LockLevel::None).await?;
            let zone_ops = group_ops_by_zone(caller, &zones, ops)?;

            let mut changed_zones = Vec::new();
            let mut records_added = 0u32;
            let mut records_deleted = 0u32;

            // BTreeMap iteration locks zones in name order, so concurrent
            // multi-zone requests cannot deadlock on row locks.
            for (zone_name, ops) in &zone_ops {
                let zone = RepositoryService::get_zone_by_name_tx(
                    &mut tx,
                    zone_name.as_str(),
                    LockLevel::Exclusive,
                )
                .await?
                .ok_or_else(|| ServiceError::zone_not_found(zone_name.as_str()))?;

                let writes: Vec<RecordWrite<'_>> = ops
                    .adds
                    .iter()
                    .chain(ops.dels.iter())
                    .map(|op| RecordWrite {
                        relative_name: op.name.clone(),
                        record_type: Some(&op.record_type),
                    })
                    .collect();
                caller
                    .authorize_record_writes_tx(&mut tx, &zone, &writes)
                    .await?;

                // Only records sharing an owner name with the request can be
                // touched or conflict, so load just those.
                let mut names: Vec<OwnerName> = ops
                    .adds
                    .iter()
                    .chain(ops.dels.iter())
                    .map(|op| op.name.clone())
                    .collect();
                names.sort();
                names.dedup();
                let existing = RepositoryService::list_records_by_names_tx(
                    &mut tx,
                    zone.id,
                    &names,
                    LockLevel::Exclusive,
                )
                .await?;

                let change_set = compute_zone_change_set(&zone, &existing, ops)?;
                if change_set.deletes.is_empty() && change_set.creates.is_empty() {
                    continue;
                }

                let new_serial = generate_serial(Some(zone.serial))?;
                RecordService::delete_with_changes_tx(
                    &mut tx,
                    zone.id,
                    new_serial,
                    &change_set.deletes,
                )
                .await?;
                RecordService::create_with_changes_tx(
                    &mut tx,
                    zone.id,
                    new_serial,
                    &change_set.creates,
                )
                .await?;
                DnssecService::sign_zone_tx(&mut tx, &zone, new_serial).await?;
                // Advance the serial once so IXFR consumers detect the change
                ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

                records_deleted += change_set.deletes.len() as u32;
                records_added += change_set.creates.len() as u32;
                changed_zones.push(zone.name.to_string());
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
