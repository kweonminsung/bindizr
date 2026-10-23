//! Applying an ExternalDNS change set atomically and idempotently; the change
//! set itself is computed in `change_set`.

use bindizr_core::{dns::name::OwnerName, model::role_grant::Action};
use bindizr_db::LockLevel;

use super::change_set::{ZoneChangeSet, group_operations_by_zone, parse_changes_request};
use crate::{
    Context,
    authorization::{Caller, RecordAccess},
    dnssec,
    error::ServiceError,
    record,
    serial::generate_serial,
    time::elapsed_ms,
    transaction,
    types::{ApplyExternalDnsChangesRequest, ApplyExternalDnsChangesResponse},
    zone,
};

/// Apply all zones' ExternalDNS changes atomically, advancing serial/history
/// once per changed zone.
pub async fn apply_changes(
    cx: &Context,
    caller: &Caller,
    request: &ApplyExternalDnsChangesRequest,
) -> Result<ApplyExternalDnsChangesResponse, ServiceError> {
    let started = std::time::Instant::now();

    let operations = parse_changes_request(request)?;
    let requested_ops = operations.len();

    if operations.is_empty() {
        log::info!("event=external_dns_apply zones= ops=0 added=0 deleted=0 noop=true ms=0.0");
        return Ok(ApplyExternalDnsChangesResponse {
            changed_zones: Vec::new(),
            added: 0,
            deleted: 0,
        });
    }

    let mut tx = transaction::begin_tx(cx, "failed to apply ExternalDNS changes").await?;

    let apply_result = async {
        // Resolve authoritative zones from committed state inside the tx;
        // the residual race with concurrent zone creation is accepted.
        let zones = bindizr_db::zone::list_all_tx(&mut tx, LockLevel::Unlocked).await?;
        let zone_operations = group_operations_by_zone(&zones, operations)?;

        let mut changed_zones = Vec::new();
        let mut added = 0u64;
        let mut deleted = 0u64;

        // BTreeMap iteration locks zones in name order, so concurrent
        // multi-zone requests cannot deadlock on row locks.
        for (zone_name, operations) in &zone_operations {
            let zone = bindizr_db::zone::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive)
                .await?
                .ok_or_else(|| ServiceError::zone_not_found(zone_name))?;
            let caller = &caller.reauthenticate_tx(&mut tx).await?;

            if !caller.sees_zone(zone.id) {
                return Err(ServiceError::ZoneNotFound(format!(
                    "no zone is authoritative for '{}'",
                    operations.request_name
                )));
            }

            // Authorize the requested operations before idempotent pairs cancel;
            // a no-op must not bypass grants or reveal existing records.
            let adds = operations.adds.iter().map(|op| (Action::RecordCreate, op));
            let deletes = operations
                .deletes
                .iter()
                .map(|op| (Action::RecordDelete, op));
            let writes: Vec<RecordAccess<'_>> = adds
                .chain(deletes)
                .map(|(action, op)| RecordAccess {
                    action,
                    relative_name: op.name.clone(),
                    record_type: Some(&op.record_type),
                })
                .collect();

            caller.authorize_record_access(&zone, &writes)?;

            // Only records sharing an owner name with the request can be
            // touched or conflict, so load just those.
            let mut names: Vec<OwnerName> = operations
                .adds
                .iter()
                .chain(operations.deletes.iter())
                .map(|op| op.name.clone())
                .collect();
            names.sort();
            names.dedup();

            let records_at_names = bindizr_db::record::list_by_names_tx(
                &mut tx,
                zone.id,
                &names,
                LockLevel::Exclusive,
            )
            .await?;

            let change_set = ZoneChangeSet::compute(operations, &zone, &records_at_names)?;

            if change_set.deletes.is_empty() && change_set.creates.is_empty() {
                continue;
            }

            zone::validate_record_changes_tx(
                &mut tx,
                &zone,
                &change_set.deletes,
                &change_set.creates,
            )
            .await?;

            // Apply the remaining delta and its signatures under one zone serial.
            let new_serial = generate_serial(Some(zone.serial));

            record::delete_with_changes_tx(&mut tx, zone.id, new_serial, &change_set.deletes)
                .await?;
            record::create_with_changes_tx(&mut tx, zone.id, new_serial, &change_set.creates)
                .await?;
            dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;

            // Advance the serial once so IXFR consumers detect the change
            zone::advance_serial_tx(&mut tx, &zone, new_serial, caller.change_origin()).await?;

            deleted += change_set.deletes.len() as u64;
            added += change_set.creates.len() as u64;
            changed_zones.push(zone.name.clone());
        }

        Ok::<_, ServiceError>((changed_zones, added, deleted))
    }
    .await;

    let (changed_zones, added, deleted) =
        transaction::finish_tx(tx, apply_result, "failed to apply ExternalDNS changes").await?;

    // Every affected zone must commit before any secondary is asked to transfer.
    cx.metrics().track_serial_bumps(changed_zones.len() as u64);

    for zone_name in &changed_zones {
        crate::notify::notify_after_update(cx, zone_name).await;
    }

    let changed_zones: Vec<String> = changed_zones.iter().map(ToString::to_string).collect();
    log::info!(
        "event=external_dns_apply zones={} ops={} added={} deleted={} noop={} ms={:.1}",
        changed_zones.join(","),
        requested_ops,
        added,
        deleted,
        changed_zones.is_empty(),
        elapsed_ms(started),
    );

    Ok(ApplyExternalDnsChangesResponse {
        changed_zones,
        added,
        deleted,
    })
}
