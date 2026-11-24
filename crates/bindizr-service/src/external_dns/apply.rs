//! Applying an ExternalDNS change set atomically and idempotently: each name's
//! zone is resolved and authorized here, its change set computed in `change_set`.

use std::collections::{BTreeMap, BTreeSet};
use std::slice;
use std::time::Instant;

use bindizr_core::dns::name::{OwnerName, ZoneName};
use bindizr_core::model::activity_log::ActivityOperation;
use bindizr_core::model::role_grant::Action;
use bindizr_core::model::zone::Zone;
use bindizr_db::LockLevel;

use crate::authorization::{Caller, RecordAccess};
use crate::error::ServiceError;
use crate::external_dns::change_set::{RecordSetOperation, ZoneChangeSet, ZoneOperations};
use crate::external_dns::{change_set, policy};
use crate::types::{ApplyExternalDnsChangesRequest, ApplyExternalDnsChangesResponse};
use crate::{Context, dnssec, notify, record, serial, time, transaction, zone};

/// Apply all zones' ExternalDNS changes atomically, advancing serial/history
/// once per changed zone.
pub async fn apply_changes(
    cx: &Context,
    caller: &Caller,
    request: &ApplyExternalDnsChangesRequest,
) -> Result<ApplyExternalDnsChangesResponse, ServiceError> {
    let started = Instant::now();

    let operations = change_set::parse_changes_request(request)?;
    let requested_operations = operations.len();

    if operations.is_empty() {
        log::info!("event=external_dns_apply zones= ops=0 added=0 deleted=0 noop=true ms=0.0");
        return Ok(ApplyExternalDnsChangesResponse {
            changed_zones: Vec::new(),
            added: 0,
            deleted: 0,
        });
    }

    let mut tx = transaction::begin_tx(cx, "failed to apply ExternalDNS changes").await?;

    let apply_result: Result<_, ServiceError> = async {
        // Resolve authoritative zones from committed state inside the tx;
        // the residual race with concurrent zone creation is accepted.
        let zones = bindizr_db::zone::list_all_tx(&mut tx).await?;
        let zone_index = policy::ZoneIndex::new(&zones);

        // Only to learn the lock targets, from all zones so a hidden subzone
        // still shadows a granted parent; nothing is decided on these rows.
        let target_zone_names: BTreeSet<&ZoneName> = operations
            .iter()
            .filter_map(|operation| {
                let (RecordSetOperation::Add(record_set) | RecordSetOperation::Delete(record_set)) =
                    operation;
                zone_index.find(&record_set.name)
            })
            .map(|(zone, _)| &zone.name)
            .collect();

        // Name order, so concurrent multi-zone requests cannot deadlock on row locks.
        let mut locked_zones = Vec::new();
        for zone_name in target_zone_names {
            locked_zones
                .push(zone::lookup_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?);
        }

        let caller = &caller.reauthenticate_tx(&mut tx).await?;
        let locked_zone_index = policy::ZoneIndex::new(&locked_zones);

        // Refuse missing and hidden zones alike, in request order and before any
        // grant check; the locked zones hold each name's most-specific match.
        let mut resolved_operations = Vec::new();
        for operation in operations {
            let (action, record_set) = match &operation {
                RecordSetOperation::Add(record_set) => (Action::RecordCreate, record_set),
                RecordSetOperation::Delete(record_set) => (Action::RecordDelete, record_set),
            };
            let Some((zone, owner)) = locked_zone_index
                .find(&record_set.name)
                .filter(|(zone, _)| caller.sees_zone(zone.id))
            else {
                return Err(ServiceError::ZoneNotFound {
                    message: format!("no zone is authoritative for '{}'", record_set.name),
                });
            };

            let write = RecordAccess {
                action,
                relative_name: owner,
                record_type: Some(record_set.record_type),
            };
            resolved_operations.push((zone, write, operation));
        }

        // A write needs its grant even if its value is invalid or an
        // idempotent pair will later cancel it.
        for (zone, write, _) in &resolved_operations {
            caller.authorize_record_access(zone, slice::from_ref(write))?;
        }

        let mut zone_operations: BTreeMap<&ZoneName, (&Zone, ZoneOperations)> = BTreeMap::new();
        for (zone, write, operation) in resolved_operations {
            let (_, entry) = zone_operations
                .entry(&zone.name)
                .or_insert_with(|| (zone, ZoneOperations::default()));
            entry.push(write.relative_name, operation)?;
        }

        let mut changed_zones = Vec::new();
        let mut activities = Vec::new();
        let mut added = 0u64;
        let mut deleted = 0u64;

        for (zone, operations) in zone_operations.values() {
            // Only records sharing an owner name with the request can be
            // touched or conflict, so load just those.
            let mut owners: Vec<OwnerName> = operations
                .adds
                .iter()
                .chain(operations.deletes.iter())
                .map(|operation| operation.name.clone())
                .collect();
            owners.sort();
            owners.dedup();

            let records_at_owners = bindizr_db::record::list_by_names_tx(
                &mut tx,
                zone.id,
                &owners,
                LockLevel::Exclusive,
            )
            .await?;

            let change_set = ZoneChangeSet::compute(zone, operations, &records_at_owners)?;

            if change_set.deletes.is_empty() && change_set.creates.is_empty() {
                continue;
            }

            zone::validate_record_changes_tx(
                &mut tx,
                zone,
                &change_set.deletes,
                &change_set.creates,
            )
            .await?;

            // Apply the remaining delta and its signatures under one zone serial.
            let new_serial = serial::generate_serial(Some(zone.serial));

            record::delete_with_changes_tx(&mut tx, new_serial, &change_set.deletes).await?;
            let created =
                record::create_with_changes_tx(&mut tx, new_serial, &change_set.creates).await?;
            dnssec::sign_zone_tx(&mut tx, zone, new_serial).await?;

            // Advance the serial once so IXFR consumers detect the change
            zone::advance_serial_tx(&mut tx, zone, new_serial, caller.change_origin()).await?;

            activities.extend(change_set.deletes.iter().map(|record| {
                (
                    ActivityOperation::RecordDelete,
                    record::activity_target(&zone.name, record),
                )
            }));
            activities.extend(created.iter().map(|record| {
                (
                    ActivityOperation::RecordCreate,
                    record::activity_target(&zone.name, record),
                )
            }));
            activities.push((
                ActivityOperation::ExternalDnsApply,
                zone::activity_target(&zone.name),
            ));

            deleted += change_set.deletes.len() as u64;
            added += change_set.creates.len() as u64;
            changed_zones.push(zone.name.clone());
        }

        // Publish only after all affected zones have been written and versioned.
        crate::activity::save_operations_tx(&mut tx, activities, caller.change_origin()).await?;

        Ok((changed_zones, added, deleted))
    }
    .await;

    let (changed_zones, added, deleted) =
        transaction::finish_tx(tx, apply_result, "failed to apply ExternalDNS changes").await?;

    // Every affected zone must commit before any secondary is asked to transfer.
    cx.metrics().track_serial_bumps(changed_zones.len() as u64);

    for zone_name in &changed_zones {
        notify::notify_after_update(cx, zone_name).await;
    }

    let changed_zones: Vec<String> = changed_zones.iter().map(ToString::to_string).collect();
    log::info!(
        "event=external_dns_apply zones={} ops={requested_operations} added={added} deleted={deleted} noop={} ms={:.1}",
        changed_zones.join(","),
        changed_zones.is_empty(),
        time::elapsed_ms(started)
    );

    Ok(ApplyExternalDnsChangesResponse {
        changed_zones,
        added,
        deleted,
    })
}
