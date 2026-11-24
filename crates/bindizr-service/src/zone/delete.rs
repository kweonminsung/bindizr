use bindizr_core::dns::name::ZoneName;
use bindizr_core::model::activity_log::{ActivityOperation, ActivityResult};
use bindizr_core::model::role_grant::Action;
use bindizr_db::LockLevel;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::types::{DeleteZoneResponse, Run, ZoneResponse};
use crate::{Context, activity, notify, transaction, zone};

/// Delete a zone, records, and rollback history; NOTIFY the catalog after commit.
/// A dry run reports the contents without removing them.
pub async fn delete(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    run: Run,
) -> Result<DeleteZoneResponse, ServiceError> {
    let mut tx = transaction::begin_tx(cx, "failed to delete zone").await?;

    let apply_result: Result<_, ServiceError> = async {
        // Locked lookup so a raced double-delete reports 404, not success.
        let zone = zone::lookup_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        let caller = &caller.reauthenticate_tx(&mut tx).await?;
        caller.authorize_zone_action(Action::ZoneDelete, &zone)?;

        // Counted for the report on the open transaction, which holds the
        // only connection this request takes.
        let records = bindizr_db::record::count_tx(&mut tx, zone.id).await?;
        let versions = bindizr_db::zone_version::count_tx(&mut tx, zone.id).await?;

        let response = DeleteZoneResponse {
            applied: !run.is_dry_run(),
            dry_run: run.is_dry_run(),
            zone: ZoneResponse::from(&zone),
            records_deleted: records,
            versions_deleted: versions,
        };

        if run.is_dry_run() {
            return Ok(response);
        }

        bindizr_db::zone::delete_tx(&mut tx, zone.id)
            .await
            .map_err(|error| ServiceError::internal_with_source("failed to delete zone", error))?;

        // The independent activity row survives the zone and its versions.
        activity::save_detail_tx(
            &mut tx,
            ActivityOperation::ZoneDelete,
            ActivityResult::Changed,
            zone::activity_target(&zone.name),
            Some(format!(
                "records_deleted {records}, versions_deleted {versions}"
            )),
            caller.change_origin(),
        )
        .await?;

        Ok(response)
    }
    .await;

    let response = transaction::finish_tx(tx, apply_result, "failed to delete zone").await?;

    log::info!(
        "event=zone_delete zone={zone_name} applied={}",
        response.applied
    );

    // Send catalog NOTIFY so secondaries drop the removed zone
    let config = cx.config();

    if response.applied {
        notify::notify_after_update(cx, &config.dns.catalog_zone_name).await;
    }

    Ok(response)
}
