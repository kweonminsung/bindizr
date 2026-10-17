use bindizr_core::{
    dns::name::ZoneName,
    model::{
        audit_log::{AuditEntity, AuditOperation},
        role_grant::Action,
        zone_version::VersionFilter,
    },
};
use bindizr_db::{LockLevel, record::RecordFilter};

use crate::{
    Context, audit,
    authorization::Caller,
    error::ServiceError,
    transaction,
    types::{DeleteZoneResponse, Run, ZoneResponse},
};

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
        let zone = super::lookup_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        let caller = caller.reauthenticate_tx(&mut tx).await?;
        caller.authorize_zone_action(Action::ZoneDelete, &zone)?;

        // Counted for the report, not acted on, so they run unlocked.
        let records = bindizr_db::record::count_by_filter(
            cx.db(),
            RecordFilter {
                zone_name: Some(zone.name.clone()),
                ..RecordFilter::default()
            },
        )
        .await?;
        let versions =
            bindizr_db::zone_version::count_by_filter(cx.db(), zone.id, VersionFilter::All).await?;

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
            .map_err(|e| {
                log::error!("Failed to delete zone: {}", e);
                ServiceError::internal_with_source("failed to delete zone", e)
            })?;
        // The zone's versions went with it, so the deletion is the audit log's.
        audit::save_tx(
            &mut tx,
            AuditEntity::Zone,
            zone.name.as_str(),
            AuditOperation::Delete,
            Some(format!(
                "records_deleted {records}, versions_deleted {versions}"
            )),
            caller.change_attribution(),
        )
        .await?;
        Ok(response)
    }
    .await;

    let response = transaction::finish_tx(tx, apply_result, "failed to delete zone").await?;

    log::info!(
        "event=zone_delete zone={} applied={}",
        zone_name,
        response.applied
    );

    // Send catalog NOTIFY so secondaries drop the removed zone
    let config = cx.config();
    if response.applied {
        crate::notify::notify_after_update(cx, &config.dns.catalog_zone_name).await;
    }

    Ok(response)
}
