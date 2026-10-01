use bindizr_core::{dns::name::ZoneName, model::zone_version::VersionScope};
use bindizr_db::{LockLevel, record::RecordFilter};

use crate::{
    Context,
    authorization::Caller,
    error::ServiceError,
    transaction,
    types::{DeleteZoneResponse, GetZoneResponse, Run},
};

/// Delete a zone by name and NOTIFY the catalog zone after commit. A dry
/// run reports what the zone holds and removes nothing, since the delete
/// takes the records and the rollback history with it.
pub async fn delete(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    run: Run,
) -> Result<DeleteZoneResponse, ServiceError> {
    caller.authorize_global("delete zones")?;

    let mut tx = transaction::begin_tx(cx, "Failed to delete zone").await?;

    let apply_result: Result<_, ServiceError> = async {
        // Locked lookup so a raced double-delete reports 404, not success.
        let zone = super::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;

        // Counted for the report, not acted on, so they run unlocked.
        let records = bindizr_db::record::count_by_filter(
            cx.db(),
            RecordFilter {
                zone_name: Some(zone.name.clone()),
                ..RecordFilter::default()
            },
        )
        .await?;
        let versions = bindizr_db::zone_version::count(cx.db(), zone.id, VersionScope::All).await?;

        let response = DeleteZoneResponse {
            applied: !run.is_dry_run(),
            dry_run: run.is_dry_run(),
            zone: GetZoneResponse::from(&zone),
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
                ServiceError::internal("Failed to delete zone")
            })?;
        log::info!("event=zone_delete zone={} zone_id={}", zone.name, zone.id);
        Ok(response)
    }
    .await;

    let response = transaction::finish_tx(tx, apply_result, "Failed to delete zone").await?;

    // Send catalog NOTIFY so secondaries drop the removed zone
    let config = cx.config();
    if response.applied {
        crate::notify::notify_after_update(cx, &config.dns.catalog_zone_name).await;
    }

    Ok(response)
}
