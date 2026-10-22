use bindizr_core::{dns::Serial, model::zone_version::ZoneVersionId};
use chrono::Utc;

use crate::{
    Transaction,
    change::ChangeOrigin,
    error::ServiceError,
    model::{zone::Zone, zone_version::ZoneVersion},
};

/// Advance the zone serial so IXFR consumers detect the change, and
/// version it in the same transaction.
pub(crate) async fn advance_serial_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    new_serial: Serial,
    origin: &ChangeOrigin,
) -> Result<(), ServiceError> {
    bindizr_db::zone::update_serial_tx(tx, zone.id, new_serial)
        .await
        .map_err(|error| {
            log::error!("Failed to update zone serial: {}", error);
            ServiceError::internal_with_source("failed to update zone serial", error)
        })?;

    save_version_tx(tx, zone, new_serial, origin).await
}

/// Save a version of the zone's SOA data for historical tracking.
pub(crate) async fn save_version_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    serial: Serial,
    origin: &ChangeOrigin,
) -> Result<(), ServiceError> {
    // Retire ambiguous history before serial values can be reused after wrapping.
    bindizr_db::zone_change::prune_outside_serial_window_tx(tx, zone.id, serial).await?;
    bindizr_db::zone_version::prune_outside_serial_window_tx(tx, zone.id, serial).await?;
    bindizr_db::zone_version::upsert_tx(
        tx,
        ZoneVersion {
            id: ZoneVersionId::UNWRITTEN,
            zone_id: zone.id,
            serial,
            mname: zone.mname.clone(),
            rname: zone
                .soa_mailbox()
                .map_err(ServiceError::invalid_zone_field)?
                .into_encoded(),
            default_ttl: zone.default_ttl,
            refresh: zone.refresh,
            retry: zone.retry,
            expire: zone.expire,
            minimum_ttl: zone.minimum_ttl,
            change_source: origin.source,
            changed_by: origin.actor.clone(),
            created_at: Utc::now(),
        },
    )
    .await
    .map_err(|error| {
        log::error!("Failed to save SOA version: {}", error);
        ServiceError::internal_with_source("failed to save SOA version", error)
    })?;

    Ok(())
}
