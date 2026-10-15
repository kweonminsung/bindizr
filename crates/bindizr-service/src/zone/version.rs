use bindizr_core::{dns::Serial, model::zone_version::ZoneVersionId};
use chrono::Utc;

use crate::{
    Transaction,
    error::ServiceError,
    model::{
        zone::Zone,
        zone_version::{ChangeActor, ChangeSource, ZoneVersion},
    },
};

/// The origin of a version and the named credential behind it, independent of permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChangeAttribution {
    pub(crate) source: ChangeSource,
    pub(crate) actor: Option<ChangeActor>,
}

impl ChangeAttribution {
    /// The scheduler, acting on nobody's request.
    pub(crate) fn system() -> Self {
        ChangeAttribution {
            source: ChangeSource::System,
            actor: None,
        }
    }
}

/// Advance the zone serial so IXFR consumers detect the change, and
/// version it in the same transaction.
pub(crate) async fn advance_serial_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    new_serial: Serial,
    attribution: &ChangeAttribution,
) -> Result<(), ServiceError> {
    bindizr_db::zone::update_serial_tx(tx, zone.id, new_serial)
        .await
        .map_err(|e| {
            log::error!("Failed to update zone serial: {}", e);
            ServiceError::internal_with_source("failed to update zone serial", e)
        })?;

    save_version_tx(tx, zone, new_serial, attribution).await
}

/// Save a version of the zone's SOA data for historical tracking.
pub(crate) async fn save_version_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    serial: Serial,
    attribution: &ChangeAttribution,
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
            change_source: attribution.source,
            changed_by: attribution.actor.clone(),
            created_at: Utc::now(),
        },
    )
    .await
    .map_err(|e| {
        log::error!("Failed to save SOA version: {}", e);
        ServiceError::internal_with_source("failed to save SOA version", e)
    })?;

    Ok(())
}
