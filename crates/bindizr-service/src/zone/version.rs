use bindizr_core::{
    dns::Serial,
    model::{zone::ZoneId, zone_version::ZoneVersionId},
};
use chrono::Utc;

use crate::{
    Context, Transaction,
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
    /// An RFC 2136 update, named by the TSIG key that signed it; unsigned
    /// updates reach here only through an address ACL, which names nobody.
    pub(crate) fn nsupdate(key_name: Option<&str>) -> Self {
        ChangeAttribution {
            source: ChangeSource::Nsupdate,
            actor: key_name.map(|name| ChangeActor::TsigKey {
                name: name.to_string(),
            }),
        }
    }

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
    cx: &Context,
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

    save_version_tx(tx, cx, zone, new_serial, attribution).await
}

/// Reject DS records without an NS delegation at the same owner: a DS identifies a child
/// zone's key (RFC 4034, Section 5).
///
/// The owner goes unnamed, as a delete by id may orphan it for a caller who
/// cannot read it; bulk and import name the owners they touch first.
async fn validate_delegations_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
) -> Result<(), ServiceError> {
    if bindizr_db::record::find_name_ds_without_ns_tx(tx, zone_id)
        .await?
        .is_some()
    {
        return Err(ServiceError::record_conflict(
            "DS records require delegation NS records at the same name",
        ));
    }
    Ok(())
}

/// Save a version of the zone's SOA data for historical tracking.
/// Every mutation path ends here, so the cross-row invariants are
/// checked once, against the final state, order-independently.
pub(crate) async fn save_version_tx(
    tx: &mut Transaction<'_>,
    cx: &Context,
    zone: &Zone,
    serial: Serial,
    attribution: &ChangeAttribution,
) -> Result<(), ServiceError> {
    validate_delegations_tx(tx, zone.id).await?;
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

    // Every serial-advancing path funnels through this version write.
    cx.metrics().track_serial_bump();

    Ok(())
}

/// Fetch the SOA version recorded for a zone at the given serial, if any.
pub async fn find_version_by_serial(
    cx: &Context,
    zone_id: ZoneId,
    serial: Serial,
) -> Result<Option<ZoneVersion>, ServiceError> {
    Ok(bindizr_db::zone_version::get_by_serial(cx.db(), zone_id, serial).await?)
}

/// Fetch every SOA version for a zone with serial in `[from_serial, to_serial]`.
pub async fn list_versions_in_serial_range(
    cx: &Context,
    zone_id: ZoneId,
    from_serial: Serial,
    to_serial: Serial,
) -> Result<Vec<ZoneVersion>, ServiceError> {
    Ok(
        bindizr_db::zone_version::list_in_serial_range(cx.db(), zone_id, from_serial, to_serial)
            .await?,
    )
}
