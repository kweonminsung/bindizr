use chrono::Utc;

use super::ZoneService;
use crate::{
    RepositoryTx,
    error::ServiceError,
    metrics::track_serial_bump,
    model::{
        zone::Zone,
        zone_version::{ChangeSource, ZoneVersion},
    },
    repository::RepositoryService,
};

/// Who a zone version is recorded as the work of; the scheduler and an
/// unsigned update have no name to give.
pub(crate) struct ChangeSubject {
    pub(crate) source: ChangeSource,
    pub(crate) actor: Option<String>,
}

impl ChangeSubject {
    /// An RFC 2136 update, named by the TSIG key that signed it; unsigned
    /// updates reach here only through an address ACL, which names nobody.
    pub(crate) fn nsupdate(key_name: Option<&str>) -> Self {
        ChangeSubject {
            source: ChangeSource::Nsupdate,
            actor: key_name.map(str::to_string),
        }
    }

    /// The maintenance scheduler, acting on nobody's request.
    pub(crate) fn system() -> Self {
        ChangeSubject {
            source: ChangeSource::System,
            actor: None,
        }
    }
}

impl ZoneService {
    /// Advance the zone serial so IXFR consumers detect the change, and
    /// version it in the same transaction.
    pub(crate) async fn advance_serial_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        new_serial: i32,
        subject: &ChangeSubject,
    ) -> Result<(), ServiceError> {
        RepositoryService::update_zone_serial_tx(tx, zone.id, new_serial)
            .await
            .map_err(|e| {
                log::error!("Failed to update zone serial: {}", e);
                ServiceError::internal("Failed to update zone serial")
            })?;

        Self::save_version_tx(tx, zone, new_serial, subject).await
    }

    /// Reject DS records without an NS delegation at the same owner: a DS identifies a child
    /// zone's key (RFC 4034, Section 5).
    async fn validate_delegations_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), ServiceError> {
        let orphaned = RepositoryService::get_record_ds_name_without_ns_tx(tx, zone_id).await?;
        if let Some(name) = orphaned.as_deref() {
            let name = if name.is_empty() { "@" } else { name };
            return Err(ServiceError::record_conflict(format!(
                "DS records at '{}' require delegation NS records at the same name",
                name
            )));
        }
        Ok(())
    }

    /// Save a version of the zone's SOA data for historical tracking.
    /// Every mutation path ends here, so the cross-row invariants are
    /// checked once, against the final state, order-independently.
    pub(crate) async fn save_version_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        serial: i32,
        subject: &ChangeSubject,
    ) -> Result<(), ServiceError> {
        Self::validate_delegations_tx(tx, zone.id).await?;
        RepositoryService::upsert_zone_version_tx(
            tx,
            ZoneVersion {
                id: 0,
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
                change_source: subject.source,
                changed_by: subject.actor.clone(),
                created_at: Utc::now(),
            },
        )
        .await
        .map_err(|e| {
            log::error!("Failed to save SOA version: {}", e);
            ServiceError::internal("Failed to save SOA version")
        })?;

        // Every serial-advancing path funnels through this version write.
        track_serial_bump();

        Ok(())
    }

    /// Fetch the SOA version recorded for a zone at the given serial, if any.
    pub async fn find_version_by_serial(
        zone_id: i32,
        serial: i32,
    ) -> Result<Option<ZoneVersion>, ServiceError> {
        RepositoryService::get_zone_version_by_serial(zone_id, serial).await
    }

    /// Fetch every SOA version for a zone with serial in `[from_serial, to_serial]`.
    pub async fn list_versions_in_serial_range(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneVersion>, ServiceError> {
        RepositoryService::list_zone_versions_in_serial_range(zone_id, from_serial, to_serial).await
    }
}
