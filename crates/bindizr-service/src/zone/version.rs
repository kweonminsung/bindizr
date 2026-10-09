use std::collections::HashSet;

use bindizr_core::{
    dns::{Serial, name::OwnerName, record::SrvRecordValue},
    model::{zone::ZoneId, zone_version::ZoneVersionId},
};
use chrono::Utc;

use crate::{
    Context, Transaction,
    error::ServiceError,
    model::{
        record::RecordType,
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

/// Reject records below a DNAME owner (RFC 6672, Section 2.4): the DNAME
/// stands in for the whole subtree. Names go unnamed, as the DS check's do.
async fn validate_dname_subtrees_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
) -> Result<(), ServiceError> {
    let dnames =
        bindizr_db::record::list_by_record_types_tx(tx, zone_id, &[RecordType::Dname]).await?;
    if dnames.is_empty() {
        return Ok(());
    }
    // Below a DNAME: a proper ancestor, the apex included, owns one.
    let dname_owners: HashSet<&[String]> = dnames.iter().map(|dname| dname.name.labels()).collect();
    let names = bindizr_db::record::list_names_tx(tx, zone_id).await?;
    let below_a_dname = names.iter().any(|name| {
        let labels = name.labels();
        (1..=labels.len()).any(|depth| dname_owners.contains(&labels[depth..]))
    });
    if below_a_dname {
        return Err(ServiceError::record_conflict(
            "records cannot exist below a DNAME record (RFC 6672, Section 2.4)",
        ));
    }
    Ok(())
}

/// Reject an NS, MX, or SRV whose target in this zone is a CNAME (RFC 2181,
/// Section 10.3; RFC 2782). A target outside the zone is nobody's to check.
async fn validate_alias_targets_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
) -> Result<(), ServiceError> {
    let cnames =
        bindizr_db::record::list_by_record_types_tx(tx, zone.id, &[RecordType::Cname]).await?;
    if cnames.is_empty() {
        return Ok(());
    }
    let cnames: HashSet<&OwnerName> = cnames.iter().map(|cname| &cname.name).collect();
    let pointers = bindizr_db::record::list_by_record_types_tx(
        tx,
        zone.id,
        &[RecordType::Ns, RecordType::Mx, RecordType::Srv],
    )
    .await?;
    for record in &pointers {
        // An NS or MX value is its target; an SRV value carries it last.
        let target = match record.record_type {
            RecordType::Srv => SrvRecordValue::parse(&record.value, record.priority)
                .ok()
                .map(|srv| srv.target().to_string()),
            _ => Some(record.value.clone()),
        };
        let Some(owner) =
            target.and_then(|target| OwnerName::parse_absolute_in_zone(&target, &zone.name).ok())
        else {
            continue;
        };
        if cnames.contains(&owner) {
            return Err(ServiceError::record_conflict(
                "an NS, MX, or SRV record cannot name a CNAME record of this zone as its target (RFC 2181, Section 10.3; RFC 2782)",
            ));
        }
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
    validate_dname_subtrees_tx(tx, zone.id).await?;
    validate_alias_targets_tx(tx, zone).await?;
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
