//! What a zone transfer may read: the enabled zone the request named, granted
//! to the caller its key became, decided on the locked row it will serve.

use bindizr_core::{dns::name::ZoneName, model::role_grant::Action};
use bindizr_db::LockLevel;

mod ixfr;

pub use ixfr::{IxfrPlan, authorize_ixfr_plan_by_name};

use crate::{
    Context, Transaction,
    authorization::Caller,
    error::{ErrorCode, ServiceError},
    model::{dnssec_record::DnssecRecord, record::Record, zone::Zone, zone_version::ZoneVersionId},
    transaction,
};

/// The outcome of asking to transfer a zone: what may be read, or the answer
/// the DNS plane owes instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferAccess<T> {
    Granted(T),
    /// No enabled zone carries the name: NOTAUTH.
    NotAuth,
    /// The key's role holds no `zone:transfer` reaching the zone: REFUSED, signed by it.
    Refused(String),
}

impl<T> TransferAccess<T> {
    /// Carry a granted value into another shape, leaving a denial as it is.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> TransferAccess<U> {
        match self {
            TransferAccess::Granted(value) => TransferAccess::Granted(f(value)),
            TransferAccess::NotAuth => TransferAccess::NotAuth,
            TransferAccess::Refused(reason) => TransferAccess::Refused(reason),
        }
    }
}

/// A zone with both record planes, as a full transfer serves them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferContent {
    pub zone: Zone,
    pub version_id: ZoneVersionId,
    pub records: Vec<Record>,
    pub dnssec_records: Vec<DnssecRecord>,
}

/// The enabled zone `zone_name` names, if `caller` may transfer it. Decided
/// on the row this transaction share-locks, with the grants re-read beside it.
pub async fn authorize_transfer_by_name(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
) -> Result<TransferAccess<(Zone, ZoneVersionId)>, ServiceError> {
    let mut tx = transaction::begin_read_tx(cx, "failed to authorize the transfer").await?;
    let result = async {
        match authorize_transfer_tx(&mut tx, caller, zone_name).await? {
            TransferAccess::Granted(zone) => {
                let version_id = lookup_current_version_id_tx(&mut tx, &zone).await?;
                Ok(TransferAccess::Granted((zone, version_id)))
            }
            TransferAccess::NotAuth => Ok(TransferAccess::NotAuth),
            TransferAccess::Refused(reason) => Ok(TransferAccess::Refused(reason)),
        }
    }
    .await;
    transaction::finish_tx(tx, result, "failed to authorize the transfer").await
}

/// Authorize a catalog transfer and load its member zones in one read
/// transaction; the caller needs `zone:transfer` in all zones.
pub async fn authorize_catalog_content(
    cx: &Context,
    caller: &Caller,
) -> Result<TransferAccess<Vec<Zone>>, ServiceError> {
    let mut tx = transaction::begin_read_tx(cx, "failed to load catalog content").await?;
    let result = async {
        let caller = match reauthenticate_transfer_tx(&mut tx, caller).await? {
            TransferAccess::Granted(caller) => caller,
            TransferAccess::NotAuth => return Ok(TransferAccess::NotAuth),
            TransferAccess::Refused(reason) => return Ok(TransferAccess::Refused(reason)),
        };
        if let Err(e) = caller.authorize_action(Action::ZoneTransfer) {
            return Ok(TransferAccess::Refused(e.to_string()));
        }
        let zones = bindizr_db::zone::list_all_tx(&mut tx, LockLevel::Unlocked).await?;
        Ok(TransferAccess::Granted(
            zones.into_iter().filter(|zone| zone.enabled).collect(),
        ))
    }
    .await;
    transaction::finish_tx(tx, result, "failed to load catalog content").await
}

/// Authorize the caller and read both record planes in one shared-lock snapshot.
pub async fn authorize_transfer_content_by_name(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
) -> Result<TransferAccess<TransferContent>, ServiceError> {
    let mut tx = transaction::begin_read_tx(cx, "failed to load transfer content").await?;
    let result = async {
        let zone = match authorize_transfer_tx(&mut tx, caller, zone_name).await? {
            TransferAccess::Granted(zone) => zone,
            TransferAccess::NotAuth => return Ok(TransferAccess::NotAuth),
            TransferAccess::Refused(reason) => return Ok(TransferAccess::Refused(reason)),
        };
        let records = bindizr_db::record::list_tx(&mut tx, zone.id, LockLevel::Unlocked).await?;
        let dnssec_records =
            bindizr_db::dnssec_record::list_tx(&mut tx, zone.id, LockLevel::Unlocked).await?;
        let version_id = lookup_current_version_id_tx(&mut tx, &zone).await?;
        Ok(TransferAccess::Granted(TransferContent {
            zone,
            version_id,
            records,
            dnssec_records,
        }))
    }
    .await;
    transaction::finish_tx(tx, result, "failed to load transfer content").await
}

/// Read the immutable version identity, which remains distinct when serials wrap.
async fn lookup_current_version_id_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
) -> Result<ZoneVersionId, ServiceError> {
    bindizr_db::zone_version::get_by_serial_tx(tx, zone.id, zone.serial, LockLevel::Unlocked)
        .await?
        .map(|version| version.id)
        .ok_or_else(|| ServiceError::internal("the current zone version is missing"))
}

/// Share-lock the enabled zone by name and the grants that must permit the
/// transfer, re-read for the caller as every transaction does.
async fn authorize_transfer_tx(
    tx: &mut Transaction<'_>,
    caller: &Caller,
    zone_name: &ZoneName,
) -> Result<TransferAccess<Zone>, ServiceError> {
    let Some(zone) = super::find_served_by_name_tx(tx, zone_name, LockLevel::Shared).await? else {
        return Ok(TransferAccess::NotAuth);
    };
    let caller = match reauthenticate_transfer_tx(tx, caller).await? {
        TransferAccess::Granted(caller) => caller,
        TransferAccess::NotAuth => return Ok(TransferAccess::NotAuth),
        TransferAccess::Refused(reason) => return Ok(TransferAccess::Refused(reason)),
    };
    // A zone the role does not reach is refused rather than hidden: NOTAUTH
    // would claim the zone is not served, and its name is no secret here.
    match caller.authorize_zone_action(Action::ZoneTransfer, &zone) {
        Ok(()) => Ok(TransferAccess::Granted(zone)),
        Err(e) if e.code() == ErrorCode::ZoneNotFound => Ok(TransferAccess::Refused(format!(
            "role does not permit '{}' in zone '{}'",
            Action::ZoneTransfer,
            zone.name
        ))),
        Err(e) => Ok(TransferAccess::Refused(e.to_string())),
    }
}

/// Re-read the caller's credential and grants under the transfer's lock; a
/// credential gone since is a refusal, not a fault.
async fn reauthenticate_transfer_tx(
    tx: &mut Transaction<'_>,
    caller: &Caller,
) -> Result<TransferAccess<Caller>, ServiceError> {
    match caller.reauthenticate_tx(tx).await {
        Ok(caller) => Ok(TransferAccess::Granted(caller)),
        Err(e) if e.code() == ErrorCode::InvalidToken => Ok(TransferAccess::Refused(e.to_string())),
        Err(e) => Err(e),
    }
}
