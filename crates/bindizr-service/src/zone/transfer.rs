//! What a zone transfer may read: the enabled zone the request named, granted
//! to the key that signed it, decided on the locked row it will serve.

use bindizr_core::dns::name::ZoneName;
use bindizr_db::LockLevel;

use crate::{
    Context, Transaction,
    error::ServiceError,
    model::{dnssec_record::DnssecRecord, record::Record, tsig_key::TsigKey, zone::Zone},
    transaction,
    tsig_key::grant,
};

/// The outcome of asking to transfer a zone: what may be read, or the answer
/// the DNS plane owes instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferAccess<T> {
    Granted(T),
    /// No enabled zone carries the name: NOTAUTH.
    NotAuth,
    /// The key holds no grant over the whole zone: REFUSED, signed by it.
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
    pub records: Vec<Record>,
    pub dnssec_records: Vec<DnssecRecord>,
}

/// The enabled zone `zone_name` names, if `key` may transfer it (`None`, a
/// request the address ACL admitted, no grant narrows). Decided on the row
/// this transaction share-locks, with the grants locked beside it.
pub async fn authorize_transfer_by_name(
    cx: &Context,
    zone_name: &ZoneName,
    key: Option<&TsigKey>,
) -> Result<TransferAccess<Zone>, ServiceError> {
    let mut tx = transaction::begin_read_tx(cx, "failed to authorize the transfer").await?;
    let result = authorize_transfer_tx(&mut tx, zone_name, key).await;
    transaction::finish_tx(tx, result, "failed to authorize the transfer").await
}

/// Both record planes of the zone `zone_name` names, read under the share
/// lock that decides whether `key` may transfer it, so the serial, the
/// signatures, and the grant all describe one row.
pub async fn authorize_transfer_content_by_name(
    cx: &Context,
    zone_name: &ZoneName,
    key: Option<&TsigKey>,
) -> Result<TransferAccess<TransferContent>, ServiceError> {
    let mut tx = transaction::begin_read_tx(cx, "failed to load transfer content").await?;
    let result = async {
        let zone = match authorize_transfer_tx(&mut tx, zone_name, key).await? {
            TransferAccess::Granted(zone) => zone,
            TransferAccess::NotAuth => return Ok(TransferAccess::NotAuth),
            TransferAccess::Refused(reason) => return Ok(TransferAccess::Refused(reason)),
        };
        let records = bindizr_db::record::list_tx(&mut tx, zone.id, LockLevel::Unlocked).await?;
        let dnssec_records =
            bindizr_db::dnssec_record::list_tx(&mut tx, zone.id, LockLevel::Unlocked).await?;
        Ok(TransferAccess::Granted(TransferContent {
            zone,
            records,
            dnssec_records,
        }))
    }
    .await;
    transaction::finish_tx(tx, result, "failed to load transfer content").await
}

/// Share-lock the enabled zone by name and, for a scoped key, the grants
/// that must cover it whole.
async fn authorize_transfer_tx(
    tx: &mut Transaction<'_>,
    zone_name: &ZoneName,
    key: Option<&TsigKey>,
) -> Result<TransferAccess<Zone>, ServiceError> {
    let Some(zone) = super::find_served_by_name_tx(tx, zone_name, LockLevel::Shared).await? else {
        return Ok(TransferAccess::NotAuth);
    };
    if let Some(key) = key
        && !grant::authorize_whole_zone_tx(tx, &zone, key).await?
    {
        return Ok(TransferAccess::Refused(format!(
            "TSIG key '{}' is not granted zone '{}' whole",
            key.name, zone.name
        )));
    }
    Ok(TransferAccess::Granted(zone))
}
