use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::dns::address::AddressTarget;
use crate::model::tsig_key::TsigKeyId;

id_newtype!(
    /// The id of a secondary row.
    SecondaryId
);

/// A secondary server: it receives NOTIFY, may pull zones unsigned from its
/// address, and is probed for the serial it serves.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct Secondary {
    pub id: SecondaryId,
    pub name: String,
    /// A hostname is resolved when used, not when stored.
    pub address: AddressTarget,
    /// Disabled: no NOTIFY, no unsigned transfer, no probe; still registered.
    pub enabled: bool,
    /// TSIG key outbound NOTIFY is signed with; `None` sends it unsigned.
    pub notify_tsig_key_id: Option<TsigKeyId>,
    pub created_at: DateTime<Utc>,
}

/// A secondary joined with its NOTIFY key's name, without loading the key's secret.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct SecondaryWithNotifyKey {
    #[sqlx(flatten)]
    pub secondary: Secondary,
    pub notify_tsig_key_name: Option<String>,
}
