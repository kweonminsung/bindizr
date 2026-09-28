//! The Postgres SQL, one module per entity; the crate root dispatches here.

pub(crate) mod api_token;
pub(crate) mod catalog_zone;
pub(crate) mod dnssec_key;
pub(crate) mod dnssec_policy;
pub(crate) mod dnssec_record;
pub(crate) mod dnssec_withdrawal;
pub(crate) mod record;
pub(crate) mod secondary;
pub(crate) mod token_grant;
pub(crate) mod transfer;
pub(crate) mod tsig_grant;
pub(crate) mod tsig_key;
pub(crate) mod zone;
pub(crate) mod zone_change;
pub(crate) mod zone_version;
