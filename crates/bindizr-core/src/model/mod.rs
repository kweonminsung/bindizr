//! The database models every layer above shares.

pub mod api_token;
pub mod dnssec_key;
pub mod dnssec_policy;
pub mod dnssec_record;
pub mod record;
pub mod secondary;
pub mod token_grant;
pub mod tsig_grant;
pub mod tsig_key;
pub mod zone;
pub mod zone_change;
pub mod zone_version;

/// The id the database gave a row, or `None` for one it has not seen: every
/// insert starts from the `0` placeholder, which is no id at all.
pub fn written_id(id: i32) -> Option<i32> {
    (id != 0).then_some(id)
}
