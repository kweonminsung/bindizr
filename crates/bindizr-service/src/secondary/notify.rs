//! Load the TSIG key a registered secondary uses for outbound NOTIFY.

use bindizr_core::dns::tsig::TsigSigningKey;

use crate::{
    Context,
    error::ServiceError,
    model::{secondary::Secondary, tsig_key::TsigKey},
};

/// The key a secondary's NOTIFY is signed with, ready to sign; `None`
/// for one notified unsigned. The FK keeps a referenced key present.
pub(crate) async fn find_notify_signing_key(
    cx: &Context,
    secondary: &Secondary,
) -> Result<Option<TsigSigningKey>, ServiceError> {
    match find_notify_tsig_key(cx, secondary).await? {
        Some(tsig_key) => tsig_key.to_signing_key().map(Some).map_err(|e| {
            ServiceError::internal_with_source(
                format!("NOTIFY key '{}' is unusable: {:?}", tsig_key.name, e),
                e,
            )
        }),
        None => Ok(None),
    }
}

/// The stored key a secondary's NOTIFY is signed with, if any.
pub(crate) async fn find_notify_tsig_key(
    cx: &Context,
    secondary: &Secondary,
) -> Result<Option<TsigKey>, ServiceError> {
    match secondary.notify_tsig_key_id {
        Some(id) => Ok(Some(
            bindizr_db::tsig_key::get(cx.db(), id)
                .await?
                .ok_or_else(|| ServiceError::internal(format!("TSIG key {} is missing", id)))?,
        )),
        None => Ok(None),
    }
}
