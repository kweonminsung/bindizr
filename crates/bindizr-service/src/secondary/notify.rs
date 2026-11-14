//! Look up the TSIG key a registered secondary uses for outbound NOTIFY.

use bindizr_core::dns::tsig::TsigSigningKey;
use bindizr_core::model::secondary::Secondary;
use bindizr_core::model::tsig_key::TsigKey;

use crate::Context;
use crate::error::ServiceError;

/// The key a secondary's NOTIFY is signed with, ready to sign; `None`
/// for one notified unsigned. The FK keeps a referenced key present.
pub(crate) async fn find_notify_signing_key(
    cx: &Context,
    secondary: &Secondary,
) -> Result<Option<TsigSigningKey>, ServiceError> {
    let Some(tsig_key) = find_notify_tsig_key(cx, secondary).await? else {
        return Ok(None);
    };

    tsig_key.to_signing_key().map(Some).map_err(|error| {
        ServiceError::internal_with_source(
            format!("NOTIFY key '{}' is unusable: {:?}", tsig_key.name, error),
            error,
        )
    })
}

/// The stored key a secondary's NOTIFY is signed with, if any.
pub(crate) async fn find_notify_tsig_key(
    cx: &Context,
    secondary: &Secondary,
) -> Result<Option<TsigKey>, ServiceError> {
    let Some(id) = secondary.notify_tsig_key_id else {
        return Ok(None);
    };

    Ok(Some(
        bindizr_db::tsig_key::get(cx.db(), id)
            .await?
            .ok_or_else(|| ServiceError::internal(format!("TSIG key {id} is missing")))?,
    ))
}
