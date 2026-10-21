//! Read registered secondaries and assemble their named-key representations.

use std::collections::HashMap;

use bindizr_core::model::{role_grant::Action, tsig_key::TsigKeyId};

use super::{find_notify_tsig_key, normalize_secondary_name};
use crate::{
    Context,
    authorization::Caller,
    error::ServiceError,
    model::secondary::Secondary,
    pagination::{build_page, validate_page_limit},
    types::{PageRequest, PaginatedResponse, SecondaryResponse},
};

/// List every secondary, disabled ones included.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    page: PageRequest,
) -> Result<PaginatedResponse<SecondaryResponse>, ServiceError> {
    caller.authorize_action(Action::SecondaryRead)?;
    validate_page_limit(page.limit)?;

    let secondaries = bindizr_db::secondary::list_all(cx.db()).await?;

    // One statement names every key rather than one per secondary.
    let key_names: HashMap<TsigKeyId, String> = bindizr_db::tsig_key::list_all(cx.db())
        .await?
        .into_iter()
        .map(|tsig_key| (tsig_key.id, tsig_key.name))
        .collect();

    Ok(build_page(
        secondaries
            .iter()
            .map(|secondary| {
                SecondaryResponse::from_secondary(
                    secondary,
                    secondary
                        .notify_tsig_key_id
                        .and_then(|id| key_names.get(&id))
                        .map(String::as_str),
                )
            })
            .collect(),
        page.limit,
        page.offset,
    ))
}

/// Fetch one secondary by name.
pub async fn get(
    cx: &Context,
    caller: &Caller,
    name: &str,
) -> Result<SecondaryResponse, ServiceError> {
    caller.authorize_action(Action::SecondaryRead)?;
    let secondary = lookup_by_name(cx, name).await?;
    load_response(cx, secondary).await
}

/// The enabled secondaries, for the DNS plane, which takes no caller.
/// Read per use, so a change takes effect on the next NOTIFY or transfer.
pub async fn list_enabled(cx: &Context) -> Result<Vec<Secondary>, ServiceError> {
    Ok(bindizr_db::secondary::list_all(cx.db())
        .await?
        .into_iter()
        .filter(|secondary| secondary.enabled)
        .collect())
}

/// The API form of a secondary, naming its NOTIFY key.
pub(crate) async fn load_response(
    cx: &Context,
    secondary: Secondary,
) -> Result<SecondaryResponse, ServiceError> {
    let tsig_key = find_notify_tsig_key(cx, &secondary).await?;
    Ok(SecondaryResponse::from_secondary(
        &secondary,
        tsig_key.as_ref().map(|tsig_key| tsig_key.name.as_str()),
    ))
}

/// Fetch one secondary by name, unchecked.
pub(crate) async fn lookup_by_name(cx: &Context, name: &str) -> Result<Secondary, ServiceError> {
    let name = normalize_secondary_name(name)?;
    bindizr_db::secondary::get_by_name(cx.db(), &name)
        .await?
        .ok_or_else(|| ServiceError::secondary_not_found(&name))
}
