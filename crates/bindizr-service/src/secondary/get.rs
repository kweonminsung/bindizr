//! Read registered secondaries and assemble their named-key representations.

use bindizr_core::model::role_grant::Action;
use bindizr_core::model::secondary::Secondary;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::types::{PageRequest, PaginatedResponse, SecondaryResponse};
use crate::{Context, pagination, secondary};

/// List every secondary, disabled ones included.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    page: PageRequest,
) -> Result<PaginatedResponse<SecondaryResponse>, ServiceError> {
    caller.authorize_action(Action::SecondaryRead)?;
    pagination::validate_page_limit(page.limit)?;

    let total = bindizr_db::secondary::count_all(cx.db()).await?;
    let secondaries =
        bindizr_db::secondary::list_all_with_notify_tsig_key(cx.db(), page.limit, page.offset)
            .await?;

    Ok(pagination::build_paginated_response(
        secondaries
            .iter()
            .map(|secondary| {
                SecondaryResponse::from_secondary(
                    &secondary.secondary,
                    secondary.notify_key_name.as_deref(),
                )
            })
            .collect(),
        page.limit,
        page.offset,
        total,
    ))
}

/// Get one secondary by name.
pub async fn get_by_name(
    cx: &Context,
    caller: &Caller,
    name: &str,
) -> Result<SecondaryResponse, ServiceError> {
    caller.authorize_action(Action::SecondaryRead)?;

    let secondary = lookup_by_name(cx, name).await?;
    lookup_response(cx, &secondary).await
}

/// List the enabled secondaries, for the DNS plane, which takes no caller.
/// Read per use, so a change takes effect on the next NOTIFY or transfer.
pub async fn list_enabled(cx: &Context) -> Result<Vec<Secondary>, ServiceError> {
    Ok(bindizr_db::secondary::list_all(cx.db())
        .await?
        .into_iter()
        .filter(|secondary| secondary.enabled)
        .collect())
}

/// Look up the API form of a secondary, naming its NOTIFY key.
pub(crate) async fn lookup_response(
    cx: &Context,
    secondary: &Secondary,
) -> Result<SecondaryResponse, ServiceError> {
    let tsig_key = secondary::find_notify_tsig_key(cx, secondary).await?;
    Ok(SecondaryResponse::from_secondary(
        secondary,
        tsig_key.as_ref().map(|tsig_key| tsig_key.name.as_str()),
    ))
}

/// Look up one secondary by name, unchecked.
pub(crate) async fn lookup_by_name(cx: &Context, name: &str) -> Result<Secondary, ServiceError> {
    let name = secondary::normalize_name(name)?;
    bindizr_db::secondary::get_by_name(cx.db(), &name)
        .await?
        .ok_or_else(|| ServiceError::secondary_not_found(&name))
}
