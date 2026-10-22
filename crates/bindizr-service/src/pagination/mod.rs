//! Listing policy: validate query windows, page collections, and assemble metadata.

use bindizr_db::ParseSortError;

use crate::{
    error::ServiceError,
    types::{PaginatedResponse, PaginationResponse},
};

/// Maximum explicitly requested page size. An omitted limit remains unbounded.
const MAX_PAGE_LIMIT: u32 = 1000;

/// Validate an explicit page size; transport defaults belong to the caller.
pub(crate) fn validate_page_limit(limit: Option<u32>) -> Result<(), ServiceError> {
    if let Some(limit) = limit
        && (limit == 0 || limit > MAX_PAGE_LIMIT)
    {
        return Err(ServiceError::invalid_input(format!(
            "limit must be between 1 and {}",
            MAX_PAGE_LIMIT
        )));
    }

    Ok(())
}

/// Parse a listing's sort or order using its query enum, or take the default.
pub(crate) fn parse_setting<T>(value: Option<&str>) -> Result<T, ServiceError>
where
    T: Default + std::str::FromStr<Err = ParseSortError>,
{
    match value {
        None => Ok(T::default()),
        Some(value) => value
            .parse()
            .map_err(|error: ParseSortError| ServiceError::invalid_input(error.to_string())),
    }
}

/// A page already limited and offset at the query layer; an omitted limit
/// reports the whole `total`, saturating at `u32::MAX`.
pub(crate) fn build_paginated_response<T>(
    items: Vec<T>,
    limit: Option<u32>,
    offset: Option<u64>,
    total: u64,
) -> PaginatedResponse<T> {
    PaginatedResponse {
        items,
        pagination: PaginationResponse {
            limit: limit.unwrap_or_else(|| total.min(u64::from(u32::MAX)) as u32),
            offset: offset.unwrap_or(0),
            total,
        },
    }
}

/// Apply a validated window to a collection and build its page metadata.
pub(crate) fn build_page<T>(
    items: Vec<T>,
    limit: Option<u32>,
    offset: Option<u64>,
) -> PaginatedResponse<T> {
    let total = items.len() as u64;
    let start = offset.unwrap_or(0);
    let take = limit.map_or(items.len(), |limit| limit as usize);
    let page = items
        .into_iter()
        .skip(usize::try_from(start).unwrap_or(usize::MAX))
        .take(take)
        .collect();

    build_paginated_response(page, limit, offset, total)
}

#[cfg(test)]
mod tests;
