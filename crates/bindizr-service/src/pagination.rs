//! Listing policy: validate query windows, page collections, and assemble metadata.

use bindizr_db::ParseSortError;

use crate::{
    error::ServiceError,
    types::{PaginatedResponse, Pagination},
};

/// Bounds one call to a page rather than a whole table.
const MAX_PAGE_LIMIT: u32 = 1000;

/// The page size to query with, rejecting one past [`MAX_PAGE_LIMIT`].
pub(crate) fn normalize_page_limit(limit: Option<u32>) -> Result<u32, ServiceError> {
    match limit {
        None => Ok(MAX_PAGE_LIMIT),
        Some(limit) if limit == 0 || limit > MAX_PAGE_LIMIT => Err(ServiceError::invalid_input(
            format!("limit must be between 1 and {}", MAX_PAGE_LIMIT),
        )),
        Some(limit) => Ok(limit),
    }
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
            .map_err(|e: ParseSortError| ServiceError::invalid_input(e.to_string())),
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
        pagination: Pagination {
            limit: limit.unwrap_or_else(|| total.min(u64::from(u32::MAX)) as u32),
            offset: offset.unwrap_or(0),
            total,
        },
    }
}

/// Page small management collections in memory, avoiding separate
/// count queries for tokens, keys, policies, and grants.
pub(crate) fn build_page<T>(
    items: Vec<T>,
    limit: Option<u32>,
    offset: Option<u64>,
) -> Result<PaginatedResponse<T>, ServiceError> {
    let total = items.len() as u64;
    let start = offset.unwrap_or(0);
    let take = match limit {
        Some(limit) => normalize_page_limit(Some(limit))? as usize,
        None => items.len(),
    };
    let page = items
        .into_iter()
        .skip(usize::try_from(start).unwrap_or(usize::MAX))
        .take(take)
        .collect();
    Ok(build_paginated_response(page, limit, offset, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that page limit defaults and rejects out of range.
    #[test]
    fn page_limit_defaults_and_rejects_out_of_range() {
        // The cap, not the HTTP default, which the HTTP surface supplies.
        assert_eq!(normalize_page_limit(None).unwrap(), MAX_PAGE_LIMIT);
        assert_eq!(normalize_page_limit(Some(1)).unwrap(), 1);
        assert_eq!(
            normalize_page_limit(Some(MAX_PAGE_LIMIT)).unwrap(),
            MAX_PAGE_LIMIT
        );
        // Zero would page forever without advancing.
        assert!(normalize_page_limit(Some(0)).is_err());
        assert!(normalize_page_limit(Some(MAX_PAGE_LIMIT + 1)).is_err());
    }
}
