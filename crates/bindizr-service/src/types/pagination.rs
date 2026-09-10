//! Paginated response envelope shared by every listing endpoint.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::ServiceError;

/// What an HTTP listing pages at when the request names no limit. The daemon
/// socket applies none: the CLI reads whole tables.
pub const DEFAULT_PAGE_LIMIT: u32 = 50;

/// Bounds one call to a page rather than a whole table.
pub(crate) const MAX_PAGE_LIMIT: u32 = 1000;

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

/// A page of items together with its pagination metadata.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub pagination: Pagination,
}

impl<T> PaginatedResponse<T> {
    /// A page already limited and offset at the query layer; an omitted limit
    /// reports the whole `total`, saturating at `u32::MAX`.
    pub(crate) fn from_page(
        items: Vec<T>,
        limit: Option<u32>,
        offset: Option<u64>,
        total: u64,
    ) -> Self {
        PaginatedResponse {
            items,
            pagination: Pagination {
                limit: limit.unwrap_or_else(|| total.min(u64::from(u32::MAX)) as u32),
                offset: offset.unwrap_or(0),
                total,
            },
        }
    }
}

/// Pagination window and total count for a list response.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct Pagination {
    #[schema(example = 50)]
    pub limit: u32,
    #[schema(example = 0)]
    pub offset: u64,
    #[schema(example = 125)]
    pub total: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

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
