//! Paginated response envelope shared by every listing endpoint.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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
