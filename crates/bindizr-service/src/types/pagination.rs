//! Paginated response envelope shared by every listing endpoint.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A page of items together with its pagination metadata.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub pagination: Pagination,
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
