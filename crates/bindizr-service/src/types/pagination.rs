//! Paginated response envelope shared by every listing endpoint.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Requested pagination window for a listing with no row predicates.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema, IntoParams,
)]
#[serde(deny_unknown_fields)]
pub struct PageRequest {
    /// Items per page; the HTTP API defaults it, the daemon socket does not.
    #[schema(example = 50)]
    #[param(minimum = 1, maximum = 1000)]
    pub limit: Option<u32>,
    #[schema(example = 0)]
    pub offset: Option<u64>,
}

/// A page of items together with its pagination metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub pagination: PaginationResponse,
}

/// Pagination window and total count for a list response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PaginationResponse {
    #[schema(example = 50)]
    pub limit: u32,
    #[schema(example = 0)]
    pub offset: u64,
    #[schema(example = 125)]
    pub total: u64,
}
