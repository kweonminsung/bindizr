//! Paginated response envelope shared by every listing endpoint.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// What an HTTP listing pages at when the request names no limit. The daemon
/// socket applies none: the CLI reads whole tables.
pub const DEFAULT_PAGE_LIMIT: u32 = 50;

/// The query window of a listing that takes no other filter.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, ToSchema, IntoParams)]
#[serde(deny_unknown_fields)]
pub struct PageFilter {
    /// Items per page; the HTTP API defaults it, the daemon socket does not.
    #[schema(example = 50)]
    pub limit: Option<u32>,
    #[schema(example = 0)]
    pub offset: Option<u64>,
}

/// A page of items together with its pagination metadata.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub pagination: Pagination,
}

/// Pagination window and total count for a list response.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct Pagination {
    #[schema(example = 50)]
    pub limit: u32,
    #[schema(example = 0)]
    pub offset: u64,
    #[schema(example = 125)]
    pub total: u64,
}
