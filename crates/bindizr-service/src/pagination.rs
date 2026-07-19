//! In-memory pagination of list responses.

use crate::types::{PaginatedResponse, Pagination};

/// Assemble a response for items already limited/offset at the query layer,
/// with `total` coming from a separate count.
pub(crate) fn paginated_response<T>(
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

pub(crate) fn paginate_items<T>(
    items: Vec<T>,
    limit: Option<u32>,
    offset: Option<u64>,
) -> PaginatedResponse<T> {
    let total = items.len() as u64;
    let offset = offset.unwrap_or(0);
    let limit = limit.unwrap_or_else(|| total.min(u64::from(u32::MAX)) as u32);

    let paginated_items = items
        .into_iter()
        .skip(usize::try_from(offset).unwrap_or(usize::MAX))
        .take(limit as usize)
        .collect();

    PaginatedResponse {
        items: paginated_items,
        pagination: Pagination {
            limit,
            offset,
            total,
        },
    }
}
