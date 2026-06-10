use crate::types::{PaginatedResponse, Pagination};

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
