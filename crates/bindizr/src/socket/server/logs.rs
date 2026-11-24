use bindizr_core::model::activity_log::ActivityLog;
use bindizr_service::authorization::Caller;
use bindizr_service::error::ServiceError;
use bindizr_service::types::{
    AccessLogFilter, AccessLogResponse, ActivityLogFilter, PaginatedResponse, TransferLogFilter,
    TransferLogResponse,
};
use bindizr_service::{Context, access, activity, transfer};

use crate::socket::types::DaemonResponse;

/// List the access log rows the filter selects.
pub(crate) async fn list_access_logs(
    cx: &Context,
    filter: &AccessLogFilter,
) -> Result<DaemonResponse<PaginatedResponse<AccessLogResponse>>, ServiceError> {
    let response = access::list(cx, &Caller::socket(), filter).await?;
    Ok(DaemonResponse {
        message: "Access log retrieved successfully".to_string(),
        data: response,
    })
}

/// List the transfer log rows the filter selects.
pub(crate) async fn list_transfer_logs(
    cx: &Context,
    filter: &TransferLogFilter,
) -> Result<DaemonResponse<PaginatedResponse<TransferLogResponse>>, ServiceError> {
    let response = transfer::list(cx, &Caller::socket(), filter).await?;
    Ok(DaemonResponse {
        message: "Transfer log retrieved successfully".to_string(),
        data: response,
    })
}

/// List the activity log rows selected by the filter.
pub(crate) async fn list_activity_logs(
    cx: &Context,
    filter: &ActivityLogFilter,
) -> Result<DaemonResponse<PaginatedResponse<ActivityLog>>, ServiceError> {
    let response = activity::list(cx, &Caller::socket(), filter).await?;
    Ok(DaemonResponse {
        message: "Activity log retrieved successfully".to_string(),
        data: response,
    })
}
