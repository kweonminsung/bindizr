use bindizr_service::authorization::Caller;
use bindizr_service::error::ServiceError;
use bindizr_service::types::{
    AccessLogFilter, AccessLogResponse, AuditLogFilter, AuditLogResponse, PaginatedResponse,
    TransferLogFilter, TransferLogResponse,
};
use bindizr_service::{Context, access, audit, transfer};

use crate::socket::types::DaemonResponse;

/// List the audit log rows the filter selects.
pub(crate) async fn list_audit_logs(
    cx: &Context,
    filter: &AuditLogFilter,
) -> Result<DaemonResponse<PaginatedResponse<AuditLogResponse>>, ServiceError> {
    let response = audit::list(cx, &Caller::socket(), filter).await?;
    Ok(DaemonResponse {
        message: "Audit log retrieved successfully".to_string(),
        data: response,
    })
}

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
