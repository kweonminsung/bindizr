use bindizr_service::{
    Context, audit,
    authorization::Caller,
    error::ServiceError,
    types::{AuditLogFilter, AuditLogResponse, PaginatedResponse},
};

use crate::socket::types::DaemonResponse;

/// List the audit log rows the filter selects.
pub(crate) async fn list_audit_logs(
    cx: &Context,
    filter: AuditLogFilter,
) -> Result<DaemonResponse<PaginatedResponse<AuditLogResponse>>, ServiceError> {
    let response = audit::list(cx, &Caller::socket(), filter).await?;
    Ok(DaemonResponse {
        message: "Audit log retrieved successfully".to_string(),
        data: response,
    })
}
