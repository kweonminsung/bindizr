use bindizr_service::authorization::Caller;
use bindizr_service::error::ServiceError;
use bindizr_service::types::{
    CreateDnssecPolicyRequest, DnssecPolicyResponse, MessageResponse, PageRequest,
    PaginatedResponse, SingleDnssecPolicyResponse, UpdateDnssecPolicyRequest,
};
use bindizr_service::{Context, dnssec_policy};

use crate::socket::types::DaemonResponse;

/// Create DNSSEC policy from the control request.
pub(crate) async fn create_dnssec_policy(
    cx: &Context,
    request: CreateDnssecPolicyRequest,
) -> Result<DaemonResponse<SingleDnssecPolicyResponse>, ServiceError> {
    let policy = dnssec_policy::create(cx, &Caller::socket(), request).await?;

    Ok(DaemonResponse {
        message: "DNSSEC policy created successfully".to_string(),
        data: SingleDnssecPolicyResponse {
            dnssec_policy: DnssecPolicyResponse::from(&policy),
        },
    })
}

/// List the requested DNSSEC policies.
pub(crate) async fn list_dnssec_policies(
    cx: &Context,
    page: PageRequest,
) -> Result<DaemonResponse<PaginatedResponse<DnssecPolicyResponse>>, ServiceError> {
    let response = dnssec_policy::list(cx, &Caller::socket(), page).await?;
    Ok(DaemonResponse {
        message: "DNSSEC policies retrieved successfully".to_string(),
        data: response,
    })
}

/// Get the requested DNSSEC policy.
pub(crate) async fn get_dnssec_policy(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<SingleDnssecPolicyResponse>, ServiceError> {
    let policy = dnssec_policy::get(cx, &Caller::socket(), name).await?;

    Ok(DaemonResponse {
        message: "DNSSEC policy retrieved successfully".to_string(),
        data: SingleDnssecPolicyResponse {
            dnssec_policy: DnssecPolicyResponse::from(&policy),
        },
    })
}

/// Update the requested DNSSEC policy.
pub(crate) async fn update_dnssec_policy(
    cx: &Context,
    name: &str,
    request: UpdateDnssecPolicyRequest,
) -> Result<DaemonResponse<SingleDnssecPolicyResponse>, ServiceError> {
    let policy = dnssec_policy::update(cx, &Caller::socket(), name, request).await?;

    Ok(DaemonResponse {
        message: "DNSSEC policy updated successfully".to_string(),
        data: SingleDnssecPolicyResponse {
            dnssec_policy: DnssecPolicyResponse::from(&policy),
        },
    })
}

/// Delete the requested DNSSEC policy.
pub(crate) async fn delete_dnssec_policy(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    dnssec_policy::delete(cx, &Caller::socket(), name).await?;
    let message = format!("DNSSEC policy '{}' deleted successfully", name);
    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}
