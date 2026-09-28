use bindizr_service::{
    Context,
    authorization::Caller,
    dnssec_policy,
    error::ServiceError,
    types::{
        CreateDnssecPolicyRequest, DnssecPolicyResponse, GetDnssecPolicyResponse, MessageResponse,
        PageFilter,
    },
};

use crate::{
    params::NameParams,
    socket::{
        server::{parse_params, to_response_data},
        types::{DaemonResponse, UpdateDnssecPolicyParams},
    },
};

/// Create DNSSEC policy from the control request.
pub(crate) async fn create_dnssec_policy(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let request: CreateDnssecPolicyRequest = parse_params(data)?;

    let policy = dnssec_policy::create(cx, &Caller::Global, request).await?;

    Ok(DaemonResponse {
        message: "DNSSEC policy created successfully".to_string(),
        data: to_response_data(DnssecPolicyResponse {
            dnssec_policy: GetDnssecPolicyResponse::from_policy(&policy),
        })?,
    })
}

/// List the requested DNSSEC policies.
pub(crate) async fn list_dnssec_policies(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let page: PageFilter = parse_params(data)?;

    let response = dnssec_policy::list(cx, &Caller::Global, page).await?;

    Ok(DaemonResponse {
        message: "DNSSEC policies retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// Get the requested DNSSEC policy.
pub(crate) async fn get_dnssec_policy(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: NameParams = parse_params(data)?;

    let policy = dnssec_policy::get(cx, &Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "DNSSEC policy retrieved successfully".to_string(),
        data: to_response_data(DnssecPolicyResponse {
            dnssec_policy: GetDnssecPolicyResponse::from_policy(&policy),
        })?,
    })
}

/// Update the requested DNSSEC policy.
pub(crate) async fn update_dnssec_policy(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: UpdateDnssecPolicyParams = parse_params(data)?;

    let policy = dnssec_policy::update(cx, &Caller::Global, &params.name, params.request).await?;

    Ok(DaemonResponse {
        message: "DNSSEC policy updated successfully".to_string(),
        data: to_response_data(DnssecPolicyResponse {
            dnssec_policy: GetDnssecPolicyResponse::from_policy(&policy),
        })?,
    })
}

/// Delete the requested DNSSEC policy.
pub(crate) async fn delete_dnssec_policy(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: NameParams = parse_params(data)?;

    dnssec_policy::delete(cx, &Caller::Global, &params.name).await?;

    let message = format!("DNSSEC policy '{}' deleted successfully", params.name);
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}
