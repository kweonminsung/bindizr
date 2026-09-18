use bindizr_service::{
    authorization::Caller,
    dnssec_policy::DnssecPolicyService,
    error::ServiceError,
    types::{CreateDnssecPolicyRequest, DnssecPolicyResponse, GetDnssecPolicyResponse, PageFilter},
};

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{DaemonResponse, DnssecPolicyNameParams, UpdateDnssecPolicyParams},
};

/// Create DNSSEC policy from the control request.
pub(crate) async fn create_dnssec_policy(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let request: CreateDnssecPolicyRequest = parse_params(data)?;

    let policy = DnssecPolicyService::create(&Caller::Global, request).await?;

    Ok(DaemonResponse {
        message: "DNSSEC policy created successfully".to_string(),
        data: to_response_data(DnssecPolicyResponse {
            dnssec_policy: GetDnssecPolicyResponse::from_policy(&policy),
        })?,
    })
}

/// List the requested DNSSEC policies.
pub(crate) async fn list_dnssec_policies(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let page: PageFilter = parse_params(data)?;

    let response = DnssecPolicyService::list(&Caller::Global, page).await?;

    Ok(DaemonResponse {
        message: "DNSSEC policies retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// Get the requested DNSSEC policy.
pub(crate) async fn get_dnssec_policy(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: DnssecPolicyNameParams = parse_params(data)?;

    let policy = DnssecPolicyService::get(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "DNSSEC policy retrieved successfully".to_string(),
        data: to_response_data(DnssecPolicyResponse {
            dnssec_policy: GetDnssecPolicyResponse::from_policy(&policy),
        })?,
    })
}

/// Update the requested DNSSEC policy.
pub(crate) async fn update_dnssec_policy(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: UpdateDnssecPolicyParams = parse_params(data)?;

    let policy = DnssecPolicyService::update(&Caller::Global, &params.name, params.request).await?;

    Ok(DaemonResponse {
        message: "DNSSEC policy updated successfully".to_string(),
        data: to_response_data(DnssecPolicyResponse {
            dnssec_policy: GetDnssecPolicyResponse::from_policy(&policy),
        })?,
    })
}

/// Delete the requested DNSSEC policy.
pub(crate) async fn delete_dnssec_policy(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: DnssecPolicyNameParams = parse_params(data)?;

    DnssecPolicyService::delete(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: format!("DNSSEC policy '{}' deleted successfully", params.name),
        data: serde_json::Value::Null,
    })
}
