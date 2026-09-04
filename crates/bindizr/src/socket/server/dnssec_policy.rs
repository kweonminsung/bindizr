use bindizr_service::{
    authorization::Caller,
    dnssec_policy::DnssecPolicyService,
    error::ServiceError,
    types::{CreateDnssecPolicyRequest, GetDnssecPolicyResponse},
};

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{DaemonResponse, DnssecPolicyNameParams, UpdateDnssecPolicyParams},
};

/// Handle the `DnssecPolicyCreate` command by creating a policy.
pub(crate) async fn create_dnssec_policy(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let request: CreateDnssecPolicyRequest = parse_params(data)?;

    let policy = DnssecPolicyService::create(&Caller::Global, request).await?;

    Ok(DaemonResponse {
        message: "DNSSEC policy created successfully".to_string(),
        data: to_response_data(GetDnssecPolicyResponse::from_policy(&policy))?,
    })
}

/// Handle the `DnssecPolicyList` command by returning every policy.
pub(crate) async fn list_dnssec_policies() -> Result<DaemonResponse, ServiceError> {
    let policies = DnssecPolicyService::list(&Caller::Global).await?;
    let policies: Vec<GetDnssecPolicyResponse> = policies
        .iter()
        .map(GetDnssecPolicyResponse::from_policy)
        .collect();

    Ok(DaemonResponse {
        message: "DNSSEC policies retrieved successfully".to_string(),
        data: to_response_data(policies)?,
    })
}

/// Handle the `DnssecPolicyGet` command by returning one policy.
pub(crate) async fn get_dnssec_policy(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: DnssecPolicyNameParams = parse_params(data)?;

    let policy = DnssecPolicyService::get(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "DNSSEC policy retrieved successfully".to_string(),
        data: to_response_data(GetDnssecPolicyResponse::from_policy(&policy))?,
    })
}

/// Handle the `DnssecPolicyUpdate` command by editing a policy's timing.
pub(crate) async fn update_dnssec_policy(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: UpdateDnssecPolicyParams = parse_params(data)?;

    let policy = DnssecPolicyService::update(&Caller::Global, &params.name, params.request).await?;

    Ok(DaemonResponse {
        message: "DNSSEC policy updated successfully".to_string(),
        data: to_response_data(GetDnssecPolicyResponse::from_policy(&policy))?,
    })
}

/// Handle the `DnssecPolicyDelete` command by deleting an unused policy.
pub(crate) async fn delete_dnssec_policy(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: DnssecPolicyNameParams = parse_params(data)?;

    DnssecPolicyService::delete(&Caller::Global, &params.name).await?;

    Ok(DaemonResponse {
        message: "DNSSEC policy deleted successfully".to_string(),
        data: serde_json::Value::Null,
    })
}
