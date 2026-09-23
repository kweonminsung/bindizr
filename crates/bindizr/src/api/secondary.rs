use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    secondary::SecondaryService,
    types::{
        CreateSecondaryRequest, DEFAULT_PAGE_LIMIT, ErrorResponse, GetSecondaryResponse,
        MessageResponse, PageFilter, PaginatedResponse, SecondaryResponse, UpdateSecondaryRequest,
    },
};
use serde::Deserialize;

use crate::api::{
    RequestCaller,
    error::{ApiError, Path, Query},
    middleware::body_parser::JsonBody,
};

pub(crate) struct SecondaryApi;

impl SecondaryApi {
    /// Build the secondary API routes.
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route("/secondaries", routing::get(list_secondaries))
            .route("/secondaries", routing::post(create_secondary))
            .route("/secondaries/{name}", routing::get(get_secondary))
            .route("/secondaries/{name}", routing::put(update_secondary))
            .route("/secondaries/{name}", routing::delete(delete_secondary))
    }
}

#[derive(Deserialize)]
pub(crate) struct SecondaryNameParam {
    name: String,
}

/// List all secondaries.
#[utoipa::path(
        get,
        path = "/secondaries",
        tag = "Secondary",
        summary = "List all secondaries",
        params(PageFilter),
        description = "Lists every registered secondary, disabled ones included. An enabled secondary receives NOTIFY for every zone, may pull zones unsigned from its address, and is probed for the serial it serves.",
        responses(
            (status = 200, description = "All secondaries", body = PaginatedResponse<GetSecondaryResponse>),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_secondaries(
    RequestCaller(caller): RequestCaller,
    Query(mut page): Query<PageFilter>,
) -> Result<Response, ApiError> {
    page.limit = page.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = SecondaryService::list(&caller, page).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Register a secondary.
#[utoipa::path(
        post,
        path = "/secondaries",
        tag = "Secondary",
        summary = "Register a secondary",
        description = "Registers a secondary by name and `host[:port]` address (port 53 when left out). It receives NOTIFY from the next change on and may pull zones unsigned from that address; a hostname is resolved when used. A signed transfer is authorized by its key instead, but NOTIFY still goes only to the registered secondaries.",
        request_body = CreateSecondaryRequest,
        responses(
            (status = 201, description = "Secondary registered successfully", body = SecondaryResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 409, description = "A secondary with the same name or address already exists", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn create_secondary(
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateSecondaryRequest>,
) -> Result<Response, ApiError> {
    let secondary = SecondaryService::create(&caller, &body.name, &body.address).await?;
    let response = SecondaryResponse {
        secondary: GetSecondaryResponse::from_secondary(&secondary),
    };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

/// Get one secondary by name.
#[utoipa::path(
        get,
        path = "/secondaries/{name}",
        tag = "Secondary",
        summary = "Get a secondary",
        params(
            ("name" = String, Path, description = "The name of the secondary.")
        ),
        responses(
            (status = 200, description = "The secondary", body = SecondaryResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Secondary not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_secondary(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<SecondaryNameParam>,
) -> Result<Response, ApiError> {
    let secondary = SecondaryService::get(&caller, &params.name).await?;
    let response = SecondaryResponse {
        secondary: GetSecondaryResponse::from_secondary(&secondary),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Change a secondary's address or enabled flag.
#[utoipa::path(
        put,
        path = "/secondaries/{name}",
        tag = "Secondary",
        summary = "Update a secondary",
        description = "Changes the address, or enables or disables the secondary; an omitted field keeps its value. A disabled secondary receives no NOTIFY, may not transfer unsigned, and is not probed, but stays registered.",
        params(
            ("name" = String, Path, description = "The name of the secondary.")
        ),
        request_body = UpdateSecondaryRequest,
        responses(
            (status = 200, description = "Secondary updated successfully", body = SecondaryResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Secondary not found", body = ErrorResponse),
            (status = 409, description = "Another secondary already has the address", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn update_secondary(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<SecondaryNameParam>,
    JsonBody(body): JsonBody<UpdateSecondaryRequest>,
) -> Result<Response, ApiError> {
    let secondary = SecondaryService::update(&caller, &params.name, body).await?;
    let response = SecondaryResponse {
        secondary: GetSecondaryResponse::from_secondary(&secondary),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Delete a secondary.
#[utoipa::path(
        delete,
        path = "/secondaries/{name}",
        tag = "Secondary",
        summary = "Delete a secondary",
        description = "Forgets the secondary: it receives no further NOTIFY and its unsigned transfers are refused from the next request on.",
        params(
            ("name" = String, Path, description = "The name of the secondary.")
        ),
        responses(
            (status = 200, description = "Secondary deleted successfully", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Secondary not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_secondary(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<SecondaryNameParam>,
) -> Result<Response, ApiError> {
    SecondaryService::delete(&caller, &params.name).await?;
    let response = MessageResponse {
        message: "Secondary deleted successfully".to_string(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}
