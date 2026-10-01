use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    Context, secondary,
    types::{
        CreateSecondaryRequest, DEFAULT_PAGE_LIMIT, ErrorResponse, GetSecondaryResponse,
        GetSecondaryTransfersFilter, MessageResponse, PageRequest, PaginatedResponse,
        SecondaryCheckResponse, SecondaryResponse, SecondaryTransfersResponse,
        UpdateSecondaryRequest,
    },
};

use crate::{
    api::{
        RequestCaller,
        error::{ApiError, Path, Query},
        middleware::body_parser::JsonBody,
    },
    params::NameParams,
};

/// Build the secondary API routes.
pub(crate) fn routes() -> Router<Arc<Context>> {
    Router::new()
        .route("/secondaries", routing::get(list_secondaries))
        .route("/secondaries", routing::post(create_secondary))
        .route("/secondaries/{name}", routing::get(get_secondary))
        .route("/secondaries/{name}", routing::put(update_secondary))
        .route("/secondaries/{name}", routing::delete(delete_secondary))
        .route("/secondaries/{name}/check", routing::post(check_secondary))
        .route(
            "/secondaries/{name}/transfers",
            routing::get(list_secondary_transfers),
        )
}

/// List all secondaries.
#[utoipa::path(
        get,
        path = "/secondaries",
        tag = "Secondary",
        summary = "List all secondaries",
        params(PageRequest),
        description = "Lists every registered secondary, disabled ones included. An enabled secondary receives NOTIFY for every zone, may pull zones unsigned from its address, and is probed for the serial it serves.",
        responses(
            (status = 200, description = "All secondaries", body = PaginatedResponse<GetSecondaryResponse>),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_secondaries(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Query(mut page): Query<PageRequest>,
) -> Result<Response, ApiError> {
    page.limit = page.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = secondary::list(&cx, &caller, page).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Register a secondary.
#[utoipa::path(
        post,
        path = "/secondaries",
        tag = "Secondary",
        summary = "Register a secondary",
        description = "Registers a secondary by name and `host[:port]` address (port 53 when left out). It receives NOTIFY from the next change on and may pull zones unsigned from that address; a hostname is resolved when used. A signed transfer is authorized by its key instead, but NOTIFY still goes only to the registered secondaries. With `notify_key_name`, every NOTIFY to it is signed with that TSIG key and the answer's signature checked.",
        request_body = CreateSecondaryRequest,
        responses(
            (status = 201, description = "Secondary registered successfully", body = SecondaryResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 409, description = "A secondary with the same name or address already exists", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn create_secondary(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateSecondaryRequest>,
) -> Result<Response, ApiError> {
    let secondary = secondary::create(&cx, &caller, &body).await?;
    let response = SecondaryResponse { secondary };
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
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Secondary not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_secondary(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
) -> Result<Response, ApiError> {
    let secondary = secondary::get(&cx, &caller, &params.name).await?;
    let response = SecondaryResponse { secondary };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Change a secondary's address or enabled flag.
#[utoipa::path(
        put,
        path = "/secondaries/{name}",
        tag = "Secondary",
        summary = "Update a secondary",
        description = "Changes the address, the NOTIFY key (empty sends NOTIFY unsigned again), or enables or disables the secondary; an omitted field keeps its value. A disabled secondary receives no NOTIFY, may not transfer unsigned, and is not probed, but stays registered.",
        params(
            ("name" = String, Path, description = "The name of the secondary.")
        ),
        request_body = UpdateSecondaryRequest,
        responses(
            (status = 200, description = "Secondary updated successfully", body = SecondaryResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Secondary not found", body = ErrorResponse),
            (status = 409, description = "Another secondary already has the address", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn update_secondary(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
    JsonBody(body): JsonBody<UpdateSecondaryRequest>,
) -> Result<Response, ApiError> {
    let secondary = secondary::update(&cx, &caller, &params.name, body).await?;
    let response = SecondaryResponse { secondary };
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
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Secondary not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_secondary(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
) -> Result<Response, ApiError> {
    secondary::delete(&cx, &caller, &params.name).await?;
    let response = MessageResponse {
        message: "Secondary deleted successfully".to_string(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Check a secondary.
#[utoipa::path(
        post,
        path = "/secondaries/{name}/check",
        tag = "Secondary",
        summary = "Check a secondary",
        description = "Resolves the secondary's address, asks it for the catalog zone's SOA serial and compares that with the serial Bindizr serves, and sends it a NOTIFY for the catalog zone. A disabled secondary is checked all the same. The NOTIFY is a real one, so the secondary may transfer the catalog as a result.",
        params(
            ("name" = String, Path, description = "The name of the secondary.")
        ),
        responses(
            (status = 200, description = "What the secondary answered", body = SecondaryCheckResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Secondary not found", body = ErrorResponse),
            (status = 500, description = "Internal server error, including Bindizr's own DNS listener not answering", body = ErrorResponse)
        )
)]
pub(crate) async fn check_secondary(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
) -> Result<Response, ApiError> {
    let check = secondary::check(&cx, &caller, &params.name).await?;
    Ok((StatusCode::OK, Json(check)).into_response())
}

/// The transfers Bindizr served a secondary.
#[utoipa::path(
    get,
    path = "/secondaries/{name}/transfers",
    tag = "Secondary",
    summary = "List a secondary's transfers",
    description = "The transfers Bindizr served the secondary's addresses, newest first, with how each zone was last served: AXFR, IXFR as a delta or as the whole zone, or refused and why. Bindizr keeps the latest transfer per zone and address, so each zone appears once.",
    params(
        ("name" = String, Path, description = "The name of the secondary."),
        GetSecondaryTransfersFilter
    ),
    responses(
        (status = 200, description = "The transfers served", body = SecondaryTransfersResponse),
        (status = 400, description = "Invalid query parameters", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
        (status = 404, description = "Secondary not found", body = ErrorResponse)
    )
)]
pub(crate) async fn list_secondary_transfers(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
    Query(query): Query<GetSecondaryTransfersFilter>,
) -> Result<Response, ApiError> {
    let transfers = secondary::list_transfers(&cx, &caller, &params.name, query).await?;
    Ok((StatusCode::OK, Json(transfers)).into_response())
}
