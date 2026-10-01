use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    Context, tsig_key,
    types::{
        CreateTsigKeyRequest, DEFAULT_PAGE_LIMIT, ErrorResponse, GetTsigKeyResponse,
        MessageResponse, PageRequest, PaginatedResponse, TsigKeyResponse,
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

/// Build the TSIG key API routes.
pub(crate) fn routes() -> Router<Arc<Context>> {
    Router::new()
        .route("/tsig-keys", routing::get(list_tsig_keys))
        .route("/tsig-keys", routing::post(create_tsig_key))
        .route("/tsig-keys/{name}", routing::get(get_tsig_key))
        .route("/tsig-keys/{name}", routing::delete(delete_tsig_key))
}

/// List all TSIG keys (secrets omitted).
#[utoipa::path(
        get,
        path = "/tsig-keys",
        tag = "TSIG",
        summary = "List all TSIG keys",
        params(PageRequest),
        description = "Lists every TSIG key without its secret. Fetch a single key to read the secret.",
        responses(
            (status = 200, description = "All TSIG keys", body = PaginatedResponse<GetTsigKeyResponse>),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_tsig_keys(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Query(mut page): Query<PageRequest>,
) -> Result<Response, ApiError> {
    page.limit = page.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = tsig_key::list(&cx, &caller, page).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Create a TSIG key, generating a secret unless one is imported.
#[utoipa::path(
        post,
        path = "/tsig-keys",
        tag = "TSIG",
        summary = "Create a TSIG key",
        description = "Creates a TSIG key. When `secret` is omitted a random secret is generated; when provided it must be valid base64 (imports an existing key). The key authenticates into `role_name`, whose grants decide what updates and transfers it may sign. The response includes the secret.",
        request_body = CreateTsigKeyRequest,
        responses(
            (status = 201, description = "TSIG key created successfully", body = TsigKeyResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 409, description = "A TSIG key with the same name already exists", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn create_tsig_key(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateTsigKeyRequest>,
) -> Result<Response, ApiError> {
    let response = tsig_key::create(&cx, &caller, &body).await?;
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

/// Get one TSIG key by name, including its secret.
#[utoipa::path(
        get,
        path = "/tsig-keys/{name}",
        tag = "TSIG",
        summary = "Get a specific TSIG key",
        description = "Returns one TSIG key including its secret.",
        params(
            ("name" = String, Path, description = "The name of the TSIG key.")
        ),
        responses(
            (status = 200, description = "The TSIG key", body = TsigKeyResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "TSIG key not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_tsig_key(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
) -> Result<Response, ApiError> {
    let response = tsig_key::get(&cx, &caller, &params.name).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Delete a TSIG key that signs no secondary's NOTIFY.
#[utoipa::path(
        delete,
        path = "/tsig-keys/{name}",
        tag = "TSIG",
        summary = "Delete a TSIG key",
        description = "Deletes a TSIG key. Refused while it still signs a secondary's NOTIFY.",
        params(
            ("name" = String, Path, description = "The name of the TSIG key.")
        ),
        responses(
            (status = 200, description = "TSIG key deleted successfully", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "TSIG key not found", body = ErrorResponse),
            (status = 409, description = "TSIG key still signs a secondary's NOTIFY", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_tsig_key(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
) -> Result<Response, ApiError> {
    tsig_key::delete(&cx, &caller, &params.name).await?;
    let response = MessageResponse {
        message: "TSIG key deleted successfully".to_string(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}
