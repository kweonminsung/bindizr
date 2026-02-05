use crate::api::{
    dto::{CreateKeyRequest, GetKeyResponse, UpdateKeyRequest},
    service::key::KeyService,
};
use axum::{Json, Router, extract::Path, http::StatusCode, response::IntoResponse, routing};
use serde_json::json;

pub struct KeyController;

impl KeyController {
    pub async fn routes() -> Router {
        Router::new()
            .route("/keys", routing::get(Self::get_keys))
            .route("/keys", routing::post(Self::create_key))
            .route("/keys/{name}", routing::get(Self::get_key))
            .route("/keys/{name}", routing::put(Self::update_key))
            .route("/keys/{name}", routing::delete(Self::delete_key))
    }

    async fn get_keys() -> impl IntoResponse {
        match KeyService::get_keys().await {
            Ok(keys) => {
                let response: Vec<GetKeyResponse> =
                    keys.iter().map(GetKeyResponse::from_key).collect();
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn get_key(Path(name): Path<String>) -> impl IntoResponse {
        match KeyService::get_key(&name).await {
            Ok(key) => {
                let response = GetKeyResponse::from_key(&key);
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn create_key(Json(request): Json<CreateKeyRequest>) -> impl IntoResponse {
        match KeyService::create_key(&request).await {
            Ok(key) => {
                let response = GetKeyResponse::from_key(&key);
                (StatusCode::CREATED, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn update_key(
        Path(name): Path<String>,
        Json(request): Json<UpdateKeyRequest>,
    ) -> impl IntoResponse {
        match KeyService::update_key(&name, &request).await {
            Ok(key) => {
                let response = GetKeyResponse::from_key(&key);
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }

    async fn delete_key(Path(name): Path<String>) -> impl IntoResponse {
        match KeyService::delete_key(&name).await {
            Ok(_) => {
                let json_body = json!({ "message": "Key deleted successfully" });
                (StatusCode::OK, Json(json_body)).into_response()
            }
            Err(err) => err.into_response(),
        }
    }
}
