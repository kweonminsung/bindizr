use crate::{
    api::{
        dto::{CreateKeyRequest, UpdateKeyRequest},
        error::ApiError,
    },
    database::{
        error::DatabaseError,
        get_key_repository,
        model::key::{Key, KeyAlgorithm, KeyType},
    },
    log_error,
};
use chrono::Utc;

#[derive(Clone)]
pub struct KeyService;

impl KeyService {
    pub async fn get_keys() -> Result<Vec<Key>, ApiError> {
        let key_repository = get_key_repository();

        key_repository.get_all().await.map_err(|e: DatabaseError| {
            log_error!("Failed to fetch keys: {}", e);
            ApiError::InternalServerError("Failed to fetch keys".to_string())
        })
    }

    pub async fn get_key(name: &str) -> Result<Key, ApiError> {
        let key_repository = get_key_repository();

        match key_repository.get_by_name(name).await {
            Ok(Some(key)) => Ok(key),
            Ok(None) => Err(ApiError::NotFound(format!(
                "Key with name '{}' not found",
                name
            ))),
            Err(e) => {
                log_error!("Failed to fetch key: {}", e);
                Err(ApiError::InternalServerError(
                    "Failed to fetch key".to_string(),
                ))
            }
        }
    }

    pub async fn create_key(request: &CreateKeyRequest) -> Result<Key, ApiError> {
        let key_repository = get_key_repository();

        // Check if name already exists
        match key_repository.get_by_name(&request.name).await {
            Ok(Some(_)) => {
                return Err(ApiError::BadRequest(format!(
                    "Key with name '{}' already exists",
                    request.name
                )));
            }
            Ok(None) => {}
            Err(e) => {
                log_error!("Failed to check key name: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to check key name".to_string(),
                ));
            }
        }

        // Parse key type
        let key_type = KeyType::from_str(&request.key_type)
            .map_err(|e| ApiError::BadRequest(format!("Invalid key type: {}", e)))?;

        // Parse key algorithm
        let key_algorithm = KeyAlgorithm::from_str(&request.key_algorithm)
            .map_err(|e| ApiError::BadRequest(format!("Invalid key algorithm: {}", e)))?;

        let key = Key {
            id: 0,
            name: request.name.clone(),
            key_type,
            key_algorithm,
            secret: request.secret.clone(),
            created_at: Utc::now(),
        };

        key_repository.create(key).await.map_err(|e| {
            log_error!("Failed to create key: {}", e);
            ApiError::InternalServerError("Failed to create key".to_string())
        })
    }

    pub async fn update_key(name: &str, request: &UpdateKeyRequest) -> Result<Key, ApiError> {
        let key_repository = get_key_repository();

        // Check if key exists
        let mut key = match key_repository.get_by_name(name).await {
            Ok(Some(key)) => key,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Key with name '{}' not found",
                    name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch key: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch key".to_string(),
                ));
            }
        };

        // If name is being changed, check if new name already exists
        if request.name != key.name {
            match key_repository.get_by_name(&request.name).await {
                Ok(Some(_)) => {
                    return Err(ApiError::BadRequest(format!(
                        "Key with name '{}' already exists",
                        request.name
                    )));
                }
                Ok(None) => {}
                Err(e) => {
                    log_error!("Failed to check key name: {}", e);
                    return Err(ApiError::InternalServerError(
                        "Failed to check key name".to_string(),
                    ));
                }
            }
        }

        // Parse key type
        let key_type = KeyType::from_str(&request.key_type)
            .map_err(|e| ApiError::BadRequest(format!("Invalid key type: {}", e)))?;

        // Parse key algorithm
        let key_algorithm = KeyAlgorithm::from_str(&request.key_algorithm)
            .map_err(|e| ApiError::BadRequest(format!("Invalid key algorithm: {}", e)))?;

        key.name = request.name.clone();
        key.key_type = key_type;
        key.key_algorithm = key_algorithm;
        key.secret = request.secret.clone();

        key_repository.update(key).await.map_err(|e| {
            log_error!("Failed to update key: {}", e);
            ApiError::InternalServerError("Failed to update key".to_string())
        })
    }

    pub async fn delete_key(name: &str) -> Result<(), ApiError> {
        let key_repository = get_key_repository();

        // Check if key exists and get its ID
        let key_id = match key_repository.get_by_name(name).await {
            Ok(Some(key)) => key.id,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Key with name '{}' not found",
                    name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch key: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch key".to_string(),
                ));
            }
        };

        key_repository.delete(key_id).await.map_err(|e| {
            log_error!("Failed to delete key: {}", e);
            ApiError::InternalServerError("Failed to delete key".to_string())
        })
    }
}
