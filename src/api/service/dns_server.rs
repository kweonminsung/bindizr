use crate::{
    api::{
        dto::{CreateDnsServerRequest, UpdateDnsServerRequest},
        error::ApiError,
    },
    database::{error::DatabaseError, get_dns_server_repository, model::dns_server::DnsServer},
    log_error,
};
use chrono::Utc;
use std::net::IpAddr;

#[derive(Clone)]
pub struct DnsServerService;

impl DnsServerService {
    /// Get all DNS servers
    pub async fn get_dns_servers() -> Result<Vec<DnsServer>, ApiError> {
        let dns_server_repository = get_dns_server_repository();

        dns_server_repository
            .get_all()
            .await
            .map_err(|e: DatabaseError| {
                log_error!("Failed to fetch DNS servers: {}", e);
                ApiError::InternalServerError("Failed to fetch DNS servers".to_string())
            })
    }

    /// Get a DNS server by ID
    pub async fn get_dns_server(id: i32) -> Result<DnsServer, ApiError> {
        let dns_server_repository = get_dns_server_repository();

        match dns_server_repository.get_by_id(id).await {
            Ok(Some(dns_server)) => Ok(dns_server),
            Ok(None) => Err(ApiError::NotFound(format!(
                "DNS server with id {} not found",
                id
            ))),
            Err(e) => {
                log_error!("Failed to fetch DNS server: {}", e);
                Err(ApiError::InternalServerError(
                    "Failed to fetch DNS server".to_string(),
                ))
            }
        }
    }

    /// Create a new DNS server
    pub async fn create_dns_server(
        create_request: &CreateDnsServerRequest,
    ) -> Result<DnsServer, ApiError> {
        let dns_server_repository = get_dns_server_repository();

        // Validate IP address
        if create_request.ip_address.parse::<IpAddr>().is_err() {
            return Err(ApiError::BadRequest(format!(
                "Invalid IP address: {}",
                create_request.ip_address
            )));
        }

        // Validate port
        if !(1..=65535).contains(&create_request.port) {
            return Err(ApiError::BadRequest(format!(
                "Invalid port number: {}. Must be between 1 and 65535",
                create_request.port
            )));
        }

        let new_dns_server = DnsServer {
            id: 0, // Will be set by database
            ip_address: create_request.ip_address.clone(),
            port: create_request.port,
            created_at: Utc::now(),
        };

        dns_server_repository
            .create(new_dns_server)
            .await
            .map_err(|e| {
                log_error!("Failed to create DNS server: {}", e);
                // Check for unique constraint violation
                if e.to_string().contains("UNIQUE") || e.to_string().contains("unique") {
                    ApiError::BadRequest(format!(
                        "DNS server with IP address {} already exists",
                        create_request.ip_address
                    ))
                } else {
                    ApiError::InternalServerError("Failed to create DNS server".to_string())
                }
            })
    }

    /// Update an existing DNS server
    pub async fn update_dns_server(
        id: i32,
        update_request: &UpdateDnsServerRequest,
    ) -> Result<DnsServer, ApiError> {
        let dns_server_repository = get_dns_server_repository();

        // Get existing DNS server
        let mut dns_server = match dns_server_repository.get_by_id(id).await {
            Ok(Some(server)) => server,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "DNS server with id {} not found",
                    id
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch DNS server: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch DNS server".to_string(),
                ));
            }
        };

        // Update fields if provided
        if let Some(ref ip_address) = update_request.ip_address {
            // Validate IP address
            if ip_address.parse::<IpAddr>().is_err() {
                return Err(ApiError::BadRequest(format!(
                    "Invalid IP address: {}",
                    ip_address
                )));
            }
            dns_server.ip_address = ip_address.clone();
        }

        if let Some(port) = update_request.port {
            // Validate port
            if !(1..=65535).contains(&port) {
                return Err(ApiError::BadRequest(format!(
                    "Invalid port number: {}. Must be between 1 and 65535",
                    port
                )));
            }
            dns_server.port = port;
        }

        dns_server_repository.update(dns_server).await.map_err(|e| {
            log_error!("Failed to update DNS server: {}", e);
            // Check for unique constraint violation
            if e.to_string().contains("UNIQUE") || e.to_string().contains("unique") {
                ApiError::BadRequest("DNS server with this IP address already exists".to_string())
            } else {
                ApiError::InternalServerError("Failed to update DNS server".to_string())
            }
        })
    }

    /// Delete a DNS server
    pub async fn delete_dns_server(id: i32) -> Result<(), ApiError> {
        let dns_server_repository = get_dns_server_repository();

        // Check if DNS server exists
        match dns_server_repository.get_by_id(id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "DNS server with id {} not found",
                    id
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch DNS server: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch DNS server".to_string(),
                ));
            }
        }

        dns_server_repository.delete(id).await.map_err(|e| {
            log_error!("Failed to delete DNS server: {}", e);
            ApiError::InternalServerError("Failed to delete DNS server".to_string())
        })
    }
}
