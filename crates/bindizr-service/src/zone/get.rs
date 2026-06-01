use crate::{
    RepositoryTx,
    error::ServiceError,
    log_error,
    model::{zone::Zone, zone_change::ZoneChange},
    repository::RepositoryService,
    types::GetZonesFilter,
};

use super::ZoneService;

impl ZoneService {
    pub async fn find(zone_name: &str) -> Result<Option<Zone>, ServiceError> {
        RepositoryService::get_zone_by_name(zone_name).await
    }

    pub async fn find_tx(
        tx: &mut RepositoryTx<'_>,
        zone_name: &str,
    ) -> Result<Option<Zone>, ServiceError> {
        RepositoryService::get_zone_by_name_tx(tx, zone_name).await
    }

    pub async fn find_by_id(zone_id: i32) -> Result<Option<Zone>, ServiceError> {
        RepositoryService::get_zone_by_id(zone_id).await
    }

    pub async fn get_changes_between_serials(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, ServiceError> {
        RepositoryService::get_zone_changes_between_serials(zone_id, from_serial, to_serial).await
    }

    pub async fn list() -> Result<Vec<Zone>, ServiceError> {
        RepositoryService::get_all_zones().await.map_err(|e| {
            log_error!("Failed to fetch zones: {}", e);
            ServiceError::Internal("Failed to fetch zones".to_string())
        })
    }

    pub async fn list_filtered(filter: GetZonesFilter) -> Result<Vec<Zone>, ServiceError> {
        let zones = Self::list().await?;
        Ok(zones
            .into_iter()
            .filter(|zone| zone_matches_filter(zone, &filter))
            .collect())
    }

    pub async fn get_by_name(zone_name: &str) -> Result<Zone, ServiceError> {
        match RepositoryService::get_zone_by_name(zone_name).await {
            Ok(Some(zone)) => Ok(zone),
            Ok(None) => Err(ServiceError::NotFound(format!(
                "Zone with name '{}' not found",
                zone_name
            ))),
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                Err(ServiceError::Internal("Failed to fetch zone".to_string()))
            }
        }
    }
}

fn zone_matches_filter(zone: &Zone, filter: &GetZonesFilter) -> bool {
    matches_dns_string(&zone.name, filter.name.as_deref())
        && filter.id.is_none_or(|id| zone.id == id)
        && matches_dns_string(&zone.primary_ns, filter.primary_ns.as_deref())
        && matches_string(&zone.admin_email, filter.admin_email.as_deref())
        && filter.ttl.is_none_or(|ttl| zone.ttl == ttl)
        && filter.min_ttl.is_none_or(|min_ttl| zone.ttl >= min_ttl)
        && filter.max_ttl.is_none_or(|max_ttl| zone.ttl <= max_ttl)
        && filter.serial.is_none_or(|serial| zone.serial == serial)
        && matches_zone_search(zone, filter.search.as_deref())
}

fn matches_zone_search(zone: &Zone, search: Option<&str>) -> bool {
    search.is_none_or(|search| {
        let search = search.trim().to_ascii_lowercase();
        !search.is_empty()
            && [
                zone.name.as_str(),
                zone.primary_ns.as_str(),
                zone.admin_email.as_str(),
            ]
            .iter()
            .any(|value| value.to_ascii_lowercase().contains(&search))
    })
}

fn matches_string(actual: &str, expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| actual.eq_ignore_ascii_case(expected.trim()))
}

fn matches_dns_string(actual: &str, expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| to_fqdn_lower(actual) == to_fqdn_lower(expected))
}

fn to_fqdn_lower(value: &str) -> String {
    format!(
        "{}.",
        value.trim().trim_end_matches('.').to_ascii_lowercase()
    )
}
