use bindizr_db::repository::{LockLevel, ZoneFilter};

use super::{ZoneService, validation::normalize_zone_name};
use crate::{
    RepositoryTx,
    authorization::Caller,
    error::ServiceError,
    log_error,
    model::{dnssec_record::DnssecRecord, record::Record, zone::Zone, zone_change::ZoneChange},
    pagination::paginated_response,
    repository::RepositoryService,
    types::{GetZonesFilter, PaginatedResponse},
};

impl ZoneService {
    /// Look up a zone by name, returning `None` if it does not exist.
    pub async fn find_by_name(zone_name: &str) -> Result<Option<Zone>, ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;
        RepositoryService::get_zone_by_name(lookup_name.as_str()).await
    }

    /// Look up a zone by name within the caller's transaction.
    pub(crate) async fn find_by_name_tx(
        tx: &mut RepositoryTx<'_>,
        zone_name: &str,
        lock_level: LockLevel,
    ) -> Result<Option<Zone>, ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;
        RepositoryService::get_zone_by_name_tx(tx, lookup_name.as_str(), lock_level).await
    }

    /// List the recorded zone changes between two serials, for building an IXFR.
    pub async fn list_journal_between_serials(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, ServiceError> {
        RepositoryService::list_zone_journal_between_serials(zone_id, from_serial, to_serial).await
    }

    /// Cheap database round-trip (limit-1 zones probe), for health checks.
    pub async fn ping() -> Result<(), ServiceError> {
        RepositoryService::ping_zones().await
    }

    /// List all zones.
    pub async fn list() -> Result<Vec<Zone>, ServiceError> {
        RepositoryService::list_zones().await.map_err(|e| {
            log_error!("Failed to fetch zones: {}", e);
            ServiceError::internal("Failed to fetch zones".to_string())
        })
    }

    /// List the zones matching `filter` that the caller may see, restricted in
    /// SQL so pagination stays database-side.
    pub async fn list_by_filter(
        caller: &Caller,
        filter: GetZonesFilter,
    ) -> Result<PaginatedResponse<Zone>, ServiceError> {
        let scope_token_id = caller.scope_token_id();
        let limit = filter.limit;
        let offset = filter.offset;

        let zone_filter = ZoneFilter {
            name: filter.name,
            id: filter.id,
            mname: filter.mname,
            rname: filter.rname,
            default_ttl: filter.default_ttl,
            min_default_ttl: filter.min_default_ttl,
            max_default_ttl: filter.max_default_ttl,
            serial: filter.serial,
            search: filter.search,
            scope_token_id,
            limit,
            offset,
        };

        let total = RepositoryService::count_zones_by_filter(zone_filter.clone()).await?;
        let zones = RepositoryService::list_zones_by_filter(zone_filter).await?;
        Ok(paginated_response(zones, limit, offset, total))
    }

    /// Fetch a zone by name for `caller`; a zone it cannot see reads as
    /// `NotFound`, so grants cannot be probed.
    pub async fn get_by_name(caller: &Caller, zone_name: &str) -> Result<Zone, ServiceError> {
        let zone = Self::lookup_by_name(zone_name).await?;
        caller.ensure_zone_visible(&zone)?;
        Ok(zone)
    }

    /// Fetch a zone by name, returning `NotFound` if it does not exist. This is
    /// the unchecked lookup for service-internal use; anything reachable from a
    /// front end goes through [`Self::get_by_name`].
    pub(crate) async fn lookup_by_name(zone_name: &str) -> Result<Zone, ServiceError> {
        Self::find_by_name(zone_name)
            .await?
            .ok_or_else(|| ServiceError::zone_not_found(zone_name))
    }

    /// Fetch a zone by name within the caller's transaction at `lock_level`,
    /// returning `NotFound` if it does not exist.
    pub(crate) async fn get_by_name_tx(
        tx: &mut RepositoryTx<'_>,
        zone_name: &str,
        lock_level: LockLevel,
    ) -> Result<Zone, ServiceError> {
        Self::find_by_name_tx(tx, zone_name, lock_level)
            .await?
            .ok_or_else(|| ServiceError::zone_not_found(zone_name))
    }
    /// A zone row and both record planes read under one shared zone lock, so
    /// a transfer never serves records and signatures from different serials.
    /// Takes no caller: DNS-plane reads are authorized by the transfer ACL.
    pub async fn transfer_content(
        zone_id: i32,
    ) -> Result<Option<(Zone, Vec<Record>, Vec<DnssecRecord>)>, ServiceError> {
        let mut tx = RepositoryService::begin_read_tx("failed to load transfer content").await?;
        let result = async {
            let Some(zone) =
                RepositoryService::get_zone_tx(&mut tx, zone_id, LockLevel::Shared).await?
            else {
                return Ok(None);
            };
            let records =
                RepositoryService::list_records_tx(&mut tx, zone.id, LockLevel::None).await?;
            let dnssec_records =
                RepositoryService::list_dnssec_records_tx(&mut tx, zone.id, LockLevel::None)
                    .await?;
            Ok(Some((zone, records, dnssec_records)))
        }
        .await;
        RepositoryService::finish_tx(tx, result, "failed to load transfer content").await
    }
}
