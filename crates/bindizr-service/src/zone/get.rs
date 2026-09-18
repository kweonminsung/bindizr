use bindizr_db::repository::{DnssecRecordFilter, LockLevel, RecordFilter, ZoneFilter};

use super::{ZoneService, validation::normalize_zone_name};
use crate::{
    RepositoryTx,
    authorization::Caller,
    error::ServiceError,
    model::{record::Record, zone::Zone, zone_change::ZoneChange},
    repository::RepositoryService,
    types::{
        GetRecordResponse, GetZoneResponse, GetZonesFilter, PaginatedResponse, ZoneDetailResponse,
        normalize_page_limit, parse_setting,
    },
};

impl ZoneService {
    /// The DNS plane's view of a zone: a disabled one is absent rather than
    /// served. The nsupdate apply and the transfer authorization read it.
    pub(crate) async fn find_served_by_name_tx(
        tx: &mut RepositoryTx<'_>,
        zone_name: &str,
        lock_level: LockLevel,
    ) -> Result<Option<Zone>, ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;
        Ok(
            RepositoryService::get_zone_by_name_tx(tx, lookup_name.as_str(), lock_level)
                .await?
                .filter(|zone| zone.enabled),
        )
    }

    /// Fetch a zone by name within the caller's transaction at `lock_level`,
    /// whether or not it is served. The import reads it this way because a
    /// disabled zone still takes records.
    pub(crate) async fn find_by_name_tx(
        tx: &mut RepositoryTx<'_>,
        zone_name: &str,
        lock_level: LockLevel,
    ) -> Result<Option<Zone>, ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;
        RepositoryService::get_zone_by_name_tx(tx, lookup_name.as_str(), lock_level).await
    }

    /// Count journal rows in `(from_serial, to_serial]` for the IXFR size estimate.
    pub async fn count_changes_between_serials(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<u64, ServiceError> {
        RepositoryService::count_zone_changes_between_serials(zone_id, from_serial, to_serial).await
    }

    /// Journal rows in `(from_serial, to_serial]`, ordered by serial then row id.
    pub async fn list_changes_between_serials(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, ServiceError> {
        RepositoryService::list_zone_changes_between_serials(zone_id, from_serial, to_serial).await
    }

    /// Cheap database round-trip (limit-1 zones probe), for health checks.
    pub async fn ping() -> Result<(), ServiceError> {
        RepositoryService::ping().await
    }

    /// The zones the DNS plane serves: the catalog's membership and the NOTIFY
    /// fan-out read it.
    pub async fn list() -> Result<Vec<Zone>, ServiceError> {
        let zones = RepositoryService::list_zones().await.map_err(|e| {
            log::error!("Failed to fetch zones: {}", e);
            ServiceError::internal("Failed to fetch zones")
        })?;
        Ok(zones.into_iter().filter(|zone| zone.enabled).collect())
    }

    /// Every zone, for the unauthenticated metrics endpoint.
    pub async fn count_all() -> Result<u64, ServiceError> {
        RepositoryService::count_zones_by_filter(ZoneFilter::default()).await
    }

    /// Count the zones visible to `caller`.
    pub async fn count(caller: &Caller) -> Result<u64, ServiceError> {
        RepositoryService::count_zones_by_filter(ZoneFilter {
            scope_token_id: caller.scope_token_id(),
            ..ZoneFilter::default()
        })
        .await
    }

    /// List the zones matching `filter` that the caller may see, restricted in
    /// SQL so pagination stays database-side.
    pub async fn list_by_filter(
        caller: &Caller,
        filter: GetZonesFilter,
    ) -> Result<PaginatedResponse<GetZoneResponse>, ServiceError> {
        let scope_token_id = caller.scope_token_id();
        let limit = Some(normalize_page_limit(filter.limit)?);
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
            min_serial: filter.min_serial,
            max_serial: filter.max_serial,
            created_after: filter.created_after,
            created_before: filter.created_before,
            signed: filter.signed,
            enabled: filter.enabled,
            search: filter.search,
            scope_token_id,
            sort: parse_setting(filter.sort.as_deref())?,
            order: parse_setting(filter.order.as_deref())?,
            limit,
            offset,
        };

        let total = RepositoryService::count_zones_by_filter(zone_filter.clone()).await?;
        let zones = RepositoryService::list_zones_by_filter(zone_filter).await?;
        let items = zones.iter().map(GetZoneResponse::from_zone).collect();
        Ok(PaginatedResponse::from_page(items, limit, offset, total))
    }

    /// Fetch a zone by name for `caller`; a zone it cannot see reads as
    /// `NotFound`, so grants cannot be probed.
    pub async fn get_by_name(caller: &Caller, zone_name: &str) -> Result<Zone, ServiceError> {
        let zone = Self::lookup_by_name(zone_name).await?;
        caller.authorize_zone_visible(&zone)?;
        Ok(zone)
    }

    /// Fetch a zone by name, returning `NotFound` if it does not exist. This is
    /// the unchecked lookup for service-internal use; anything reachable from a
    /// front end goes through [`Self::get_by_name`].
    pub(crate) async fn lookup_by_name(zone_name: &str) -> Result<Zone, ServiceError> {
        // Canonical, like the hidden-zone 404s: an echoed spelling would tell them apart.
        let lookup_name = normalize_zone_name(zone_name)?;
        RepositoryService::get_zone_by_name(lookup_name.as_str())
            .await?
            .ok_or_else(|| ServiceError::zone_not_found(lookup_name.as_str()))
    }

    /// Fetch a zone by name for `caller` within the caller's transaction at
    /// `lock_level`; a zone it cannot see reads as `NotFound`, so grants
    /// cannot be probed. Visibility is decided on the row this tx locked, so
    /// a same-name recreation cannot swap the zone in.
    pub(crate) async fn get_visible_by_name_tx(
        tx: &mut RepositoryTx<'_>,
        caller: &Caller,
        zone_name: &str,
        lock_level: LockLevel,
    ) -> Result<Zone, ServiceError> {
        let zone = Self::get_by_name_tx(tx, zone_name, lock_level).await?;
        caller.authorize_zone_visible(&zone)?;
        Ok(zone)
    }

    /// The zone and its records from one snapshot, so they share a serial.
    /// Fetch a zone as the detail payload both front ends answer with,
    /// carrying its records only when they were asked for.
    pub async fn get_detail(
        caller: &Caller,
        zone_name: &str,
        with_records: bool,
    ) -> Result<ZoneDetailResponse, ServiceError> {
        let (zone, records) = if with_records {
            Self::get_with_records(caller, zone_name).await?
        } else {
            (Self::get_by_name(caller, zone_name).await?, vec![])
        };
        Ok(ZoneDetailResponse {
            zone: GetZoneResponse::from_zone(&zone),
            records: records
                .iter()
                .map(|record| GetRecordResponse::from_record_and_zone_name(record, &zone.name))
                .collect(),
        })
    }

    pub(crate) async fn get_with_records(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<(Zone, Vec<Record>), ServiceError> {
        let mut tx = RepositoryService::begin_read_tx("Failed to fetch zone").await?;
        let result = async {
            let zone =
                Self::get_visible_by_name_tx(&mut tx, caller, zone_name, LockLevel::Shared).await?;
            // Narrowed the way `/records` narrows it: a grant that hides a
            // record from the listing must hide it from the zone's detail too.
            let records = RepositoryService::list_records_tx(&mut tx, zone.id, LockLevel::None)
                .await?
                .into_iter()
                .filter(|record| {
                    caller.sees_record(zone.id, &record.name, Some(&record.record_type))
                })
                .collect();
            Ok::<(Zone, Vec<Record>), ServiceError>((zone, records))
        }
        .await;
        RepositoryService::finish_tx(tx, result, "Failed to fetch zone").await
    }

    /// Fetch a zone by name within the caller's transaction at `lock_level`,
    /// returning `NotFound` if it does not exist.
    pub(crate) async fn get_by_name_tx(
        tx: &mut RepositoryTx<'_>,
        zone_name: &str,
        lock_level: LockLevel,
    ) -> Result<Zone, ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;
        RepositoryService::get_zone_by_name_tx(tx, lookup_name.as_str(), lock_level)
            .await?
            .ok_or_else(|| ServiceError::zone_not_found(lookup_name.as_str()))
    }

    /// Count both record planes for the IXFR/AXFR size comparison. These unlocked
    /// counts may drift during a write; they choose the transfer format only.
    pub async fn count_transfer_records(zone_name: &str) -> Result<u64, ServiceError> {
        let records = RepositoryService::count_records_by_filter(RecordFilter {
            zone_name: Some(zone_name.to_string()),
            ..RecordFilter::default()
        })
        .await?;

        let dnssec_records =
            RepositoryService::count_dnssec_records_by_filter(DnssecRecordFilter {
                zone_name: Some(zone_name.to_string()),
                ..DnssecRecordFilter::default()
            })
            .await?;

        Ok(records + dnssec_records)
    }
}
