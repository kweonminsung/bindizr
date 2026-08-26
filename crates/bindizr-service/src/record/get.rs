use bindizr_core::dns::name::{OwnerName, ZoneName};
use bindizr_db::repository::{DnssecRecordFilter, LockLevel, RecordFilter};

use super::{ListedRecord, RecordService};
use crate::{
    RepositoryTx,
    authorization::Caller,
    error::ServiceError,
    log_error,
    model::{
        dnssec_record::DnssecRecordType,
        record::{Record, RecordType, RecordWithZone},
    },
    pagination::paginated_response,
    repository::RepositoryService,
    types::{GetRecordsFilter, PaginatedResponse},
    zone::{ZoneService, validation::normalize_zone_name},
};

/// Resolve a record_type filter to its plane — at most one side is `Some`: a
/// user type, or a derived DNSSEC type when the signed view is requested.
fn parse_type_filter(
    value: Option<&str>,
    signed: bool,
) -> Result<(Option<RecordType>, Option<DnssecRecordType>), ServiceError> {
    let Some(value) = value else {
        return Ok((None, None));
    };
    match value.parse::<RecordType>() {
        Ok(record_type) => Ok((Some(record_type), None)),
        Err(err) => {
            if signed && let Ok(record_type) = value.to_uppercase().parse::<DnssecRecordType>() {
                return Ok((None, Some(record_type)));
            }
            Err(ServiceError::invalid_input(err))
        }
    }
}

impl RecordService {
    /// List all records in a zone by zone id, within the caller's transaction.
    pub(crate) async fn list_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<Record>, ServiceError> {
        RepositoryService::list_records_tx(tx, zone_id, lock_level).await
    }

    /// List a zone's records for `caller`; a zone it cannot see reads as
    /// `NotFound`.
    pub async fn list_in_zone(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<Vec<Record>, ServiceError> {
        let zone = ZoneService::get_by_name(caller, zone_name).await?;
        RepositoryService::list_records(zone.id).await.map_err(|e| {
            log_error!("Failed to fetch records for zone {}: {}", zone_name, e);
            ServiceError::internal(format!("Failed to fetch records for zone {}", zone_name))
        })
    }

    /// Count the records visible to `caller`.
    pub async fn count(caller: &Caller) -> Result<u64, ServiceError> {
        RepositoryService::count_records_by_filter(RecordFilter {
            scope_token_id: caller.scope_token_id(),
            ..RecordFilter::default()
        })
        .await
    }

    /// List records with their zone name matching `filter`, restricted to the
    /// caller's visible zones in SQL so pagination stays database-side. A
    /// filter naming an unknown or invisible zone reads as an empty page.
    /// With `signed`, the derived DNSSEC plane pages after the user records;
    /// value, search, and priority filters keep the listing user-plane only.
    pub async fn list_with_zone_by_filter(
        caller: &Caller,
        filter: GetRecordsFilter,
    ) -> Result<PaginatedResponse<ListedRecord>, ServiceError> {
        let scope_token_id = caller.scope_token_id();
        let zone_name = filter
            .zone_name
            .as_deref()
            .map(normalize_zone_name)
            .transpose()?;
        let limit = filter.limit;
        let offset = filter.offset;
        let signed = filter.signed.unwrap_or(false);

        // Scoped callers read unknown and invisible zones alike as empty
        // pages, so skip the 404 probe.
        if let Some(name) = zone_name.as_ref()
            && scope_token_id.is_none()
        {
            ZoneService::lookup_by_name(name.as_str()).await?;
        }

        let name = to_record_name_filter(filter.name, zone_name.as_ref());
        let (user_type, derived_type) = parse_type_filter(filter.record_type.as_deref(), signed)?;

        let user_plane = derived_type.is_none();
        // Derived rows carry no value, priority, or search text, so those
        // filters leave only the user plane in the listing.
        let derived_plane = signed
            && user_type.is_none()
            && filter.value.is_none()
            && filter.search.is_none()
            && filter.priority.is_none()
            && filter.min_priority.is_none()
            && filter.max_priority.is_none();

        let zone_name = zone_name.map(|name| name.to_string());
        let record_filter = RecordFilter {
            zone_name: zone_name.clone(),
            name: name.clone(),
            record_type: user_type,
            value: filter.value,
            ttl: filter.ttl,
            min_ttl: filter.min_ttl,
            max_ttl: filter.max_ttl,
            priority: filter.priority,
            min_priority: filter.min_priority,
            max_priority: filter.max_priority,
            search: filter.search,
            scope_token_id,
            limit,
            offset,
        };
        let derived_filter = DnssecRecordFilter {
            zone_name,
            name,
            record_type: derived_type.map(|record_type| record_type.wire_type() as i32),
            ttl: filter.ttl,
            min_ttl: filter.min_ttl,
            max_ttl: filter.max_ttl,
            scope_token_id,
            limit: None,
            offset: None,
        };

        let user_total = if user_plane {
            RepositoryService::count_records_by_filter(record_filter.clone()).await?
        } else {
            0
        };
        let derived_total = if derived_plane {
            RepositoryService::count_dnssec_records_by_filter(derived_filter.clone()).await?
        } else {
            0
        };

        let start = offset.unwrap_or(0);
        let mut items: Vec<ListedRecord> = Vec::new();
        if user_plane && start < user_total {
            items.extend(
                RepositoryService::list_records_by_filter_with_zone(record_filter)
                    .await?
                    .into_iter()
                    .map(ListedRecord::User),
            );
        }
        // The derived plane pages after the user plane: it starts where the
        // window passed the user rows and fills what the limit still holds.
        let remaining = limit.map(|limit| limit.saturating_sub(items.len() as u32));
        if derived_plane && remaining != Some(0) {
            items.extend(
                RepositoryService::list_dnssec_records_by_filter_with_zone(DnssecRecordFilter {
                    limit: remaining,
                    offset: Some(start.saturating_sub(user_total)),
                    ..derived_filter
                })
                .await?
                .into_iter()
                .map(ListedRecord::Derived),
            );
        }

        Ok(paginated_response(
            items,
            limit,
            offset,
            user_total + derived_total,
        ))
    }

    /// Fetch a record with its zone name by id. A record in a zone the caller
    /// cannot see reads as `NotFound`, so ids cannot be probed.
    pub async fn get_with_zone(
        caller: &Caller,
        record_id: i32,
    ) -> Result<RecordWithZone, ServiceError> {
        let record = match RepositoryService::get_record_with_zone(record_id).await {
            Ok(Some(record)) => record,
            Ok(None) => return Err(ServiceError::record_not_found(record_id)),
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                return Err(ServiceError::internal("Failed to fetch record"));
            }
        };

        if !caller.zone_visible(record.zone_id) {
            return Err(ServiceError::record_not_found(record_id));
        }
        Ok(record)
    }
}

fn to_record_name_filter(name: Option<String>, zone_name: Option<&ZoneName>) -> Option<String> {
    name.and_then(|name| {
        let trimmed = name.trim();
        // An empty value is no filter. Left to fall through it would spell the
        // apex, which rows hold as the empty string, and match every apex row.
        if trimmed.is_empty() {
            return None;
        }
        let Some(zone) = zone_name else {
            // No zone to build an FQDN against, so the apex can only be matched
            // by the sentinel rows hold it as.
            if trimmed == OwnerName::APEX {
                return Some(OwnerName::apex().to_stored());
            }
            return Some(trimmed.to_string());
        };

        // The query compares the filter against both the stored owner and the
        // FQDN it builds from it, so spell it the way rows do. Anything that is
        // not a name passes through to match literally.
        if let Ok(owner) = OwnerName::parse_absolute_in_zone(trimmed, zone) {
            return Some(owner.to_fqdn(zone));
        }
        Some(match OwnerName::parse_in_zone(trimmed, zone) {
            Ok(owner) => owner.to_stored(),
            Err(_) => trimmed.to_string(),
        })
    })
}
