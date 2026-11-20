use bindizr_core::dns::name::OwnerName;
use bindizr_core::model::record::{Record, RecordId, RecordType};
use bindizr_core::model::role_grant::Action;
use bindizr_core::model::zone::{Zone, ZoneId};
use chrono::Utc;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::types::{CreateZoneRequest, WriteZoneResponse, ZoneResponse};
use crate::zone::validation;
use crate::{Context, Transaction, notify, serial, text, transaction, ttl, zone};

/// Create a zone and NOTIFY the catalog; add an ordinary apex NS naming MNAME
/// unless opted out. Additional NS records are caller-managed.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    request: &CreateZoneRequest,
) -> Result<WriteZoneResponse, ServiceError> {
    caller.authorize_action(Action::ZoneCreate)?;

    // Parent/child zones are allowed; only the same normalized zone name is rejected.
    // Names are stored normalized, so an exact lookup is enough to detect a collision.
    let candidate = prepare_create(cx, request)?;
    let zone_name = &candidate.name;

    match bindizr_db::zone::get_by_name(cx.db(), zone_name).await {
        Ok(Some(_)) => {
            return Err(ServiceError::zone_conflict(format!(
                "zone with name '{zone_name}' already exists"
            )));
        }
        Ok(None) => {}
        Err(error) => {
            return Err(ServiceError::internal_with_source(
                "failed to create zone",
                error,
            ));
        }
    }

    let mut tx = transaction::begin_tx(cx, "failed to create zone").await?;

    let apply_result: Result<_, ServiceError> = async {
        let caller = &caller.reauthenticate_tx(&mut tx).await?;
        caller.authorize_action(Action::ZoneCreate)?;

        // The NS type owns its row form, so the seeded value is encoded as any NS is.
        let apex_ns_value = request
            .apex_ns
            .then(|| RecordType::Ns.encoded_value(&candidate.mname, None))
            .transpose()
            .map_err(ServiceError::invalid_record_value)?;

        if request.dry_run {
            return Ok(candidate);
        }

        let created_zone = create_tx(&mut tx, candidate).await?;

        if let Some(apex_ns_value) = apex_ns_value {
            let apex_ns = Record {
                id: RecordId::UNWRITTEN,
                name: OwnerName::apex(),
                record_type: RecordType::Ns,
                value: apex_ns_value,
                ttl: created_zone.default_ttl,
                priority: None,
                zone_id: created_zone.id,
                created_at: Utc::now(),
            };

            bindizr_db::record::create_many_tx(&mut tx, &[apex_ns]).await?;
        }

        zone::save_version_tx(
            &mut tx,
            &created_zone,
            created_zone.serial,
            caller.change_origin(),
        )
        .await?;

        Ok(created_zone)
    }
    .await;

    let created_zone = transaction::finish_tx(tx, apply_result, "failed to create zone").await?;

    log::info!(
        "event=zone_create zone={} mname={} serial={} zone_id={} dry_run={}",
        created_zone.name,
        created_zone.mname,
        created_zone.serial,
        created_zone.id,
        request.dry_run
    );

    // Send catalog NOTIFY so secondaries pick up the new zone
    let config = cx.config();

    if !request.dry_run {
        cx.metrics().track_serial_bumps(1);
        if created_zone.enabled {
            notify::notify_after_update(cx, &config.dns.catalog_zone_name).await;
        }
    }

    Ok(WriteZoneResponse {
        applied: !request.dry_run,
        dry_run: request.dry_run,
        zone: ZoneResponse::from(&created_zone),
    })
}

/// Resolve creation defaults once, before opening the transaction.
fn prepare_create(cx: &Context, request: &CreateZoneRequest) -> Result<Zone, ServiceError> {
    let zone_name = validation::normalize_name(&request.name)?;
    validation::reject_catalog_zone_name(cx, &zone_name)?;
    let defaults = &cx.config().dns.zone_defaults;
    let soa = validation::normalize_soa(
        &request.mname,
        &request.rname,
        request.default_ttl.unwrap_or(i64::from(defaults.ttl)),
    )?;

    Ok(Zone {
        id: ZoneId::UNWRITTEN,
        name: zone_name,
        mname: soa.mname,
        rname: soa.rname,
        dnssec_policy_id: None,
        parent_ns_addrs: None,
        enabled: request.apex_ns,
        description: text::normalize_description(
            request.description.as_deref(),
            ServiceError::invalid_zone_field,
        )?,
        default_ttl: soa.ttl,
        serial: request
            .serial
            .unwrap_or_else(|| serial::generate_serial(None)),
        refresh: ttl::normalize_soa_interval(request.refresh, defaults.refresh, "refresh")?,
        retry: ttl::normalize_soa_interval(request.retry, defaults.retry, "retry")?,
        expire: ttl::normalize_soa_interval(request.expire, defaults.expire, "expire")?,
        minimum_ttl: ttl::normalize_minimum_ttl(request.minimum_ttl, defaults.minimum_ttl)?,
        created_at: Utc::now(),
    })
}

/// Insert a prepared zone; the caller owns authorization, records and versioning.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_>,
    candidate: Zone,
) -> Result<Zone, ServiceError> {
    let zone_name = candidate.name.clone();
    bindizr_db::zone::create_tx(tx, candidate)
        .await
        .map_err(|error| {
            if error.is_unique_violation() {
                ServiceError::zone_conflict(format!("zone with name '{zone_name}' already exists"))
            } else {
                ServiceError::internal_with_source("failed to create zone", error)
            }
        })
}

#[cfg(test)]
mod tests {
    use bindizr_core::config::Config;
    use bindizr_core::metrics::Metrics;
    use bindizr_db::Db;
    use bindizr_db::record::RecordFilter;
    use tokio::sync::{mpsc, watch};

    use super::*;

    /// Verify that the seeded apex NS is stored as any NS is, a trailing-dot
    /// FQDN, not the mname's bare zone-name spelling.
    #[tokio::test]
    async fn create_seeds_the_apex_ns_in_the_ns_row_form() {
        let mut config: Config = serde_json::from_str("{}").unwrap();
        config.database.sqlite.file_path = "sqlite::memory:".to_string();
        let db = Db::connect(&config.database).await.unwrap();
        let cx = Context::new(
            config,
            String::new(),
            db,
            Metrics::new().unwrap(),
            mpsc::unbounded_channel().0,
            mpsc::channel(1).0,
            watch::channel(0).0,
        );

        create(
            &cx,
            &Caller::socket(),
            &CreateZoneRequest {
                name: "example.com".to_string(),
                mname: "NS1.Example.com".to_string(),
                rname: "hostmaster@example.com".to_string(),
                default_ttl: None,
                serial: None,
                refresh: None,
                retry: None,
                expire: None,
                minimum_ttl: None,
                description: None,
                apex_ns: true,
                dry_run: false,
            },
        )
        .await
        .unwrap();

        let records =
            bindizr_db::record::list_by_filter_with_zone(cx.db(), &RecordFilter::default())
                .await
                .unwrap();

        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].record().value, "ns1.example.com.");
    }
}
