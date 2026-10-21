//! Resolve a bulk import's zone list and report each zone's independent outcome.

use bindizr_core::dns::{address::is_address_target, extract_member_zones};

use super::{
    ImportOptions, MissingZoneAction, authorize_new_zone_import, import_actions, import_transfer,
    normalize_zone_names,
};
use crate::{
    Context,
    authorization::Caller,
    dns_client::axfr::AxfrClient,
    error::ServiceError,
    types::{
        ErrorResponse, ImportMode, ImportResult, ImportZonesItemResponse, ImportZonesRequest,
        ImportZonesResponse, ImportZonesSummaryResponse, Run,
    },
    zone,
};

/// Import named zones or catalog members from one server over one connection
/// (RFC 9103, Section 6.3.1), each in its own transaction, reporting every outcome.
pub async fn import_zones(
    cx: &Context,
    caller: &Caller,
    request: &ImportZonesRequest,
) -> Result<ImportZonesResponse, ServiceError> {
    let mode = request
        .mode
        .parse::<ImportMode>()
        .map_err(ServiceError::invalid_input)?;
    let options = ImportOptions {
        mode,
        run: Run::from_dry_run(request.dry_run),
        missing_zone_action: if request.create {
            MissingZoneAction::Create
        } else {
            MissingZoneAction::Reject
        },
    };
    let server = request.from_server.trim();
    if !is_address_target(server) {
        return Err(ServiceError::invalid_input(
            "from_server must name one server as host[:port]",
        ));
    }
    // Checked once, before any transfer: every zone's `create` would fail alike.
    if request.create {
        authorize_new_zone_import(caller, mode)?;
    }
    let config = cx.config();
    let mut client = AxfrClient::new(server);
    let zone_names = match (&request.zone_names, &request.from_catalog) {
        (Some(names), None) => normalize_zone_names(names)?,
        (None, Some(catalog)) => {
            // A catalog names every zone its server provisions, so reading it
            // through Bindizr is an all-zones act.
            for action in import_actions(mode) {
                caller.authorize_all_whole_zones(*action)?;
            }
            let catalog = zone::normalize_name(catalog)?;
            let records = client
                .fetch_zone(&catalog, &config.dns.import)
                .await
                .map_err(|e| {
                    ServiceError::invalid_input_with_source(
                        format!("AXFR of catalog {} from {} failed: {}", catalog, server, e),
                        e,
                    )
                })?;
            let members = extract_member_zones(&records, &catalog).map_err(|e| {
                ServiceError::invalid_input_with_source(
                    format!("catalog {} from {} cannot be read: {}", catalog, server, e),
                    e,
                )
            })?;
            for member in &members {
                zone::validate_name(member)?;
            }
            members
        }
        (Some(_), Some(_)) => {
            return Err(ServiceError::invalid_input(
                "give either zone_names or from_catalog, not both",
            ));
        }
        (None, None) => {
            return Err(ServiceError::invalid_input(
                "give zone_names or from_catalog",
            ));
        }
    };

    let mut summary = ImportZonesSummaryResponse {
        zones: zone_names.len() as u64,
        ok: 0,
        rejected: 0,
        failed: 0,
    };
    let mut zones = Vec::with_capacity(zone_names.len());
    for zone_name in &zone_names {
        let (result, import, error) =
            match import_transfer(cx, caller, zone_name, &mut client, server, options).await {
                Ok(import) if import.was_rejected() => (ImportResult::Rejected, Some(import), None),
                Ok(import) => (ImportResult::Ok, Some(import), None),
                Err(e) => (ImportResult::Failed, None, Some(ErrorResponse::from(&e))),
            };
        match result {
            ImportResult::Ok => summary.ok += 1,
            ImportResult::Rejected => summary.rejected += 1,
            ImportResult::Failed => summary.failed += 1,
        }
        zones.push(ImportZonesItemResponse {
            zone_name: zone_name.to_string(),
            result,
            import,
            error,
        });
    }
    log::info!(
        "event=zones_import server={} mode={:?} dry_run={} zones={} ok={} rejected={} failed={}",
        server,
        mode,
        request.dry_run,
        summary.zones,
        summary.ok,
        summary.rejected,
        summary.failed,
    );
    Ok(ImportZonesResponse {
        dry_run: request.dry_run,
        summary,
        zones,
    })
}
