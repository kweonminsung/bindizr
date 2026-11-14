//! Resolve a bulk import's zone list and report each zone's independent outcome.

use bindizr_core::dns;
use bindizr_core::dns::address;

use crate::authorization::Caller;
use crate::dns_client::axfr::AxfrClient;
use crate::error::ServiceError;
use crate::types::{
    ErrorResponse, ImportMode, ImportResult, ImportZonesItemResponse, ImportZonesRequest,
    ImportZonesResponse, ImportZonesSummaryResponse, Run,
};
use crate::zone::import;
use crate::zone::import::{ImportOptions, MissingZoneAction};
use crate::{Context, zone};

/// Import named zones or catalog members from one server over one connection
/// (RFC 9103, Section 6.3.1), each in its own transaction, reporting every outcome.
pub async fn import_many(
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
    let address = request.from_server.trim();

    if !address::is_address_target(address) {
        return Err(ServiceError::invalid_input(
            "from_server must name one server as host[:port]",
        ));
    }

    // Checked once, before any transfer: every zone's `create` would fail alike.
    if request.create {
        import::authorize_new_zone_import(caller, mode)?;
    }

    let config = cx.config();
    let mut client = AxfrClient::new(address);

    let zone_names = match (&request.zone_names, &request.from_catalog) {
        (Some(names), None) => import::normalize_zone_names(names)?,
        (None, Some(catalog)) => {
            // A catalog names every zone its server provisions, so reading it
            // through Bindizr is an all-zones act.
            for action in import::import_actions(mode) {
                caller.authorize_all_whole_zones(*action)?;
            }

            let catalog_zone_name = zone::normalize_name(catalog)?;

            let records = client
                .fetch_zone(&catalog_zone_name, &config.dns.import)
                .await
                .map_err(|error| {
                    ServiceError::invalid_input_with_source(
                        format!(
                            "AXFR of catalog {catalog_zone_name} from {address} failed: {error}"
                        ),
                        error,
                    )
                })?;
            let members =
                dns::extract_member_zones(&records, &catalog_zone_name).map_err(|error| {
                    ServiceError::invalid_input_with_source(
                        format!(
                            "catalog {catalog_zone_name} from {address} cannot be read: {error}"
                        ),
                        error,
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

    // Reuse the transfer connection while each zone keeps its own transaction.
    for zone_name in &zone_names {
        let (result, import, error) =
            match import::import_transfer(cx, caller, zone_name, &mut client, address, options)
                .await
            {
                Ok(import) if import.was_rejected() => (ImportResult::Rejected, Some(import), None),
                Ok(import) => (ImportResult::Ok, Some(import), None),
                Err(error) => (
                    ImportResult::Failed,
                    None,
                    Some(ErrorResponse::from(&error)),
                ),
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
        "event=zones_import server={address} mode={mode:?} dry_run={} zones={} ok={} rejected={} failed={}",
        request.dry_run,
        summary.zones,
        summary.ok,
        summary.rejected,
        summary.failed
    );

    Ok(ImportZonesResponse {
        dry_run: request.dry_run,
        summary,
        zones,
    })
}
