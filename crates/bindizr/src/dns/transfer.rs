//! Zone import with its records pulled over AXFR from another server.
//! One home shared by the HTTP API and the daemon socket.

use bindizr_core::{
    dns::{message::Rtype, query::TransferRecord},
    model::record::RecordType,
};
use bindizr_service::{
    authorization::Caller,
    error::ServiceError,
    record::RecordService,
    types::{ImportZoneFileRequest, ImportZoneFileResponse},
    zone::ZoneService,
};

use crate::dns::client::axfr;

/// Import a zone from the one source the request carries: its `content`,
/// or an AXFR from its `from_server`.
pub(crate) async fn import_zone(
    caller: &Caller,
    zone_name: &str,
    request: ImportZoneFileRequest,
) -> Result<ImportZoneFileResponse, ServiceError> {
    let server = request
        .from_server
        .as_deref()
        .map(str::trim)
        .filter(|server| !server.is_empty());
    let content = match (request.content, server) {
        (Some(_), Some(_)) => {
            return Err(ServiceError::invalid_input(
                "pass either content or from_server, not both",
            ));
        }
        (None, None) => {
            return Err(ServiceError::invalid_input(
                "either content or from_server is required",
            ));
        }
        (Some(content), None) => content,
        (None, Some(server)) => {
            // Authorize and resolve the zone before any outbound connection.
            ZoneService::get_by_name(caller, zone_name).await?;
            let records = axfr::transfer_zone(server, zone_name).await.map_err(|e| {
                ServiceError::invalid_input(format!("AXFR from {} failed: {}", server, e))
            })?;
            render_zone_file(&records)?
        }
    };

    RecordService::import_zone_file(caller, zone_name, &content, request.mode, request.dry_run)
        .await
}

/// Render transferred records as zone-file lines. SOA and DNSSEC-derived
/// rows are dropped (the zone keeps its own SOA fields and signs itself);
/// any other unsupported type fails the import rather than thinning the
/// zone silently.
fn render_zone_file(records: &[TransferRecord]) -> Result<String, ServiceError> {
    let mut lines = String::new();
    for record in records {
        if matches!(
            record.rtype,
            Rtype::SOA
                | Rtype::RRSIG
                | Rtype::NSEC
                | Rtype::NSEC3
                | Rtype::NSEC3PARAM
                | Rtype::DNSKEY
                | Rtype::CDS
                | Rtype::CDNSKEY
        ) {
            continue;
        }
        RecordType::from_rtype(record.rtype).map_err(|_| {
            ServiceError::invalid_input(format!(
                "the source zone carries a record type bindizr does not store: {} {}",
                record.name, record.rtype
            ))
        })?;
        lines.push_str(&format!(
            "{} {} IN {} {}\n",
            record.name, record.ttl, record.rtype, record.rdata
        ));
    }
    Ok(lines)
}
