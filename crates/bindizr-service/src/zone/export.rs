//! Render a zone as BIND master-file text, the inverse of `zone import`.

use bindizr_core::dns::{DEFAULT_RECORD_TTL, name::to_fqdn, record::presentation_rdata};

use super::{ZoneService, validation::normalize_zone_name};
use crate::{
    error::ServiceError,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    repository::RepositoryService,
};

impl ZoneService {
    /// Render a zone and its records as a BIND master file (RFC 1035). The
    /// output round-trips through `zone import`, which manages the SOA itself
    /// and so ignores the SOA line on the way back in.
    pub async fn export_zone_file(zone_name: &str) -> Result<String, ServiceError> {
        // Read the zone and records in one locked transaction so the export is a
        // single consistent snapshot, not stale SOA metadata with newer records.
        let lookup_name = normalize_zone_name(zone_name)?;
        let mut tx = RepositoryService::begin_tx("Failed to export zone").await?;
        let load_result = async {
            let zone = RepositoryService::get_zone_by_name_tx(&mut tx, &lookup_name)
                .await?
                .ok_or_else(|| ServiceError::zone_not_found(zone_name))?;
            let records = RepositoryService::get_records_by_zone_id_tx(&mut tx, zone.id).await?;
            Ok::<(Zone, Vec<Record>), ServiceError>((zone, records))
        }
        .await;
        let (zone, mut records) =
            RepositoryService::finish_tx(tx, load_result, "Failed to export zone").await?;

        let origin = to_fqdn(&zone.name);
        let mut out = String::new();
        out.push_str(&format!("$ORIGIN {origin}\n"));
        out.push_str(&format!("$TTL {}\n", zone.ttl));

        // SOA carries names as absolute FQDNs so they are not read as relative
        // to $ORIGIN. `soa_mailbox` already escapes the local part per RFC 1035.
        let mailbox = zone
            .soa_mailbox()
            .map_err(|e| ServiceError::internal(format!("Failed to render SOA mailbox: {e}")))?;
        out.push_str(&format!(
            "@\t{}\tIN\tSOA\t{} {} {} {} {} {} {}\n",
            zone.ttl,
            to_fqdn(&zone.primary_ns),
            to_fqdn(&mailbox),
            zone.serial,
            zone.refresh,
            zone.retry,
            zone.expire,
            zone.minimum_ttl,
        ));

        // Deterministic order: owner name, then type, then rdata.
        records.sort_by(|a, b| {
            (
                &a.name,
                a.record_type.to_string(),
                presentation_rdata(&a.value, a.priority, &a.record_type),
            )
                .cmp(&(
                    &b.name,
                    b.record_type.to_string(),
                    presentation_rdata(&b.value, b.priority, &b.record_type),
                ))
        });

        for record in &records {
            // A stray SOA row (never created through the API) would duplicate
            // the apex SOA above.
            if record.record_type == RecordType::SOA {
                continue;
            }
            out.push_str(&format!(
                "{}\t{}\tIN\t{}\t{}\n",
                record.name,
                // Match the XFR encoder's served TTL so the export round-trips.
                record.ttl.unwrap_or(DEFAULT_RECORD_TTL),
                record.record_type,
                presentation_rdata(&record.value, record.priority, &record.record_type),
            ));
        }

        Ok(out)
    }
}
