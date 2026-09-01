//! Render a zone as BIND master-file text, the inverse of `zone import`.

use std::fmt::Write as _;

use bindizr_core::dns::{dnssec::rdata_presentation, name::to_fqdn};
use bindizr_db::repository::LockLevel;

use super::ZoneService;
use crate::{
    authorization::Caller,
    error::ServiceError,
    model::{dnssec_record::DnssecRecord, record::Record, zone::Zone},
    repository::RepositoryService,
};

impl ZoneService {
    /// Render a zone and its records as a BIND master file (RFC 1035). The
    /// unsigned output round-trips through `zone import`, which manages the
    /// SOA itself and so ignores the SOA line on the way back in; `signed`
    /// appends the derived DNSSEC records as an inspection artifact, not an
    /// import input. Visibility is checked on the row this tx locked, so a
    /// same-name recreation cannot swap the zone in.
    pub async fn export_zone_file(
        caller: &Caller,
        zone_name: &str,
        signed: bool,
    ) -> Result<String, ServiceError> {
        // Read the zone and records in one locked transaction so the export is a
        // single consistent view, not stale SOA metadata with newer records.
        let mut tx = RepositoryService::begin_read_tx("Failed to export zone").await?;
        let load_result = async {
            let zone =
                ZoneService::get_visible_by_name_tx(&mut tx, caller, zone_name, LockLevel::Shared)
                    .await?;
            let records =
                RepositoryService::list_records_tx(&mut tx, zone.id, LockLevel::None).await?;
            let derived = if signed {
                RepositoryService::list_dnssec_records_tx(&mut tx, zone.id, LockLevel::None).await?
            } else {
                Vec::new()
            };
            Ok::<(Zone, Vec<Record>, Vec<DnssecRecord>), ServiceError>((zone, records, derived))
        }
        .await;
        let (zone, mut records, mut derived) =
            RepositoryService::finish_tx(tx, load_result, "Failed to export zone").await?;

        let origin = zone.name.to_fqdn();
        let mut out = String::new();
        out.push_str(&format!("$ORIGIN {origin}\n"));
        out.push_str(&format!("$TTL {}\n", zone.default_ttl));

        // SOA carries names as absolute FQDNs so they are not read as relative
        // to $ORIGIN. `soa_mailbox` already escapes the local part per RFC 1035.
        let mailbox = zone
            .soa_mailbox()
            .map_err(|e| ServiceError::internal(format!("Failed to render SOA mailbox: {e}")))?;
        out.push_str(&format!(
            "@\t{}\tIN\tSOA\t{} {} {} {} {} {} {}\n",
            zone.default_ttl,
            to_fqdn(&zone.mname),
            to_fqdn(mailbox.as_str()),
            zone.serial,
            zone.refresh,
            zone.retry,
            zone.expire,
            zone.minimum_ttl,
        ));

        // Deterministic order: owner name, then type, then rdata. Keyed up front
        // because a comparator would re-render the rdata on every comparison.
        records.sort_by_cached_key(|r| {
            (
                r.name.clone(),
                r.record_type.as_str(),
                r.record_type.presentation_rdata(&r.value, r.priority),
            )
        });

        for record in &records {
            // Written straight into `out`: a zone can hold millions of records,
            // and `push_str(&format!(..))` would allocate a line at a time.
            let _ = writeln!(
                out,
                "{}\t{}\tIN\t{}\t{}",
                record.name,
                // Match the XFR encoder's served TTL so the export round-trips.
                record.ttl,
                record.record_type,
                record
                    .record_type
                    .presentation_rdata(&record.value, record.priority),
            );
        }

        derived.sort_by_cached_key(|row| {
            (
                row.name.clone(),
                row.record_type,
                rdata_presentation(row.record_type, &row.rdata),
            )
        });
        for row in &derived {
            let _ = writeln!(
                out,
                "{}\t{}\tIN\t{}\t{}",
                row.name,
                row.ttl,
                row.record_type,
                rdata_presentation(row.record_type, &row.rdata),
            );
        }

        Ok(out)
    }
}
