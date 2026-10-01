//! Render a zone as BIND master-file text, the inverse of `zone import`.

use std::fmt::Write as _;

use bindizr_core::dns::name::{ZoneName, to_fqdn};
use bindizr_db::LockLevel;

use crate::{
    Context,
    authorization::Caller,
    error::ServiceError,
    model::{dnssec_record::DnssecRecord, record::Record, zone::Zone},
    transaction,
    types::ZoneView,
};

/// Render a BIND master file (RFC 1035); unsigned output round-trips through `zone import`.
/// Import manages SOA separately. Signed output adds derived DNSSEC records for inspection only.
pub async fn export(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    view: ZoneView,
) -> Result<String, ServiceError> {
    // Read the zone and records in one locked transaction so the export is a
    // single consistent view, not stale SOA metadata with newer records.
    let mut tx = transaction::begin_read_tx(cx, "failed to export zone").await?;
    let load_result = async {
        let zone = super::get_by_name_tx(&mut tx, caller, zone_name, LockLevel::Shared).await?;
        caller.authorize_zone_unrestricted(&zone)?;
        let records = bindizr_db::record::list_tx(&mut tx, zone.id, LockLevel::Unlocked).await?;
        let derived = if view == ZoneView::Signed {
            bindizr_db::dnssec_record::list_tx(&mut tx, zone.id, LockLevel::Unlocked).await?
        } else {
            Vec::new()
        };
        Ok::<(Zone, Vec<Record>, Vec<DnssecRecord>), ServiceError>((zone, records, derived))
    }
    .await;
    let (zone, mut records, mut derived) =
        transaction::finish_tx(tx, load_result, "failed to export zone").await?;

    let origin = zone.name.to_fqdn();
    let mut out = String::new();
    out.push_str(&format!("$ORIGIN {origin}\n"));
    out.push_str(&format!("$TTL {}\n", zone.default_ttl));

    // SOA carries names as absolute FQDNs so they are not read as relative
    // to $ORIGIN. `soa_mailbox` already escapes the local part per RFC 1035.
    let mailbox = zone.soa_mailbox().map_err(|e| {
        ServiceError::internal_with_source(format!("failed to render SOA mailbox: {e}"), e)
    })?;
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
            row.rdata.to_presentation(row.record_type),
        )
    });
    for row in &derived {
        let _ = writeln!(
            out,
            "{}\t{}\tIN\t{}\t{}",
            row.name,
            row.ttl,
            row.record_type,
            row.rdata.to_presentation(row.record_type),
        );
    }

    Ok(out)
}
