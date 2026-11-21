//! Render a zone as BIND master-file text, the inverse of `zone import`.

use bindizr_core::dns::name;
use bindizr_core::dns::name::ZoneName;
use bindizr_db::LockLevel;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::types::ZoneView;
use crate::{Context, transaction, zone};

/// Render a BIND master file (RFC 1035); unsigned output round-trips through `zone import`.
/// Import manages SOA separately. Signed output adds derived DNSSEC records for inspection only.
pub async fn export(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    view: ZoneView,
) -> Result<String, ServiceError> {
    use std::fmt::Write as _;

    // Read the zone and records in one locked transaction so the export is a
    // single consistent view, not stale SOA metadata with newer records.
    let mut tx = transaction::begin_read_tx(cx, "failed to export zone").await?;

    let result: Result<_, ServiceError> = async {
        let zone = zone::lookup_by_name_tx(&mut tx, zone_name, LockLevel::Shared).await?;
        let read = caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_whole_zone_read(&zone)?;
        let records = bindizr_db::record::list_tx(&mut tx, zone.id, LockLevel::Unlocked).await?;
        let derived = if view == ZoneView::Signed {
            bindizr_db::dnssec_record::list_tx(&mut tx, zone.id).await?
        } else {
            Vec::new()
        };

        Ok((zone, read, records, derived))
    }
    .await;

    let (zone, read, mut records, mut derived) =
        transaction::finish_tx(tx, result, "failed to export zone").await?;

    let origin = zone.name.to_fqdn();
    let mut out = String::new();
    out.push_str(&format!("$ORIGIN {origin}\n"));
    out.push_str(&format!("$TTL {}\n", zone.default_ttl));

    // SOA carries names as absolute FQDNs so they are not read as relative
    // to $ORIGIN; a mailbox is one already, its local part escaped by the name codec.
    let mailbox = zone.soa_mailbox().map_err(|error| {
        ServiceError::internal_with_source("failed to render SOA mailbox", error)
    })?;
    out.push_str(&format!(
        "@\t{}\tIN\tSOA\t{} {} {} {} {} {} {}\n",
        zone.default_ttl,
        name::to_fqdn(&zone.mname),
        mailbox,
        zone.serial,
        zone.refresh,
        zone.retry,
        zone.expire,
        zone.minimum_ttl
    ));

    // Deterministic order: owner name, then type, then rdata. Keyed up front
    // because a comparator would re-render the rdata on every comparison.
    records.sort_by_cached_key(|record| {
        (
            record.name.clone(),
            record.record_type.as_str(),
            record
                .record_type
                .presentation_rdata(&record.value, record.priority),
        )
    });

    for record in read.readable_records(records).as_slice() {
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
                .presentation_rdata(&record.value, record.priority)
        );
    }

    derived.sort_by_cached_key(|record| {
        (
            record.name.clone(),
            record.record_type,
            record.rdata.to_presentation(record.record_type),
        )
    });

    for record in read.readable_records(derived).as_slice() {
        let _ = writeln!(
            out,
            "{}\t{}\tIN\t{}\t{}",
            record.name,
            record.ttl,
            record.record_type,
            record.rdata.to_presentation(record.record_type)
        );
    }

    Ok(out)
}
