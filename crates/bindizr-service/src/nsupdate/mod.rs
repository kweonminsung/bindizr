//! nsupdate (RFC 2136), from the point the wire message is decoded.
//! Prerequisite evaluation, per-key authorization, and the transactional apply
//! live here; core reads the wire format, and the DNS front end owns TSIG.
//! The service prescans the complete sections before choosing operations.

mod decode;
mod operation;
mod prerequisite;

use bindizr_core::{
    dns::{
        Serial,
        name::{OwnerName, ParseNameError, ZoneName, to_fqdn},
        nsupdate::parser::{ParseUpdateError, UpdateRecord, UpdateShapeError},
    },
    model::role_grant::Action,
};
use bindizr_db::LockLevel;
use decode::{decode_prerequisites, decode_updates};
use operation::{UpdateOperation, apply_op_tx};
use prerequisite::{Prerequisite, evaluate_prerequisites_tx};
use thiserror::Error;

use crate::{
    Context,
    authorization::{Caller, RecordAccess},
    dnssec,
    error::ServiceError,
    model::{record::RecordType, zone::Zone},
    serial::generate_serial,
    transaction, zone,
};

/// Why an update was not applied, in the terms RFC 2136, Section 2.2 gives the
/// response code.
#[derive(Debug, Error)]
pub enum NsupdateError {
    /// A section violates the wire shapes of RFC 2136, Sections 3.2.1 and 3.4.1.
    #[error("{0}")]
    FormErr(String),
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    YxDomain(String),
    #[error("{0}")]
    YxRrset(String),
    #[error("{0}")]
    NxDomain(String),
    #[error("{0}")]
    NxRrset(String),
    /// The zone section names a zone this server does not serve (RFC 2136,
    /// Section 3.1.2).
    #[error("{0}")]
    NotAuth(String),
    /// An owner name lies outside the zone the request named.
    #[error("{0}")]
    NotZone(String),
    /// A fault of the server's own, kept beneath: SERVFAIL.
    #[error("{0}")]
    Internal(#[source] ServiceError),
}

/// An update record of the wrong shape is a FORMERR (RFC 2136, Section 3.4.1).
impl From<UpdateShapeError> for NsupdateError {
    /// Report the shape the record lacked.
    fn from(err: UpdateShapeError) -> Self {
        NsupdateError::FormErr(err.to_string())
    }
}

/// Rdata that does not decode as its type, or a type no update may carry,
/// is a FORMERR (RFC 2136, Section 3.4.1).
impl From<ParseUpdateError> for NsupdateError {
    /// Report what did not decode.
    fn from(err: ParseUpdateError) -> Self {
        NsupdateError::FormErr(err.to_string())
    }
}

/// A service error the requester could fix is REFUSED; a backend fault is
/// SERVFAIL.
impl From<ServiceError> for NsupdateError {
    /// Map a service failure to the corresponding nsupdate error.
    fn from(err: ServiceError) -> Self {
        if !err.code().is_internal() {
            NsupdateError::Refused(err.to_string())
        } else {
            NsupdateError::Internal(err)
        }
    }
}

/// A database failure is a backend fault, classified through the service error.
impl From<bindizr_db::error::DatabaseError> for NsupdateError {
    /// Map a database failure to SERVFAIL.
    fn from(err: bindizr_db::error::DatabaseError) -> Self {
        NsupdateError::from(ServiceError::from(err))
    }
}

/// The complete wire sections of an UPDATE, retained until the service has
/// checked the zone and prescanned every record. RDATA compression addresses
/// `message`, the original packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update<'a> {
    pub zone_name: ZoneName,
    pub prerequisites: &'a [UpdateRecord],
    pub updates: &'a [UpdateRecord],
    pub message: &'a [u8],
}

/// Apply an update as one transaction for `caller`, reporting whether it
/// changed anything; on a change the zone serial advances once and a NOTIFY
/// follows the commit.
pub async fn apply(
    cx: &Context,
    caller: &Caller,
    update: Update<'_>,
) -> Result<bool, NsupdateError> {
    let mut tx = transaction::begin_tx(cx, "failed to begin NSUPDATE transaction").await?;

    let apply_result: Result<(bool, Zone, Serial), NsupdateError> = async {
        let zone = zone::find_served_by_name_tx(&mut tx, &update.zone_name, LockLevel::Exclusive)
            .await?
            .ok_or_else(|| {
                NsupdateError::NotAuth(format!("zone '{}' is not served here", update.zone_name))
            })?;

        let caller = &caller.reauthenticate_tx(&mut tx).await?;

        // Keep the wire sections through the zone lookup. Every owner and
        // shape is checked before decoding can omit an ineffective delete.
        let prerequisites = decode_prerequisites(update.prerequisites, &zone.name, update.message)?;
        let updates = decode_updates(update.updates, &zone.name, update.message)?;

        // A prerequisite reads what it names, so its grant is checked with
        // the updates', ahead of where RFC 2136, Section 3.3 puts permissions.
        for prerequisite in &prerequisites {
            // SOA and DNSSEC need a read grant without a type restriction.
            let record_type = prerequisite
                .record_type()
                .and_then(|rtype| RecordType::try_from(rtype).ok());
            caller.authorize_record_access(
                &zone,
                &[RecordAccess {
                    action: Action::RecordRead,
                    relative_name: prerequisite.name().clone(),
                    record_type: record_type.as_ref(),
                }],
            )?;
        }
        let mut accesses = Vec::new();
        for op in &updates {
            accesses.push(RecordAccess {
                action: op.action(),
                relative_name: op.name().clone(),
                record_type: op.record_type(),
            });
        }
        caller.authorize_record_access(&zone, &accesses)?;
        evaluate_prerequisites_tx(&mut tx, &zone, &prerequisites).await?;

        // An exhausted serial cannot advance, so refuse rather than commit
        // changes secondaries could never detect.
        let new_serial = generate_serial(Some(zone.serial))?;
        let mut changed = false;

        for op in &updates {
            changed |= apply_op_tx(&mut tx, &zone, op, new_serial, caller).await?;
        }

        if changed {
            dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;
            // Bump the serial and version it so secondaries detect the change via
            // SOA/NOTIFY and can serve it as an IXFR delta.
            zone::advance_serial_tx(&mut tx, cx, &zone, new_serial, caller.change_attribution())
                .await?;
        }

        Ok((changed, zone, new_serial))
    }
    .await;

    let (changed, zone, new_serial) =
        transaction::finish_tx(tx, apply_result, "failed to commit NSUPDATE transaction").await?;

    if changed {
        log::info!(
            "event=nsupdate_apply zone={} serial={}",
            zone.name,
            new_serial
        );

        // Queue through the service like every other mutation path, so
        // `dns.notify.batch_ms` governs RFC 2136 writes too.
        crate::notify::notify_after_update(cx, &zone.name).await;
    }

    Ok(changed)
}

/// The owner of an update record. The wire carries owners absolutely, so a name
/// outside the zone is NOTZONE rather than something to qualify.
fn parse_update_owner(name: &str, zone_name: &ZoneName) -> Result<OwnerName, NsupdateError> {
    if name.trim_end_matches('.').is_empty() {
        return Err(NsupdateError::NotZone(
            "root owner is not supported".to_string(),
        ));
    }

    OwnerName::parse_absolute_in_zone(name, zone_name).map_err(|e| match e {
        ParseNameError::OutsideZone => NsupdateError::NotZone(format!(
            "owner '{}' is outside zone '{}'",
            to_fqdn(name),
            zone_name.to_fqdn()
        )),
        other => NsupdateError::Refused(format!("owner '{}' {}", to_fqdn(name), other)),
    })
}

#[cfg(test)]
mod tests {
    use bindizr_core::dns::name::ZoneName;

    use super::*;

    /// Verify that owner in zone reduces an in zone owner to its stored form.
    #[test]
    fn parse_owner_in_zone_reduces_an_in_zone_owner_to_its_stored_form() {
        assert_eq!(
            parse_update_owner("www.example.com.", &ZoneName::from_row("example.com"))
                .unwrap()
                .to_stored(),
            "www"
        );
        assert!(
            parse_update_owner("example.com.", &ZoneName::from_row("example.com"))
                .unwrap()
                .is_apex()
        );
        // A dotted wire label is one label, so it is data rather than a boundary.
        assert_eq!(
            parse_update_owner(
                r"host\.name.example.com.",
                &ZoneName::from_row("example.com")
            )
            .unwrap()
            .labels(),
            ["host.name"]
        );
    }

    /// Verify that `parse_update_owner` rejects owners outside the zone.
    #[test]
    fn parse_owner_in_zone_rejects_owners_outside_the_zone() {
        for owner in [
            "aexample.com.",
            "badexample.com.",
            "www.badexample.com.",
            ".",
            // One label spelling the zone is not inside it.
            r"evil\.example.com.",
        ] {
            let err = parse_update_owner(owner, &ZoneName::from_row("example.com")).unwrap_err();
            assert!(matches!(err, NsupdateError::NotZone(_)), "{owner:?}");
        }
    }
}
