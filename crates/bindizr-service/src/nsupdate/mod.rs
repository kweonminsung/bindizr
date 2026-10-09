//! RFC 2136 dynamic updates, from the point the wire message is decoded.
//! Prerequisite evaluation, per-key authorization, and the transactional apply
//! live here; the DNS front end owns the message format, TSIG, and rdata.

mod operation;
mod prerequisite;

use bindizr_core::{
    dns::{
        Serial,
        message::Rtype,
        name::{OwnerName, ParseNameError, ZoneName, to_fqdn},
        record::Rdata,
    },
    model::role_grant::Action,
};
use bindizr_db::LockLevel;
pub use operation::UpdateOperation;
use operation::apply_op_tx;
use prerequisite::evaluate_prerequisites_tx;
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

/// A service error the requester could fix is REFUSED; a backend fault is
/// SERVFAIL.
impl From<ServiceError> for NsupdateError {
    /// Map a service failure to the corresponding dynamic update error.
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

/// A condition the zone must satisfy before any update is applied
/// (RFC 2136, Section 2.4). Owner names are absolute, as they arrive on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prerequisite {
    /// CLASS ANY, TYPE ANY: the owner name must exist.
    NameInUse { name: String },
    /// CLASS NONE, TYPE ANY: the owner name must not exist.
    NameNotInUse { name: String },
    /// CLASS ANY: the record set must exist.
    RecordSetInUse {
        name: String,
        record_type: RecordType,
    },
    /// CLASS NONE: the record set must not exist.
    RecordSetNotInUse {
        name: String,
        record_type: RecordType,
    },
    /// CLASS IN: with the others of its name and type, the record set must equal
    /// the zone's (RFC 2136, Section 3.2.3).
    RecordInUse {
        name: String,
        record_type: RecordType,
        /// TXT arrives row-encoded; every other type in presentation form.
        value: String,
        priority: Option<i32>,
    },
    /// A record set of a type bindizr never stores must exist: it cannot,
    /// the zone's own SOA at the apex excepted.
    UnstoredTypeInUse { name: String, record_type: Rtype },
    /// A record set of a type bindizr never stores must not exist: it never
    /// does, the zone's own SOA at the apex excepted.
    UnstoredTypeNotInUse { name: String, record_type: Rtype },
    /// CLASS IN, TYPE SOA: the zone's SOA must carry exactly this rdata
    /// (RFC 2136, Section 3.2.3).
    SoaInUse { name: String, rdata: Rdata },
}

/// A decoded UPDATE message: the zone it targets and the sections to
/// evaluate and apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    pub zone_name: ZoneName,
    pub prerequisites: Vec<Prerequisite>,
    pub updates: Vec<UpdateOperation>,
}

/// Apply an update as one transaction for `caller`, reporting whether it
/// changed anything; on a change the zone serial advances once and a NOTIFY
/// follows the commit.
pub async fn apply(cx: &Context, caller: &Caller, update: Update) -> Result<bool, NsupdateError> {
    let mut tx = transaction::begin_tx(cx, "failed to begin NSUPDATE transaction").await?;

    let apply_result: Result<(bool, Zone, Serial), NsupdateError> = async {
        let zone = zone::find_served_by_name_tx(&mut tx, &update.zone_name, LockLevel::Exclusive)
            .await?
            .ok_or_else(|| {
                NsupdateError::NotAuth(format!("zone '{}' is not served here", update.zone_name))
            })?;

        let caller = &caller.reauthenticate_tx(&mut tx).await?;

        // A prerequisite reads what it names, so its grant is checked with
        // the updates', ahead of where RFC 2136, Section 3.3 puts permissions.
        let mut accesses = Vec::new();
        for prerequisite in &update.prerequisites {
            let (name, record_type) = match prerequisite {
                Prerequisite::NameInUse { name }
                | Prerequisite::NameNotInUse { name }
                | Prerequisite::UnstoredTypeInUse { name, .. }
                | Prerequisite::UnstoredTypeNotInUse { name, .. }
                | Prerequisite::SoaInUse { name, .. } => (name, None),
                Prerequisite::RecordSetInUse { name, record_type }
                | Prerequisite::RecordSetNotInUse { name, record_type }
                | Prerequisite::RecordInUse {
                    name, record_type, ..
                } => (name, Some(record_type)),
            };
            accesses.push(RecordAccess {
                action: Action::RecordRead,
                relative_name: parse_update_owner(name, &zone.name)?,
                record_type,
            });
        }
        for op in &update.updates {
            accesses.push(RecordAccess {
                action: op.action(),
                relative_name: parse_update_owner(op.name(), &zone.name)?,
                record_type: op.record_type(),
            });
        }
        caller.authorize_record_access(&zone, &accesses)?;
        evaluate_prerequisites_tx(&mut tx, &zone, &update.prerequisites).await?;

        // An exhausted serial cannot advance, so refuse rather than commit
        // changes secondaries could never detect.
        let new_serial = generate_serial(Some(zone.serial))?;
        let mut changed = false;

        for op in &update.updates {
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
