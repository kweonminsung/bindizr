//! Prescan and apply nsupdate (RFC 2136) with prerequisite checks and role grants.
//! Core decodes the wire format; the DNS front end authenticates TSIG.

mod decode;
mod operation;
mod plan;
mod prerequisite;

use bindizr_core::{
    dns::{
        Serial,
        message::{Class, Rcode, Rtype},
        name::{OwnerName, ParseNameError, ZoneName, to_fqdn},
        nsupdate::parser::{ParseUpdateError, UpdateRecord, ValidateUpdateShapeError},
        record::ParseRecordValueError,
    },
    model::role_grant::Action,
};
use bindizr_db::LockLevel;
use decode::{decode_prerequisite, decode_updates};
use operation::apply_record_operation_tx;
use plan::UpdateOperation;
use prerequisite::{
    Prerequisite, RecordSets, evaluate_prerequisite, evaluate_record_set_prerequisites,
    list_served_record_sets_tx,
};
use thiserror::Error;

use crate::{
    Context,
    authorization::{Caller, RecordAccess},
    dnssec,
    error::ServiceError,
    model::{record::RecordType, zone::Zone},
    transaction, zone,
};

/// An UPDATE failure and its RFC 2136 response classification.
#[derive(Debug, Error)]
pub enum NsupdateError {
    #[error("record type {0} is managed by the DNSSEC signer")]
    ManagedType(Rtype),
    #[error("unsupported record type: {0}")]
    UnsupportedType(Rtype),
    #[error("{0}")]
    FormErr(String),
    #[error("{0}")]
    Shape(#[from] ValidateUpdateShapeError),
    #[error("{0}")]
    Parse(#[from] ParseUpdateError),
    #[error("invalid {record_type} rdata: {source}")]
    RecordValue {
        record_type: RecordType,
        #[source]
        source: ParseRecordValueError,
    },
    #[error("owner '{name}' in zone '{zone_name}': {source}")]
    Owner {
        name: String,
        zone_name: ZoneName,
        #[source]
        source: ParseNameError,
    },
    #[error("{0}")]
    YxDomain(String),
    #[error("{0}")]
    YxRrset(String),
    #[error("{0}")]
    NxDomain(String),
    #[error("{0}")]
    NxRrset(String),
    #[error("{0}")]
    NotAuth(String),
    #[error("{0}")]
    NotZone(String),
    /// A policy refusal (RFC 2136, Section 3.3): an unsigned request where a
    /// signature is required.
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    Service(#[from] ServiceError),
}

impl NsupdateError {
    /// Classify an UPDATE failure without consuming its original cause.
    pub fn rcode(&self) -> Rcode {
        match self {
            // RFC 2136, Section 3.4.1.2: an unrecognized type is a prescan failure.
            Self::FormErr(_) | Self::Shape(_) | Self::Parse(_) | Self::UnsupportedType(_) => {
                Rcode::FORMERR
            }
            Self::RecordValue { .. } | Self::ManagedType(_) => Rcode::REFUSED,
            Self::Owner {
                source: ParseNameError::OutsideZone,
                ..
            }
            | Self::NotZone(_) => Rcode::NOTZONE,
            Self::Owner { .. } => Rcode::REFUSED,
            Self::YxDomain(_) => Rcode::YXDOMAIN,
            Self::YxRrset(_) => Rcode::YXRRSET,
            Self::NxDomain(_) => Rcode::NXDOMAIN,
            Self::NxRrset(_) => Rcode::NXRRSET,
            Self::NotAuth(_) => Rcode::NOTAUTH,
            Self::Refused(_) => Rcode::REFUSED,
            Self::Service(error) if error.code().is_internal() => Rcode::SERVFAIL,
            Self::Service(_) => Rcode::REFUSED,
        }
    }
}

/// A database failure is a backend fault, classified through the service error.
impl From<bindizr_db::error::DatabaseError> for NsupdateError {
    /// Map a database failure to SERVFAIL.
    fn from(error: bindizr_db::error::DatabaseError) -> Self {
        NsupdateError::from(ServiceError::from(error))
    }
}

/// Keep complete UPDATE sections for zone checks and prescanning;
/// RDATA compression offsets refer to the original `message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update<'a> {
    pub zone_name: ZoneName,
    pub zone_class: Class,
    pub prerequisites: &'a [UpdateRecord],
    pub updates: &'a [UpdateRecord],
    pub message: &'a [u8],
}

/// Apply an authorized UPDATE atomically; changes advance the serial once and
/// trigger NOTIFY after commit.
pub async fn apply(
    cx: &Context,
    caller: &Caller,
    update: Update<'_>,
) -> Result<bool, NsupdateError> {
    // Bindizr serves only IN zones; other classes lack authority even if
    // their ZNAME matches a stored zone (RFC 2136, Section 3.1.1).
    if update.zone_class != Class::IN {
        return Err(NsupdateError::NotAuth(format!(
            "zone '{}' in class {} is not served here",
            update.zone_name, update.zone_class
        )));
    }

    let mut tx = transaction::begin_tx(cx, "failed to begin NSUPDATE transaction").await?;

    let apply_result: Result<(bool, Zone, Serial), NsupdateError> = async {
        let zone = zone::find_served_by_name_tx(&mut tx, &update.zone_name, LockLevel::Exclusive)
            .await?
            .ok_or_else(|| {
                NsupdateError::NotAuth(format!("zone '{}' is not served here", update.zone_name))
            })?;

        let caller = &caller.reauthenticate_tx(&mut tx).await?;

        // RFC 2136, Section 3 order: authority (NOTAUTH, above) precedes the policy
        // on unsigned requests, which is refused before anything is read.
        if caller.is_unsigned_dns() && cx.config().dns.nsupdate.tsig_required {
            return Err(NsupdateError::Refused(
                "unsigned NSUPDATE refused: no TSIG record present".to_string(),
            ));
        }

        // Prerequisites are decoded and evaluated in wire order (Section 3.2.5);
        // value-dependent sets are compared whole after the section (Section 3.2.3).
        let served = if update.prerequisites.is_empty() {
            RecordSets::new()
        } else {
            list_served_record_sets_tx(&mut tx, &zone).await?
        };

        let mut wanted = RecordSets::new();

        for record in update.prerequisites {
            let prerequisite = decode_prerequisite(record, &zone.name, update.message)?;

            // A prerequisite reads what it names, so its read grant precedes its
            // evaluation (Section 3.3.1); SOA and DNSSEC need one without a type restriction.
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
            evaluate_prerequisite(&served, &prerequisite, &mut wanted)?;
        }

        evaluate_record_set_prerequisites(&served, &wanted)?;

        // The prescan parses the owners the update grants are checked on.
        let updates = decode_updates(update.updates, &zone.name, update.message)?;
        let mut accesses = Vec::new();

        for op in &updates {
            match op {
                UpdateOperation::Record(op) => accesses.push(RecordAccess {
                    action: op.action(),
                    relative_name: op.name().clone(),
                    record_type: op.record_type(),
                }),
                UpdateOperation::ReplaceSoa { .. } => {
                    caller.authorize_zone_action(Action::ZoneUpdate, &zone)?;
                }
            }
        }

        caller.authorize_record_access(&zone, &accesses)?;

        let plan = plan::UpdatePlan::compute(&zone, updates)?;
        let new_serial = plan.zone.serial;
        let mut changed = plan.soa_changed;

        for op in &plan.records {
            changed |=
                apply_record_operation_tx(&mut tx, &plan.zone, op, new_serial, caller).await?;
        }

        if changed {
            zone::validate_record_changes_tx(&mut tx, &plan.zone, &[], &[]).await?;

            if plan.soa_changed {
                let changes = zone::soa_replacement_changes(&zone, &plan.zone, new_serial)?;
                bindizr_db::zone_change::create_many_tx(&mut tx, &changes).await?;
            }

            let updated = bindizr_db::zone::update_tx(&mut tx, plan.zone).await?;
            dnssec::sign_zone_tx(&mut tx, &updated, new_serial).await?;
            zone::save_version_tx(&mut tx, &updated, new_serial, caller.change_origin()).await?;
        }

        Ok((changed, zone, new_serial))
    }
    .await;

    let (changed, zone, new_serial) =
        transaction::finish_tx(tx, apply_result, "failed to commit NSUPDATE transaction").await?;

    if changed {
        cx.metrics().track_serial_bumps(1);
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

    OwnerName::parse_absolute_in_zone(name, zone_name).map_err(|source| NsupdateError::Owner {
        name: to_fqdn(name),
        zone_name: zone_name.clone(),
        source,
    })
}

#[cfg(test)]
mod tests;
