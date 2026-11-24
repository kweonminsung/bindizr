//! Prescan and apply nsupdate (RFC 2136) with prerequisite checks and role grants.
//! Core decodes the wire format; the DNS front end authenticates TSIG.

mod decode;
mod operation;
mod plan;
mod prerequisite;

use bindizr_core::dns::message::{Class, Rcode, Rtype};
use bindizr_core::dns::name::{ParseNameError, ZoneName};
use bindizr_core::dns::nsupdate::parser::{
    ParseUpdateError, UpdateRecord, ValidateUpdateShapeError,
};
use bindizr_core::dns::record::ParseRecordValueError;
use bindizr_core::model::activity_log::ActivityOperation;
use bindizr_core::model::record::RecordType;
use bindizr_core::model::role_grant::Action;
use bindizr_db::LockLevel;
use bindizr_db::error::DatabaseError;
use operation::RecordMutation;
use plan::UpdateOperation;
use prerequisite::RecordSets;
use thiserror::Error;

use crate::authorization::{Caller, RecordAccess};
use crate::error::ServiceError;
use crate::{Context, dnssec, notify, record, transaction, zone};

/// An UPDATE failure and its RFC 2136 response classification.
#[derive(Debug, Error)]
pub enum NsupdateError {
    #[error("record type {rtype} is managed by the DNSSEC signer")]
    ManagedType { rtype: Rtype },
    #[error("unsupported record type: {rtype}")]
    UnsupportedType { rtype: Rtype },
    #[error("{message}")]
    FormErr { message: String },
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
    #[error("{message}")]
    YxDomain { message: String },
    #[error("{message}")]
    YxRrset { message: String },
    #[error("{message}")]
    NxDomain { message: String },
    #[error("{message}")]
    NxRrset { message: String },
    #[error("{message}")]
    NotAuth { message: String },
    /// A policy refusal (RFC 2136, Section 3.3): an unsigned request where a
    /// signature is required.
    #[error("{message}")]
    Refused { message: String },
    #[error("{0}")]
    Service(#[from] ServiceError),
}

impl NsupdateError {
    /// Return the RCODE RFC 2136 gives this outcome, or the wrapped
    /// `ServiceError` whose code the transport maps to its own RCODE.
    pub fn rcode(&self) -> Result<Rcode, &ServiceError> {
        let rcode = match self {
            // RFC 2136, Section 3.4.1.2: an unrecognized type is a prescan failure.
            Self::FormErr { .. }
            | Self::Shape(_)
            | Self::Parse(_)
            | Self::UnsupportedType { .. } => Rcode::FORMERR,
            Self::RecordValue { .. } | Self::ManagedType { .. } => Rcode::REFUSED,
            Self::Owner {
                source: ParseNameError::OutsideZone,
                ..
            } => Rcode::NOTZONE,
            Self::Owner { .. } => Rcode::REFUSED,
            Self::YxDomain { .. } => Rcode::YXDOMAIN,
            Self::YxRrset { .. } => Rcode::YXRRSET,
            Self::NxDomain { .. } => Rcode::NXDOMAIN,
            Self::NxRrset { .. } => Rcode::NXRRSET,
            Self::NotAuth { .. } => Rcode::NOTAUTH,
            Self::Refused { .. } => Rcode::REFUSED,
            Self::Service(error) => return Err(error),
        };

        Ok(rcode)
    }
}

/// A database failure is a backend fault, carried as the service error.
impl From<DatabaseError> for NsupdateError {
    /// Wrap a database failure in its service error.
    fn from(error: DatabaseError) -> Self {
        Self::from(ServiceError::from(error))
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
        return Err(NsupdateError::NotAuth {
            message: format!(
                "zone '{}' in class {} is not served here",
                update.zone_name, update.zone_class
            ),
        });
    }

    let mut tx = transaction::begin_tx(cx, "failed to begin NSUPDATE transaction").await?;

    let apply_result: Result<_, NsupdateError> = async {
        let zone = zone::find_served_by_name_tx(&mut tx, &update.zone_name, LockLevel::Exclusive)
            .await?
            .ok_or_else(|| NsupdateError::NotAuth {
                message: format!("zone '{}' is not served here", update.zone_name),
            })?;

        let caller = &caller.reauthenticate_tx(&mut tx).await?;

        // RFC 2136, Section 3 order: authority (NOTAUTH, above) precedes the policy
        // on unsigned requests, which is refused before anything is read.
        if caller.is_unsigned_dns() && cx.config().dns.nsupdate.tsig_required {
            return Err(NsupdateError::Refused {
                message: "unsigned NSUPDATE refused: no TSIG record present".to_string(),
            });
        }

        // Prerequisites are decoded and evaluated in wire order (RFC 2136, Section 3.2.5);
        // value-dependent sets are compared whole after the section (RFC 2136, Section 3.2.3).
        let served = if update.prerequisites.is_empty() {
            RecordSets::new()
        } else {
            prerequisite::list_served_record_sets_tx(&mut tx, &zone).await?
        };

        let mut wanted = RecordSets::new();

        for record in update.prerequisites {
            let prerequisite = decode::decode_prerequisite(record, &zone.name, update.message)?;

            // A prerequisite reads what it names, so its read grant precedes its evaluation
            // (RFC 2136, Section 3.3.1); SOA and DNSSEC need one without a type restriction.
            let record_type = prerequisite
                .record_type()
                .and_then(|rtype| RecordType::try_from(rtype).ok());
            caller.authorize_record_access(
                &zone,
                &[RecordAccess {
                    action: Action::RecordRead,
                    relative_name: prerequisite.name().clone(),
                    record_type,
                }],
            )?;
            prerequisite::evaluate_prerequisite(&served, &prerequisite, &mut wanted)?;
        }

        prerequisite::evaluate_record_set_prerequisites(&served, &wanted)?;

        // The prescan parses the owners the update grants are checked on.
        let updates = decode::decode_updates(update.updates, &zone.name, update.message)?;
        let mut accesses = Vec::new();

        for operation in &updates {
            match operation {
                UpdateOperation::Record(operation) => accesses.push(RecordAccess {
                    action: operation.action(),
                    relative_name: operation.name().clone(),
                    record_type: operation.record_type(),
                }),
                UpdateOperation::ReplaceSoa { .. } => {
                    caller.authorize_zone_action(Action::ZoneUpdate, &zone)?;
                }
            }
        }

        caller.authorize_record_access(&zone, &accesses)?;

        let plan = plan::UpdatePlan::compute(&zone, updates)?;
        let new_serial = plan.zone.serial;
        let soa_changed = plan.soa_changed;
        let mut changed = soa_changed;
        let mut activities = Vec::new();

        for operation in &plan.records {
            let mutations = operation::apply_record_operation_tx(
                &mut tx, caller, &plan.zone, operation, new_serial,
            )
            .await?;
            changed |= !mutations.is_empty();
            activities.extend(mutations.into_iter().map(|mutation| {
                let (operation, record) = match mutation {
                    RecordMutation::Created(record) => (ActivityOperation::RecordCreate, record),
                    RecordMutation::Updated(record) => (ActivityOperation::RecordUpdate, record),
                    RecordMutation::Deleted(record) => (ActivityOperation::RecordDelete, record),
                };
                (operation, record::activity_target(&plan.zone.name, &record))
            }));
        }

        if changed {
            zone::validate_record_changes_tx(&mut tx, &plan.zone, &[], &[]).await?;

            if soa_changed {
                let changes = zone::soa_replacement_changes(&zone, &plan.zone, new_serial)?;
                bindizr_db::zone_change::create_many_tx(&mut tx, &changes).await?;
            }

            let updated_zone = bindizr_db::zone::update_tx(&mut tx, plan.zone).await?;
            dnssec::sign_zone_tx(&mut tx, &updated_zone, new_serial).await?;
            zone::save_version_tx(&mut tx, &updated_zone, new_serial, caller.change_origin())
                .await?;

            if soa_changed {
                activities.push((
                    ActivityOperation::ZoneUpdate,
                    zone::activity_target(&updated_zone.name),
                ));
            }
            activities.push((
                ActivityOperation::NsupdateApply,
                zone::activity_target(&updated_zone.name),
            ));
            crate::activity::save_operations_tx(&mut tx, activities, caller.change_origin())
                .await?;
        }

        Ok((changed, zone, new_serial))
    }
    .await;

    let (changed, zone, new_serial) =
        transaction::finish_tx(tx, apply_result, "failed to commit NSUPDATE transaction").await?;

    if changed {
        cx.metrics().track_serial_bumps(1);
        log::info!(
            "event=nsupdate_apply zone={} serial={new_serial}",
            zone.name
        );

        // Queue through the service like every other mutation path, so
        // `dns.notify.batch_ms` governs RFC 2136 writes too.
        notify::notify_after_update(cx, &zone.name).await;
    }

    Ok(changed)
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io;

    use super::*;

    /// Verify that parser failures are preserved while retaining their FORMERR classification.
    #[test]
    fn parser_errors_retain_their_sources() {
        let shape = ValidateUpdateShapeError::NonzeroTtl;
        let error = NsupdateError::from(shape);

        assert_eq!(error.rcode().ok(), Some(Rcode::FORMERR));
        assert_eq!(
            error
                .source()
                .unwrap()
                .downcast_ref::<ValidateUpdateShapeError>(),
            Some(&shape)
        );

        let parse = ParseUpdateError::Rdata { record_type: "A" };
        let error = NsupdateError::from(parse.clone());

        assert_eq!(error.rcode().ok(), Some(Rcode::FORMERR));
        assert_eq!(
            error.source().unwrap().downcast_ref::<ParseUpdateError>(),
            Some(&parse)
        );
    }

    /// Verify that caller and backend failures stay typed and reach the transport
    /// unclassified, for it to map their codes.
    #[test]
    fn service_errors_retain_their_sources_and_codes() {
        for source in [
            ServiceError::forbidden("denied"),
            ServiceError::internal_with_source("storage failed", io::Error::other("storage")),
        ] {
            let code = source.code();
            let message = source.to_string();
            let error = NsupdateError::from(source);

            assert_eq!(error.rcode().map_err(ServiceError::code), Err(code));
            assert_eq!(error.to_string(), message);
            let service = error
                .source()
                .unwrap()
                .downcast_ref::<ServiceError>()
                .unwrap();

            if code.is_internal() {
                assert!(service.source().unwrap().is::<io::Error>());
            }
        }
    }
}
