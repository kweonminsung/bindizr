//! Owner-local constraints for a proposed record state, updated only after validation succeeds.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use bindizr_core::dns::Ttl;
use bindizr_core::dns::name::OwnerName;
use bindizr_core::dns::record::{MxRecordValue, WksRecordValue};
use bindizr_core::model::record::{Record, RecordKey, RecordType};

use crate::error::ServiceError;

/// The first TTL and first different TTL preserve the validator's conflict wording
/// even when existing rows already contain a mixed-TTL set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecordSetState {
    first_ttl: Ttl,
    other_ttl: Option<Ttl>,
}

/// Canonical identities and constraints at one owner, independent of row ids.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct OwnerRecords {
    count: usize,
    identities: HashSet<RecordKey>,
    sets: HashMap<RecordType, RecordSetState>,
    wks: HashSet<(Ipv4Addr, u8)>,
    null_mx: bool,
}

/// The existing and accepted candidate records of one operation. Canonicalize each
/// stored identity once instead of scanning and re-encoding it for every addition.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct RecordConstraintIndex {
    owners: HashMap<OwnerName, OwnerRecords>,
}

impl RecordConstraintIndex {
    /// Index the rows left after the operation's proposed deletions.
    pub(crate) fn new<'a>(records: impl IntoIterator<Item = &'a Record>) -> Self {
        let mut index = Self::default();
        for record in records {
            index.insert(record);
        }
        index
    }

    /// Add an existing row or a candidate that passed validation to the proposed state.
    pub(crate) fn insert(&mut self, record: &Record) {
        let owner = self.owners.entry(record.name.clone()).or_default();
        owner.count += 1;
        owner.identities.insert(record.match_key());
        let set = owner
            .sets
            .entry(record.record_type)
            .or_insert(RecordSetState {
                first_ttl: record.ttl,
                other_ttl: None,
            });
        if record.ttl != set.first_ttl && set.other_ttl.is_none() {
            set.other_ttl = Some(record.ttl);
        }
        if record.record_type == RecordType::Wks
            && let Ok(value) = WksRecordValue::parse(&record.value)
        {
            owner.wks.insert(value.address_and_protocol());
        }
        if record.record_type == RecordType::Mx {
            owner.null_mx |= MxRecordValue::parse(&record.value, record.priority)
                .is_ok_and(MxRecordValue::is_null);
        }
    }

    /// Validate an addition without changing the index, preserving owner-local error precedence.
    pub(crate) fn validate(
        &self,
        owner: &OwnerName,
        record_type: RecordType,
        value: &str,
        ttl: Ttl,
        priority: Option<i32>,
    ) -> Result<(), ServiceError> {
        record_type
            .validate_value(value, priority)
            .map_err(ServiceError::invalid_record_value)?;
        if record_type == RecordType::Cname && owner.is_apex() {
            return Err(ServiceError::invalid_record_name(
                "CNAME record cannot have '@' as name",
            ));
        }

        let existing = self.owners.get(owner);
        if existing.is_some_and(|records| {
            records
                .identities
                .contains(&RecordKey::new(owner, record_type, value, priority))
        }) {
            return Err(ServiceError::record_conflict(format!(
                "record '{owner}' {record_type} '{value}' already exists in this zone"
            )));
        }
        if record_type == RecordType::Wks
            && WksRecordValue::parse(value).is_ok_and(|value| {
                existing.is_some_and(|records| records.wks.contains(&value.address_and_protocol()))
            })
        {
            return Err(ServiceError::record_conflict(
                "WKS records at the same name must have distinct addresses or protocols",
            ));
        }
        let has_at_name =
            |wanted| existing.is_some_and(|records| records.sets.contains_key(&wanted));
        if record_type == RecordType::Mx {
            let adding_null_mx =
                MxRecordValue::parse(value, priority).is_ok_and(MxRecordValue::is_null);
            let existing_null_mx = existing.is_some_and(|records| records.null_mx);
            if (adding_null_mx && has_at_name(RecordType::Mx))
                || (!adding_null_mx && existing_null_mx)
            {
                return Err(ServiceError::record_conflict(format!(
                    "null MX record for '{owner}' cannot coexist with other MX records"
                )));
            }
        }
        if existing.is_some_and(|records| records.count != 0) {
            if record_type == RecordType::Cname {
                return Err(ServiceError::record_conflict(format!(
                    "another record with name '{owner}' already exists in this zone, so CNAME cannot be used"
                )));
            }
            if has_at_name(RecordType::Cname) {
                return Err(ServiceError::record_conflict(format!(
                    "a CNAME record with name '{owner}' already exists in this zone"
                )));
            }
        }
        // RFC 6672, Section 2.4: DNAME is a singleton and cannot share a delegation.
        if record_type == RecordType::Dname {
            if has_at_name(RecordType::Dname) {
                return Err(ServiceError::record_conflict(format!(
                    "a DNAME record already exists at '{owner}'; only one DNAME is allowed per name"
                )));
            }
            if !owner.is_apex() && has_at_name(RecordType::Ns) {
                return Err(ServiceError::record_conflict(format!(
                    "a DNAME record cannot share the delegation '{owner}' with NS records"
                )));
            }
        }
        if record_type == RecordType::Ns && !owner.is_apex() && has_at_name(RecordType::Dname) {
            return Err(ServiceError::record_conflict(format!(
                "NS records cannot delegate '{owner}' beside its DNAME record"
            )));
        }
        // RFC 4034, Section 5: the zone's own DS belongs in its parent.
        if record_type == RecordType::Ds && owner.is_apex() {
            return Err(ServiceError::invalid_record_name(
                "DS records secure a child delegation; the zone's own DS belongs in the parent zone",
            ));
        }
        // RFC 2181, Section 5.2: all records of a name and type share one TTL.
        let conflicting = existing
            .and_then(|records| records.sets.get(&record_type))
            .and_then(|set| {
                if ttl != set.first_ttl {
                    Some(set.first_ttl)
                } else {
                    set.other_ttl
                }
            });
        if let Some(conflicting) = conflicting {
            return Err(ServiceError::record_conflict(format!(
                "TTL {ttl} does not match the existing {record_type} records for '{owner}' (TTL {conflicting}); records sharing a name and type share one TTL"
            )));
        }
        Ok(())
    }
}
