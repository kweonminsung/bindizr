mod keys;
mod reuse;
mod rollover;
mod signing;

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};

use super::*;
use crate::dns::name::{OwnerName, ZoneName};
use crate::model::dnssec_key::{
    DnssecAlgorithm, DnssecKey, DnssecKeyId, DnssecKeyRole, DnssecKeyState,
};
use crate::model::dnssec_policy::DnssecDenial;
use crate::model::dnssec_record::{DnssecRecord, DnssecRecordType};
use crate::model::record::{Record, RecordType};
use crate::model::zone::Zone;

/// Build a signing-key fixture for the test.
fn test_key(zone: &Zone, key_id: i32, role: DnssecKeyRole, state: DnssecKeyState) -> DnssecKey {
    let mut key = DnssecKey::generate(
        zone,
        DnssecAlgorithm::EcdsaP256Sha256,
        role,
        state,
        fixed_now(),
        fixed_now(),
    )
    .unwrap();
    key.id = DnssecKeyId::from(key_id);

    key
}

/// Return the fixed reference time used by signing tests.
fn fixed_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-08-18T00:00:00Z")
        .unwrap()
        .to_utc()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ComputeArgs<'a> {
    zone: &'a Zone,
    records: &'a [Record],
    keys: &'a [DnssecKey],
    prev: &'a [DnssecRecord],
    denial: DnssecDenial,
    new_serial: u32,
    expiration: DateTime<Utc>,
    /// `0` pins every record set to `expiration`; the spread has its own test.
    expiration_jitter_secs: i64,
    pass: SigningPass,
}

/// Compute a signed view using the test's signing parameters.
fn compute(args: ComputeArgs<'_>) -> SignedViewDiff {
    let now = fixed_now();
    SignedViewDiff::compute(SignedViewParams {
        zone: args.zone,
        new_serial: Serial::from(args.new_serial),
        records: args.records,
        keys: args.keys,
        prev: args.prev,
        denial: args.denial,
        now,
        inception: now - Duration::hours(1),
        expiration: args.expiration,
        expiration_jitter_secs: args.expiration_jitter_secs,
        refresh_secs: 5 * 86400,
        pass: args.pass,
        withdraw_parent_ds: false,
    })
    .unwrap()
}

/// Return the default signature expiration for the test clock.
fn default_expiration() -> DateTime<Utc> {
    fixed_now() + Duration::days(14)
}

/// Convert a computed plane to its stored form: rows get distinct ids like the
/// database would assign.
fn to_stored(records: &[DnssecRecord]) -> Vec<DnssecRecord> {
    records
        .iter()
        .enumerate()
        .map(|(index, record)| DnssecRecord {
            id: DnssecRecordId::from(index as i32 + 1),
            ..record.clone()
        })
        .collect()
}

/// Select derived records of the requested DNSSEC type.
fn records_of_type(records: &[DnssecRecord], record_type: DnssecRecordType) -> Vec<&DnssecRecord> {
    records
        .iter()
        .filter(|record| record.record_type == record_type)
        .collect()
}

/// Select signatures for the requested owner and covered type.
fn rrsigs_covering<'a>(
    records: &'a [DnssecRecord],
    owner: &OwnerName,
    covered: i32,
) -> Vec<&'a DnssecRecord> {
    records
        .iter()
        .filter(|record| {
            record.record_type == DnssecRecordType::Rrsig
                && record.covered_record_type == Some(covered)
                && record.name == *owner
        })
        .collect()
}
