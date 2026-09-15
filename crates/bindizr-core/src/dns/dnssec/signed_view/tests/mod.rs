use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};

use super::*;
use crate::{
    dns::{
        dnssec::generate_key,
        name::{OwnerName, ZoneName},
    },
    model::{
        dnssec_key::{DnssecAlgorithm, DnssecKey, DnssecKeyRole, DnssecKeyState},
        dnssec_policy::DnssecDenial,
        dnssec_record::{DnssecRecord, DnssecRecordType},
        record::{Record, RecordType},
        zone::Zone,
    },
};

/// Build a signing-key fixture for the test.
fn test_key(zone: &Zone, id: i32, role: DnssecKeyRole, state: DnssecKeyState) -> DnssecKey {
    let mut key = generate_key(
        zone,
        DnssecAlgorithm::EcdsaP256Sha256,
        role,
        state,
        fixed_now(),
        fixed_now(),
    )
    .unwrap();
    key.id = id;
    key
}

/// Return the fixed reference time used by signing tests.
fn fixed_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-08-18T00:00:00Z")
        .unwrap()
        .to_utc()
}

struct ComputeArgs<'a> {
    zone: &'a Zone,
    records: &'a [Record],
    keys: &'a [DnssecKey],
    prev: &'a [DnssecRecord],
    denial: DnssecDenial,
    new_serial: i32,
    expiration: DateTime<Utc>,
    /// `0` pins every RRset to `expiration`; the spread has its own test.
    expiration_jitter_secs: i64,
    force: bool,
}

/// Compute a signed view using the test's signing parameters.
fn compute(args: ComputeArgs<'_>) -> SignedViewDiff {
    let now = fixed_now();
    SignedViewParams {
        zone: args.zone,
        new_serial: args.new_serial,
        records: args.records,
        keys: args.keys,
        prev: args.prev,
        denial: args.denial,
        now,
        inception: now - Duration::hours(1),
        expiration: args.expiration,
        expiration_jitter_secs: args.expiration_jitter_secs,
        refresh_secs: 5 * 86_400,
        force: args.force,
        withdraw_parent_ds: false,
    }
    .compute()
    .unwrap()
}

/// Return the default signature expiration for the test clock.
fn default_expiration() -> DateTime<Utc> {
    fixed_now() + Duration::days(14)
}

/// Stored form of a computed plane: rows get distinct ids like the database
/// would assign.
fn as_stored(records: &[DnssecRecord]) -> Vec<DnssecRecord> {
    records
        .iter()
        .enumerate()
        .map(|(index, row)| DnssecRecord {
            id: index as i32 + 1,
            ..row.clone()
        })
        .collect()
}

/// Select derived records of the requested DNSSEC type.
fn records_of_type(records: &[DnssecRecord], record_type: DnssecRecordType) -> Vec<&DnssecRecord> {
    records
        .iter()
        .filter(|row| row.record_type == record_type)
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
        .filter(|row| {
            row.record_type == DnssecRecordType::Rrsig
                && row.covered_record_type == Some(covered)
                && row.name == *owner
        })
        .collect()
}

const RECORD_TYPE_SOA: i32 = 6;
const RECORD_TYPE_NS: i32 = 2;
const RECORD_TYPE_A: i32 = 1;
const RECORD_TYPE_DS: i32 = 43;

mod keys;
mod reuse;
mod rollover;
mod signing;
