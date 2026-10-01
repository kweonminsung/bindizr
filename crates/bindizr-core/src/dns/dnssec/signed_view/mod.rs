//! Compute the DNSSEC plane and diff it against storage for IXFR.
//! Reuse signatures while their record set, signer set, and validity are unchanged;
//! rollovers re-sign only the affected sets.

mod input;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use domain::{
    base::{iana::Rtype, rdata::ComposeRecordData},
    crypto::sign::{KeyPair, SecretKeyBytes},
    dnssec::sign::{keys::signingkey::SigningKey, records::Rrset, signatures::rrsigs::sign_rrset},
    rdata::{ZoneRecordData, dnssec::Timestamp},
};
use input::denial_records;
use ring::digest::{Context, SHA256};
use thiserror::Error;

use super::{WireName, WireRecord};
use crate::{
    dns::{
        ConvertTtlError, LibraryError, Serial, Ttl,
        dnssec::{KeyRdataError, KeyTag, WireNameError},
        name::{OwnerName, ParseNameError, ZoneName},
        record::{EncodeRdataError, Rdata},
    },
    model::{
        dnssec_key::DnssecKey,
        dnssec_policy::DnssecDenial,
        dnssec_record::{
            DnssecRecord, DnssecRecordId, DnssecRecordKey, DnssecRecordType,
            ParseDnssecRecordTypeError,
        },
        record::Record,
        zone::Zone,
    },
};

type SignRecord = WireRecord<ZoneRecordData<Vec<u8>, WireName>>;

/// Why a zone's signed view could not be computed.
#[derive(Debug, Error)]
pub enum SignZoneError {
    #[error("zone has keys but no usable signer for the key records or the zone data")]
    NoUsableSigner,
    #[error(transparent)]
    Ttl(#[from] ConvertTtlError),
    #[error("derived owner '{owner}' is not inside zone '{zone}': {source}")]
    OwnerOutsideZone {
        owner: String,
        zone: String,
        #[source]
        source: ParseNameError,
    },
    #[error("stored private key is invalid: {0}")]
    PrivateKey(#[source] LibraryError),
    #[error("failed to load signing key: {0}")]
    LoadKey(#[source] LibraryError),
    /// The `domain` signer's errors implement no `Error`, so their text is
    /// what is kept.
    #[error("mismatched records for one name and type: {reason}")]
    MismatchedRecordSet { reason: String },
    #[error("signing failed: {reason}")]
    Sign { reason: String },
    #[error("invalid {rtype} rdata: {source}")]
    Rdata {
        rtype: &'static str,
        #[source]
        source: LibraryError,
    },
    #[error("invalid SOA rdata: {0}")]
    Soa(#[source] LibraryError),
    #[error("NSEC3 generation failed: {reason}")]
    Nsec3 { reason: String },
    #[error("NSEC generation failed: {reason}")]
    Nsec { reason: String },
    #[error(transparent)]
    WireName(#[from] WireNameError),
    #[error(transparent)]
    Key(#[from] KeyRdataError),
    #[error(transparent)]
    EncodeRdata(#[from] EncodeRdataError),
    #[error(transparent)]
    RecordType(#[from] ParseDnssecRecordTypeError),
}

/// What a signing pass regenerates: the signatures expiring within the
/// refresh window, or every one (a manual re-sign).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningPass {
    Refresh,
    Full,
}

#[derive(Debug, Clone, Copy)]
pub struct SignedViewParams<'a> {
    pub zone: &'a Zone,
    pub new_serial: Serial,
    pub records: &'a [Record],
    pub keys: &'a [DnssecKey],
    /// The stored derived plane, the reuse source and diff baseline.
    pub prev: &'a [DnssecRecord],
    pub denial: DnssecDenial,
    pub now: DateTime<Utc>,
    pub inception: DateTime<Utc>,
    /// The latest expiration a new signature takes; each record set lands up to
    /// `expiration_jitter_secs` earlier.
    pub expiration: DateTime<Utc>,
    pub expiration_jitter_secs: i64,
    /// Re-sign when a stored signature expires within this window.
    pub refresh_secs: i64,
    pub pass: SigningPass,
    /// Publish the RFC 8078 delete CDS/CDNSKEY pair instead of per-key ones,
    /// asking the parent to drop the zone's DS record set.
    pub withdraw_parent_ds: bool,
}

impl SignedViewParams<'_> {
    /// The record set's slot in the jitter window, taken from its identity rather
    /// than drawn at random: [`Self::compute`] stays a function of its
    /// inputs, and a record set keeps its slot across re-signings.
    fn record_set_expiration(&self, owner: &WireName, covered: i32) -> DateTime<Utc> {
        if self.expiration_jitter_secs <= 0 {
            return self.expiration;
        }

        let mut hasher = Context::new(&SHA256);
        hasher.update(owner.as_slice());
        hasher.update(&covered.to_be_bytes());
        // The leading eight digest bytes, read big-endian.
        let slot = hasher
            .finish()
            .as_ref()
            .iter()
            .take(8)
            .fold(0u64, |slot, byte| (slot << 8) | u64::from(*byte));
        self.expiration
            - chrono::Duration::seconds((slot % self.expiration_jitter_secs as u64) as i64)
    }

    /// Compute the signed DNSSEC view and its changes from the previous view.
    pub fn compute(&self) -> Result<SignedViewDiff, SignZoneError> {
        let zone = self.zone;
        let apex = zone.name.to_wire_name()?;

        let signers = self
            .keys
            .iter()
            .map(|key| Signer::new(&apex, key))
            .collect::<Result<Vec<_>, _>>()?;
        let key_signers: Vec<&Signer<'_>> = signers
            .iter()
            .filter(|s| s.key.signs_key_record_sets())
            .collect();
        let data_signers: Vec<&Signer<'_>> = signers
            .iter()
            .filter(|s| s.key.signs_zone_data(self.keys))
            .collect();
        if !signers.is_empty() && (key_signers.is_empty() || data_signers.is_empty()) {
            return Err(SignZoneError::NoUsableSigner);
        }

        let input = self.signing_input(&apex, &signers)?;

        let mut new_rows: Vec<DnssecRecord> = Vec::new();
        let denial_records = denial_records(&apex, &input, self.denial)?;

        // Rows for everything the signer owns: the apex key record sets from `input`
        // and the denial chain. User records and the SOA stay in their own planes.
        for record in input.iter().filter(|record| is_key_rtype(record.rtype())) {
            new_rows.push(DnssecRecord {
                id: DnssecRecordId::UNWRITTEN,
                zone_id: zone.id,
                name: OwnerName::apex(),
                record_type: DnssecRecordType::try_from(record.rtype())?,
                covered_record_type: None,
                ttl: Ttl::try_from(record.ttl().as_secs())?,
                rdata: to_rdata(record.data())?,
                expires_at: None,
                record_set_digest: None,
            });
        }
        for record in &denial_records {
            new_rows.push(DnssecRecord {
                id: DnssecRecordId::UNWRITTEN,
                zone_id: zone.id,
                name: parse_derived_owner(record.owner(), &zone.name)?,
                record_type: DnssecRecordType::try_from(record.rtype())?,
                covered_record_type: None,
                ttl: Ttl::try_from(record.ttl().as_secs())?,
                rdata: to_rdata(record.data())?,
                expires_at: None,
                record_set_digest: None,
            });
        }

        // Record sets to sign: every authoritative record set. At a delegation the parent
        // signs only the DS record set; the NS beside it and glue at or below the cut
        // are served but not signed (RFC 4035, Section 2.2).
        let delegations: BTreeSet<Vec<u8>> = input
            .iter()
            .filter(|record| record.rtype() == Rtype::NS && *record.owner() != apex)
            .map(|record| record.owner().as_slice().to_vec())
            .collect();

        let mut signable: Vec<Vec<&SignRecord>> = Vec::new();
        let mut current: Vec<&SignRecord> = Vec::new();
        for record in &input {
            if let Some(last) = current.last()
                && (last.owner() != record.owner() || last.rtype() != record.rtype())
            {
                signable.push(std::mem::take(&mut current));
            }
            current.push(record);
        }
        if !current.is_empty() {
            signable.push(current);
        }
        signable.retain(|record_set| {
            let owner = record_set[0].owner();
            if delegations.contains(owner.as_slice()) {
                return record_set[0].rtype() == Rtype::DS;
            }
            !is_below_cut(owner, &apex, &delegations)
        });
        for record in &denial_records {
            signable.push(vec![record]);
        }

        // Index stored signatures by owner and covered type for record set reuse.
        let mut prev_rrsigs: BTreeMap<(String, i32), Vec<&DnssecRecord>> = BTreeMap::new();
        for row in self.prev {
            if row.record_type == DnssecRecordType::Rrsig
                && let Some(covered) = row.covered_record_type
            {
                prev_rrsigs
                    .entry((row.name.to_stored(), covered))
                    .or_default()
                    .push(row);
            }
        }

        let refresh_cutoff = self.now + chrono::Duration::seconds(self.refresh_secs);
        for record_set in &signable {
            let owner = parse_derived_owner(record_set[0].owner(), &zone.name)?;
            let covered = i32::from(record_set[0].rtype().to_int());
            // The apex key record sets must be signed by keys the parent DS names
            // (RFC 7344, Section 4.1 for CDS/CDNSKEY); everything else by the
            // active zone-data keys.
            let record_set_signers: &[&Signer<'_>] =
                if *record_set[0].owner() == apex && is_key_rtype(record_set[0].rtype()) {
                    &key_signers
                } else {
                    &data_signers
                };
            let digest = record_set_digest(record_set_signers, record_set)?;

            // Reuse only a complete, unchanged set of signatures that outlives
            // the refresh window; a forced pass regenerates every signature.
            let reusable = if self.pass == SigningPass::Full {
                None
            } else {
                prev_rrsigs
                    .get(&(owner.to_stored(), covered))
                    .filter(|rows| {
                        rows.len() == record_set_signers.len()
                            && rows.iter().all(|row| {
                                row.record_set_digest.as_deref() == Some(digest.as_str())
                                    && row
                                        .expires_at
                                        .is_some_and(|expires| expires > refresh_cutoff)
                            })
                    })
            };

            match reusable {
                Some(rows) => {
                    for row in rows {
                        new_rows.push((*row).clone());
                    }
                }
                None => {
                    let expiration = self.record_set_expiration(record_set[0].owner(), covered);
                    for signer in record_set_signers {
                        let rrsig = signer.sign_rrset(record_set, self.inception, expiration)?;
                        new_rows.push(DnssecRecord {
                            id: DnssecRecordId::UNWRITTEN,
                            zone_id: zone.id,
                            name: owner.clone(),
                            record_type: DnssecRecordType::Rrsig,
                            covered_record_type: Some(covered),
                            ttl: Ttl::try_from(rrsig.ttl().as_secs())?,
                            rdata: to_rdata(rrsig.data())?,
                            expires_at: Some(expiration),
                            record_set_digest: Some(digest.clone()),
                        });
                    }
                }
            }
        }

        // Diff the complete derived plane so unchanged rows keep their storage identity.
        Ok(SignedViewDiff::from_planes(self.prev, new_rows))
    }
}

/// The derived plane's change set. Rows in neither list are stored and
/// current; `removed` rows carry their database ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedViewDiff {
    pub added: Vec<DnssecRecord>,
    pub removed: Vec<DnssecRecord>,
}

impl SignedViewDiff {
    /// Check whether the signed view has no added or removed records.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    /// Compare derived record identities to find additions and removals.
    fn from_planes(prev: &[DnssecRecord], new_rows: Vec<DnssecRecord>) -> SignedViewDiff {
        let mut remaining: BTreeMap<DnssecRecordKey, Vec<DnssecRecord>> = BTreeMap::new();
        for record in prev {
            remaining
                .entry(record.match_key())
                .or_default()
                .push(record.clone());
        }

        let mut added = Vec::new();
        for record in new_rows {
            match remaining.get_mut(&record.match_key()) {
                Some(rows) if !rows.is_empty() => {
                    rows.pop();
                }
                _ => added.push(record),
            }
        }
        let removed = remaining.into_values().flatten().collect();

        SignedViewDiff { added, removed }
    }
}

/// Check whether a type carries DNSKEY, CDS, or CDNSKEY data.
fn is_key_rtype(rtype: Rtype) -> bool {
    matches!(rtype, Rtype::DNSKEY | Rtype::CDS | Rtype::CDNSKEY)
}

/// Content identity for signature reuse; any component changing must force
/// a fresh signature.
fn record_set_digest(
    signers: &[&Signer<'_>],
    record_set: &[&SignRecord],
) -> Result<String, EncodeRdataError> {
    let mut hasher = Context::new(&SHA256);
    hasher.update(record_set[0].owner().as_slice());
    hasher.update(&record_set[0].rtype().to_int().to_be_bytes());
    hasher.update(&record_set[0].ttl().as_secs().to_be_bytes());

    let mut rdatas: Vec<Rdata> = record_set
        .iter()
        .map(|record| to_rdata(record.data()))
        .collect::<Result<_, _>>()?;
    rdatas.sort();
    for rdata in rdatas {
        hasher.update(&(rdata.as_bytes().len() as u32).to_be_bytes());
        hasher.update(rdata.as_bytes());
    }
    for signer in signers {
        // Key tags are 16 bits and can collide across a rollover; the row id
        // pins the actual signing key so a stale signature cannot be reused.
        hasher.update(&i32::from(signer.key.id).to_be_bytes());
        hasher.update(&signer.key_tag.as_u16().to_be_bytes());
        hasher.update(&[signer.algorithm]);
    }
    Ok(hex::encode(hasher.finish()))
}

/// Check whether an owner lies below a delegation in this zone.
fn is_below_cut(owner: &WireName, apex: &WireName, delegations: &BTreeSet<Vec<u8>>) -> bool {
    // Walk proper ancestors of `owner` down to (excluding) the apex; the name
    // is glue if any of them is a delegation point.
    let mut ancestor = owner.parent();
    while let Some(name) = ancestor {
        if name == *apex {
            return false;
        }
        if delegations.contains(name.as_slice()) {
            return true;
        }
        ancestor = name.parent();
    }
    false
}

/// Convert a derived absolute owner to a name relative to its zone.
fn parse_derived_owner(owner: &WireName, zone_name: &ZoneName) -> Result<OwnerName, SignZoneError> {
    OwnerName::parse_absolute_in_zone(&owner.to_string(), zone_name).map_err(|source| {
        SignZoneError::OwnerOutsideZone {
            owner: owner.to_string(),
            zone: zone_name.to_string(),
            source,
        }
    })
}

/// A key loaded into signing form together with its DNSKEY RDATA.
#[derive(Debug)]
pub(crate) struct Signer<'a> {
    key: &'a DnssecKey,
    signing_key: SigningKey<Vec<u8>, KeyPair>,
    dnskey: domain::rdata::Dnskey<Vec<u8>>,
    key_tag: KeyTag,
    algorithm: u8,
}

impl<'a> Signer<'a> {
    /// Load a stored DNSSEC key into a signer for the zone apex.
    fn new(apex: &WireName, key: &'a DnssecKey) -> Result<Self, SignZoneError> {
        let dnskey = key.to_dnskey()?;
        let secret = SecretKeyBytes::parse_from_bind(&key.private_key)
            .map_err(|e| SignZoneError::PrivateKey(Box::new(e)))?;
        let key_pair = KeyPair::from_bytes(&secret, &dnskey)
            .map_err(|e| SignZoneError::LoadKey(Box::new(e)))?;
        Ok(Signer {
            key,
            signing_key: SigningKey::new(apex.clone(), key.role.flags(), key_pair),
            key_tag: KeyTag::from(dnskey.key_tag()),
            algorithm: key.algorithm.to_int() as u8,
            dnskey,
        })
    }

    /// Sign one record set for the supplied validity interval.
    fn sign_rrset(
        &self,
        record_set: &[&SignRecord],
        inception: DateTime<Utc>,
        expiration: DateTime<Utc>,
    ) -> Result<WireRecord<domain::rdata::Rrsig<Vec<u8>, WireName>>, SignZoneError> {
        let record_set =
            Rrset::new_from_refs(record_set).map_err(|e| SignZoneError::MismatchedRecordSet {
                reason: e.to_string(),
            })?;
        sign_rrset(
            &self.signing_key,
            &record_set,
            Timestamp::from(inception.timestamp() as u32),
            Timestamp::from(expiration.timestamp() as u32),
        )
        .map_err(|e| SignZoneError::Sign {
            reason: e.to_string(),
        })
    }
}

/// Wire RDATA of `data`, without the length prefix.
fn to_rdata<D: ComposeRecordData>(data: &D) -> Result<Rdata, EncodeRdataError> {
    let mut bytes = Vec::new();
    let Ok(()) = data.compose_rdata(&mut bytes);
    Rdata::new(bytes)
}
