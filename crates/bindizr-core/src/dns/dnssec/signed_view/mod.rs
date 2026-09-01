//! The signed view: the derived DNSSEC plane a zone's records imply, computed
//! whole and diffed against the stored plane. Signatures are reused while
//! their RRset, signer set, and validity are unchanged, so the diff — the
//! IXFR delta — carries only real changes; a rollover state transition
//! re-signs exactly the affected RRsets through the same digests.

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use domain::{
    base::{
        Record as WireRecord, Ttl, UnknownRecordData,
        iana::{Class, Rtype},
        name::FlattenInto,
        rdata::ComposeRecordData,
    },
    crypto::sign::{KeyPair, SecretKeyBytes},
    dep::octseq::Parser,
    dnssec::sign::{
        denial::{
            nsec::{GenerateNsecConfig, generate_nsecs},
            nsec3::{GenerateNsec3Config, Nsec3Records, generate_nsec3s},
        },
        keys::signingkey::SigningKey,
        records::{DefaultSorter, RecordsIter, Rrset},
        signatures::rrsigs::sign_rrset,
    },
    rdata::{ZoneRecordData, dnssec::Timestamp},
};
use sha2::{Digest, Sha256};

use super::{WireName, dnskey_for, ds_rdata_for, to_wire_name};
use crate::{
    dns::{
        name::{OwnerName, ZoneName},
        record::{EncodedRdata, Rdata},
    },
    model::{
        dnssec_key::DnssecKey,
        dnssec_record::{DnssecRecord, DnssecRecordType},
        record::Record,
        zone::{DnssecDenial, Zone},
    },
};

type SignRecord = WireRecord<WireName, ZoneRecordData<Vec<u8>, WireName>>;

pub struct SignedViewParams<'a> {
    pub zone: &'a Zone,
    pub new_serial: i32,
    pub records: &'a [Record],
    pub keys: &'a [DnssecKey],
    /// The stored derived plane, the reuse source and diff baseline.
    pub prev: &'a [DnssecRecord],
    pub denial: DnssecDenial,
    pub now: DateTime<Utc>,
    pub inception: DateTime<Utc>,
    /// The latest expiration a new signature takes; each RRset lands up to
    /// `expiration_jitter_secs` earlier.
    pub expiration: DateTime<Utc>,
    pub expiration_jitter_secs: i64,
    /// Re-sign when a stored signature expires within this window.
    pub refresh_secs: i64,
    /// Ignore stored signatures entirely (manual re-sign).
    pub force: bool,
    /// Publish the RFC 8078 delete CDS/CDNSKEY pair instead of per-key ones,
    /// asking the parent to drop the zone's DS RRset.
    pub withdraw_parent_ds: bool,
}

impl SignedViewParams<'_> {
    /// The RRset's slot in the jitter window, taken from its identity rather
    /// than drawn at random: [`Self::compute`] stays a function of its
    /// inputs, and an RRset keeps its slot across re-signings.
    fn expiration_for(&self, owner: &WireName, covered: i32) -> DateTime<Utc> {
        if self.expiration_jitter_secs <= 0 {
            return self.expiration;
        }

        let mut hasher = Sha256::new();
        hasher.update(owner.as_slice());
        hasher.update(covered.to_be_bytes());
        let slot = u64::from_be_bytes(
            hasher.finalize()[..8]
                .try_into()
                .expect("8 bytes of digest"),
        );
        self.expiration
            - chrono::Duration::seconds((slot % self.expiration_jitter_secs as u64) as i64)
    }

    /// Compute the signed view these params describe.
    pub fn compute(&self) -> Result<SignedViewDiff, String> {
        let zone = self.zone;
        let apex = to_wire_name(zone.name.to_wire())?;

        let signers = self
            .keys
            .iter()
            .map(|key| Signer::new(&apex, key))
            .collect::<Result<Vec<_>, _>>()?;
        let key_signers: Vec<&Signer<'_>> = signers
            .iter()
            .filter(|s| s.key.signs_key_rrsets())
            .collect();
        let data_signers: Vec<&Signer<'_>> = signers
            .iter()
            .filter(|s| s.key.signs_zone_data(self.keys))
            .collect();
        if !signers.is_empty() && (key_signers.is_empty() || data_signers.is_empty()) {
            return Err(
                "zone has keys but no usable signer for the key RRsets or the zone data"
                    .to_string(),
            );
        }

        let input = build_signing_input(self, &apex, &signers)?;

        let mut new_rows: Vec<DnssecRecord> = Vec::new();
        let denial_records = denial_records(&apex, &input, self.denial)?;

        // Rows for everything the signer owns: the apex key RRsets from `input`
        // and the denial chain. User records and the SOA stay in their own planes.
        for record in input.iter().filter(|r| is_key_rrset_type(r.rtype())) {
            new_rows.push(DnssecRecord {
                id: 0,
                zone_id: zone.id,
                name: OwnerName::apex(),
                record_type: derived_record_type(record.rtype())?,
                covered_record_type: None,
                ttl: record.ttl().as_secs() as i32,
                rdata: to_rdata(record.data()),
                expires_at: None,
                rrset_digest: None,
            });
        }
        for record in &denial_records {
            new_rows.push(DnssecRecord {
                id: 0,
                zone_id: zone.id,
                name: owner_in_zone(record.owner(), &zone.name)?,
                record_type: derived_record_type(record.rtype())?,
                covered_record_type: None,
                ttl: record.ttl().as_secs() as i32,
                rdata: to_rdata(record.data()),
                expires_at: None,
                rrset_digest: None,
            });
        }

        // RRsets to sign: every authoritative RRset. At a delegation the parent
        // signs only the DS RRset; the NS beside it and glue at or below the cut
        // are served but not signed (RFC 4035, Section 2.2).
        let delegations: BTreeSet<Vec<u8>> = input
            .iter()
            .filter(|r| r.rtype() == Rtype::NS && *r.owner() != apex)
            .map(|r| r.owner().as_slice().to_vec())
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
        signable.retain(|rrset| {
            let owner = rrset[0].owner();
            if delegations.contains(owner.as_slice()) {
                return rrset[0].rtype() == Rtype::DS;
            }
            !is_below_cut(owner, &apex, &delegations)
        });
        for record in &denial_records {
            signable.push(vec![record]);
        }

        // Index stored signatures for reuse: (owner, covered type) → rows.
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
        for rrset in &signable {
            let owner = owner_in_zone(rrset[0].owner(), &zone.name)?;
            let covered = rrset[0].rtype().to_int() as i32;
            // The apex key RRsets must be signed by keys the parent DS names
            // (RFC 7344, Section 4.1 for CDS/CDNSKEY); everything else by the
            // active zone-data keys.
            let rrset_signers: &[&Signer<'_>] =
                if *rrset[0].owner() == apex && is_key_rrset_type(rrset[0].rtype()) {
                    &key_signers
                } else {
                    &data_signers
                };
            let digest = rrset_digest(rrset_signers, rrset);

            let reusable = if self.force {
                None
            } else {
                prev_rrsigs
                    .get(&(owner.to_stored(), covered))
                    .filter(|rows| {
                        rows.len() == rrset_signers.len()
                            && rows.iter().all(|row| {
                                row.rrset_digest.as_deref() == Some(digest.as_str())
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
                    let expiration = self.expiration_for(rrset[0].owner(), covered);
                    for signer in rrset_signers {
                        let rrsig = signer.sign_rrset(rrset, self.inception, expiration)?;
                        new_rows.push(DnssecRecord {
                            id: 0,
                            zone_id: zone.id,
                            name: owner.clone(),
                            record_type: DnssecRecordType::Rrsig,
                            covered_record_type: Some(covered),
                            ttl: rrsig.ttl().as_secs() as i32,
                            rdata: to_rdata(rrsig.data()),
                            expires_at: Some(expiration),
                            rrset_digest: Some(digest.clone()),
                        });
                    }
                }
            }
        }

        Ok(SignedViewDiff::from_planes(self.prev, new_rows))
    }
}

/// The derived plane's change set. Rows in neither list are stored and
/// current; `removed` rows carry their database ids.
pub struct SignedViewDiff {
    pub added: Vec<DnssecRecord>,
    pub removed: Vec<DnssecRecord>,
}

impl SignedViewDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    fn from_planes(prev: &[DnssecRecord], new_rows: Vec<DnssecRecord>) -> SignedViewDiff {
        let identity = |row: &DnssecRecord| {
            (
                row.name.to_stored(),
                row.record_type,
                row.ttl,
                row.rdata.clone(),
            )
        };

        let mut remaining: BTreeMap<(String, DnssecRecordType, i32, Rdata), Vec<DnssecRecord>> =
            BTreeMap::new();
        for row in prev {
            remaining
                .entry(identity(row))
                .or_default()
                .push(row.clone());
        }

        let mut added = Vec::new();
        for row in new_rows {
            match remaining.get_mut(&identity(&row)) {
                Some(rows) if !rows.is_empty() => {
                    rows.pop();
                }
                _ => added.push(row),
            }
        }
        let removed = remaining.into_values().flatten().collect();

        SignedViewDiff { added, removed }
    }
}

fn derived_record_type(rtype: Rtype) -> Result<DnssecRecordType, String> {
    DnssecRecordType::try_from(rtype.to_int() as i32)
}

fn is_key_rrset_type(rtype: Rtype) -> bool {
    matches!(rtype, Rtype::DNSKEY | Rtype::CDS | Rtype::CDNSKEY)
}

/// Content identity for signature reuse; any component changing must force
/// a fresh signature.
fn rrset_digest(signers: &[&Signer<'_>], rrset: &[&SignRecord]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rrset[0].owner().as_slice());
    hasher.update(rrset[0].rtype().to_int().to_be_bytes());
    hasher.update(rrset[0].ttl().as_secs().to_be_bytes());

    let mut rdatas: Vec<Rdata> = rrset.iter().map(|r| to_rdata(r.data())).collect();
    rdatas.sort();
    for rdata in rdatas {
        hasher.update((rdata.as_bytes().len() as u32).to_be_bytes());
        hasher.update(rdata.as_bytes());
    }
    for signer in signers {
        // Key tags are 16 bits and can collide across a rollover; the row id
        // pins the actual signing key so a stale signature cannot be reused.
        hasher.update(signer.key.id.to_be_bytes());
        hasher.update(signer.key_tag.to_be_bytes());
        hasher.update([signer.algorithm]);
    }
    hex::encode(hasher.finalize())
}

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

fn owner_in_zone(owner: &WireName, zone: &ZoneName) -> Result<OwnerName, String> {
    OwnerName::parse_absolute_in_zone(&owner.to_string(), zone).map_err(|e| {
        format!(
            "derived owner '{}' is not inside zone '{}': {}",
            owner, zone, e
        )
    })
}

/// A key loaded into signing form together with its DNSKEY RDATA.
struct Signer<'a> {
    key: &'a DnssecKey,
    signing_key: SigningKey<Vec<u8>, KeyPair>,
    dnskey: domain::rdata::Dnskey<Vec<u8>>,
    key_tag: u16,
    algorithm: u8,
}

impl<'a> Signer<'a> {
    fn new(apex: &WireName, key: &'a DnssecKey) -> Result<Self, String> {
        let dnskey = dnskey_for(key)?;
        let secret = SecretKeyBytes::parse_from_bind(&key.private_key)
            .map_err(|e| format!("stored private key is invalid: {}", e))?;
        let key_pair = KeyPair::from_bytes(&secret, &dnskey)
            .map_err(|e| format!("failed to load signing key: {}", e))?;
        Ok(Signer {
            key,
            signing_key: SigningKey::new(apex.clone(), key.role.flags(), key_pair),
            key_tag: dnskey.key_tag(),
            algorithm: key.algorithm.to_int() as u8,
            dnskey,
        })
    }

    fn sign_rrset(
        &self,
        rrset: &[&SignRecord],
        inception: DateTime<Utc>,
        expiration: DateTime<Utc>,
    ) -> Result<WireRecord<WireName, domain::rdata::Rrsig<Vec<u8>, WireName>>, String> {
        let rrset = Rrset::new_from_refs(rrset).map_err(|e| format!("invalid RRset: {}", e))?;
        sign_rrset(
            &self.signing_key,
            &rrset,
            Timestamp::from(inception.timestamp() as u32),
            Timestamp::from(expiration.timestamp() as u32),
        )
        .map_err(|e| format!("signing failed: {}", e))
    }
}

/// User records, the synthesized SOA, and the apex key RRsets in canonical
/// order — the exact content the chain and the signatures must cover.
fn build_signing_input(
    params: &SignedViewParams<'_>,
    apex: &WireName,
    signers: &[Signer<'_>],
) -> Result<Vec<SignRecord>, String> {
    let zone = params.zone;
    let mut input: Vec<SignRecord> = Vec::new();

    let soa_bytes = zone.soa_rdata(params.new_serial as u32)?;
    input.push(WireRecord::new(
        apex.clone(),
        Class::IN,
        Ttl::from_secs(zone.default_ttl as u32),
        ZoneRecordData::Soa(parse_soa(soa_bytes.as_bytes())?),
    ));

    for signer in signers {
        input.push(WireRecord::new(
            apex.clone(),
            Class::IN,
            Ttl::from_secs(zone.default_ttl as u32),
            ZoneRecordData::Dnskey(signer.dnskey.clone()),
        ));
        if signer.key.wants_parent_ds() && !params.withdraw_parent_ds {
            let cds = UnknownRecordData::from_octets(
                Rtype::CDS,
                ds_rdata_for(signer.key, apex)?.into_bytes(),
            )
            .map_err(|e| format!("invalid CDS rdata: {}", e))?;
            input.push(WireRecord::new(
                apex.clone(),
                Class::IN,
                Ttl::from_secs(zone.default_ttl as u32),
                ZoneRecordData::Unknown(cds),
            ));
            let cdnskey = UnknownRecordData::from_octets(
                Rtype::CDNSKEY,
                to_rdata(&signer.dnskey).into_bytes(),
            )
            .map_err(|e| format!("invalid CDNSKEY rdata: {}", e))?;
            input.push(WireRecord::new(
                apex.clone(),
                Class::IN,
                Ttl::from_secs(zone.default_ttl as u32),
                ZoneRecordData::Unknown(cdnskey),
            ));
        }
    }

    // RFC 8078, Section 4: the 0-algorithm pair asks the parent to delete
    // the DS RRset entirely.
    if params.withdraw_parent_ds && !signers.is_empty() {
        let cds = UnknownRecordData::from_octets(Rtype::CDS, vec![0, 0, 0, 0, 0])
            .map_err(|e| format!("invalid CDS rdata: {}", e))?;
        input.push(WireRecord::new(
            apex.clone(),
            Class::IN,
            Ttl::from_secs(zone.default_ttl as u32),
            ZoneRecordData::Unknown(cds),
        ));
        let cdnskey = UnknownRecordData::from_octets(Rtype::CDNSKEY, vec![0, 0, 3, 0, 0])
            .map_err(|e| format!("invalid CDNSKEY rdata: {}", e))?;
        input.push(WireRecord::new(
            apex.clone(),
            Class::IN,
            Ttl::from_secs(zone.default_ttl as u32),
            ZoneRecordData::Unknown(cdnskey),
        ));
    }

    for record in params.records {
        let EncodedRdata { record_type, rdata } =
            EncodedRdata::from_columns(&record.record_type, &record.value, record.priority)?;
        let data = UnknownRecordData::from_octets(Rtype::from_int(record_type), rdata.into_bytes())
            .map_err(|e| format!("invalid record rdata: {}", e))?;
        let owner = to_wire_name(record.name.to_wire(&zone.name))?;
        input.push(WireRecord::new(
            owner,
            Class::IN,
            Ttl::from_secs(record.ttl as u32),
            ZoneRecordData::Unknown(data),
        ));
    }

    // An RRset shares one TTL (RFC 2181, Section 5.2); normalize stragglers to
    // the set's minimum so RRset construction and Original TTL are well-defined.
    let mut rrset_ttls: BTreeMap<(Vec<u8>, u16), Ttl> = BTreeMap::new();
    for record in &input {
        let key = (record.owner().as_slice().to_vec(), record.rtype().to_int());
        let entry = rrset_ttls.entry(key).or_insert_with(|| record.ttl());
        *entry = (*entry).min(record.ttl());
    }
    for record in &mut input {
        let key = (record.owner().as_slice().to_vec(), record.rtype().to_int());
        record.set_ttl(rrset_ttls[&key]);
    }

    input.sort_by(|a, b| {
        use domain::base::cmp::CanonicalOrd;
        a.canonical_cmp(b)
    });

    Ok(input)
}

/// The typed SOA the denial generators require (they read MINIMUM per
/// RFC 9077), parsed back from the one byte encoding the transfer serves.
fn parse_soa(rdata: &[u8]) -> Result<domain::rdata::Soa<WireName>, String> {
    let mut parser = Parser::from_ref(rdata);
    domain::rdata::Soa::parse(&mut parser)
        .map_err(|e| format!("invalid SOA rdata: {}", e))?
        .try_flatten_into()
        .map_err(|e| format!("invalid SOA rdata: {}", e))
}

/// The complete denial chain for `input` (canonical order): NSEC records, or
/// the NSEC3 chain plus its NSEC3PARAM. The chain is cheap to rebuild whole,
/// and doing so removes incremental chain-repair edge cases entirely
/// (RFC 9077 TTLs and zone cuts included).
fn denial_records(
    apex: &WireName,
    input: &[SignRecord],
    denial: DnssecDenial,
) -> Result<Vec<SignRecord>, String> {
    fn into_sign_record<D>(
        record: WireRecord<WireName, D>,
        wrap: impl FnOnce(D) -> ZoneRecordData<Vec<u8>, WireName>,
    ) -> SignRecord {
        let class = record.class();
        let ttl = record.ttl();
        let (owner, data) = record.into_owner_and_data();
        WireRecord::new(owner, class, ttl, wrap(data))
    }

    let mut records = Vec::new();
    if denial == DnssecDenial::Nsec3 {
        // GenerateNsec3Config::default() is the RFC 9276 profile: SHA-1, zero
        // iterations, no salt, no opt-out.
        let Nsec3Records { nsec3s, nsec3param } = generate_nsec3s(
            apex,
            RecordsIter::new_from_owned(input),
            &GenerateNsec3Config::<Vec<u8>, DefaultSorter>::default(),
        )
        .map_err(|e| format!("NSEC3 generation failed: {}", e))?;

        for nsec3 in nsec3s {
            records.push(into_sign_record(nsec3, ZoneRecordData::Nsec3));
        }
        records.push(into_sign_record(nsec3param, ZoneRecordData::Nsec3param));
    } else {
        let nsecs = generate_nsecs(
            apex,
            RecordsIter::new_from_owned(input),
            &GenerateNsecConfig::new(),
        )
        .map_err(|e| format!("NSEC generation failed: {}", e))?;
        for nsec in nsecs {
            records.push(into_sign_record(nsec, ZoneRecordData::Nsec));
        }
    }
    Ok(records)
}

/// Wire RDATA of `data`, without the length prefix. Composed protocol values
/// are bounded well under the RDLENGTH limit, so the cap cannot trip here.
fn to_rdata<D: ComposeRecordData>(data: &D) -> Rdata {
    let mut bytes = Vec::new();
    data.compose_rdata(&mut bytes)
        .expect("composing into a Vec cannot run out of space");
    Rdata::new(bytes).expect("composed RDATA exceeds the RDLENGTH limit")
}
