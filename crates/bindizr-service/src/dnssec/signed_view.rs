//! The signed view: the derived DNSSEC plane a zone's records imply, computed
//! whole and diffed against the stored plane. Signatures are reused while
//! their RRset, signer set, and validity are unchanged, so the diff — the
//! IXFR delta — carries only real changes; a rollover state transition
//! re-signs exactly the affected RRsets through the same digests.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use bindizr_core::dns::{
    name::{OwnerName, ParseNameError, ZoneName},
    record::{EncodedRdata, Rdata},
};
use chrono::{DateTime, Utc};
use domain::{
    base::{
        Name, Record as WireRecord, Ttl, UnknownRecordData,
        iana::{Class, Rtype, SecurityAlgorithm},
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

use crate::{
    error::ServiceError,
    model::{
        dnssec_key::DnssecKey,
        dnssec_record::{DnssecRecord, DnssecRecordType},
        record::Record,
        zone::{DnssecDenial, Zone},
    },
};

pub(super) type WireName = Name<Vec<u8>>;

type SignRecord = WireRecord<WireName, ZoneRecordData<Vec<u8>, WireName>>;

/// DS digest type 2 = SHA-256 (RFC 4509), the one digest bindizr emits.
pub(super) const DS_DIGEST_TYPE_SHA256: u8 = 2;

pub(super) struct SignedViewParams<'a> {
    pub(super) zone: &'a Zone,
    pub(super) new_serial: i32,
    pub(super) records: &'a [Record],
    pub(super) keys: &'a [DnssecKey],
    /// The stored derived plane, the reuse source and diff baseline.
    pub(super) prev: &'a [DnssecRecord],
    pub(super) denial: DnssecDenial,
    pub(super) now: DateTime<Utc>,
    pub(super) inception: DateTime<Utc>,
    /// The latest expiration a new signature takes; each RRset lands up to
    /// `expiration_jitter_secs` earlier.
    pub(super) expiration: DateTime<Utc>,
    pub(super) expiration_jitter_secs: i64,
    /// Re-sign when a stored signature expires within this window.
    pub(super) refresh_secs: i64,
    /// Ignore stored signatures entirely (manual re-sign).
    pub(super) force: bool,
}

/// The derived plane's change set. Rows in neither list are stored and
/// current; `removed` rows carry their database ids.
pub(super) struct SignedViewDiff {
    pub(super) added: Vec<DnssecRecord>,
    pub(super) removed: Vec<DnssecRecord>,
}

impl SignedViewDiff {
    pub(super) fn is_empty(&self) -> bool {
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

pub(super) fn compute_signed_view(
    params: &SignedViewParams<'_>,
) -> Result<SignedViewDiff, ServiceError> {
    let zone = params.zone;
    let apex = to_wire_name(zone.name.to_wire()).map_err(signing_internal)?;

    let signers = params
        .keys
        .iter()
        .map(|key| Signer::new(&apex, key))
        .collect::<Result<Vec<_>, _>>()?;
    let key_signers: Vec<&Signer> = signers
        .iter()
        .filter(|s| s.key.signs_key_rrsets())
        .collect();
    let data_signers: Vec<&Signer> = signers.iter().filter(|s| s.key.signs_zone_data()).collect();
    if !signers.is_empty() && (key_signers.is_empty() || data_signers.is_empty()) {
        return Err(signing_internal(
            "zone has keys but no usable signer for the key RRsets or the zone data",
        ));
    }

    let input = build_signing_input(params, &apex, &signers)?;

    let mut new_rows: Vec<DnssecRecord> = Vec::new();
    let mut denial_records: Vec<SignRecord> = Vec::new();

    // The chain is cheap to rebuild whole, and doing so removes incremental
    // chain-repair edge cases entirely (RFC 9077 TTLs and zone cuts included).
    if params.denial == DnssecDenial::Nsec3 {
        // GenerateNsec3Config::default() is the RFC 9276 profile: SHA-1, zero
        // iterations, no salt, no opt-out.
        let Nsec3Records { nsec3s, nsec3param } = generate_nsec3s(
            &apex,
            RecordsIter::new_from_owned(&input),
            &GenerateNsec3Config::<Vec<u8>, DefaultSorter>::default(),
        )
        .map_err(|e| signing_internal(format!("NSEC3 generation failed: {}", e)))?;

        for nsec3 in nsec3s {
            let class = nsec3.class();
            let ttl = nsec3.ttl();
            let (owner, data) = nsec3.into_owner_and_data();
            denial_records.push(WireRecord::new(
                owner,
                class,
                ttl,
                ZoneRecordData::Nsec3(data),
            ));
        }
        let class = nsec3param.class();
        let ttl = nsec3param.ttl();
        let (owner, data) = nsec3param.into_owner_and_data();
        denial_records.push(WireRecord::new(
            owner,
            class,
            ttl,
            ZoneRecordData::Nsec3param(data),
        ));
    } else {
        let nsecs = generate_nsecs(
            &apex,
            RecordsIter::new_from_owned(&input),
            &GenerateNsecConfig::new(),
        )
        .map_err(|e| signing_internal(format!("NSEC generation failed: {}", e)))?;
        for nsec in nsecs {
            let class = nsec.class();
            let ttl = nsec.ttl();
            let (owner, data) = nsec.into_owner_and_data();
            denial_records.push(WireRecord::new(
                owner,
                class,
                ttl,
                ZoneRecordData::Nsec(data),
            ));
        }
    }

    // Rows for everything the signer owns: the apex key RRsets from `input`
    // and the denial chain. User records and the SOA stay in their own planes.
    for record in input.iter().filter(|r| is_key_rrset_type(r.rtype())) {
        new_rows.push(derived_row(
            zone,
            OwnerName::apex(),
            derived_record_type(record.rtype())?,
            None,
            record.ttl().as_secs() as i32,
            to_rdata(record.data()),
            None,
            None,
        ));
    }
    for record in &denial_records {
        new_rows.push(derived_row(
            zone,
            owner_in_zone(record.owner(), &zone.name)?,
            derived_record_type(record.rtype())?,
            None,
            record.ttl().as_secs() as i32,
            to_rdata(record.data()),
            None,
            None,
        ));
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
    for row in params.prev {
        if row.record_type == DnssecRecordType::Rrsig
            && let Some(covered) = row.covered_record_type
        {
            prev_rrsigs
                .entry((row.name.to_stored(), covered))
                .or_default()
                .push(row);
        }
    }

    let refresh_cutoff = params.now + chrono::Duration::seconds(params.refresh_secs);
    for rrset in &signable {
        let owner = owner_in_zone(rrset[0].owner(), &zone.name)?;
        let covered = rrset[0].rtype().to_int() as i32;
        // The apex key RRsets must be signed by keys the parent DS names
        // (RFC 7344, Section 4.1 for CDS/CDNSKEY); everything else by the
        // active zone-data keys.
        let rrset_signers: &[&Signer] =
            if *rrset[0].owner() == apex && is_key_rrset_type(rrset[0].rtype()) {
                &key_signers
            } else {
                &data_signers
            };
        let digest = rrset_digest(rrset_signers, rrset);

        let reusable = if params.force {
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
                let expiration = expiration_for(params, rrset[0].owner(), covered);
                for signer in rrset_signers {
                    let rrsig = signer.sign_rrset(rrset, params.inception, expiration)?;
                    new_rows.push(derived_row(
                        zone,
                        owner.clone(),
                        DnssecRecordType::Rrsig,
                        Some(covered),
                        rrsig.ttl().as_secs() as i32,
                        to_rdata(rrsig.data()),
                        Some(expiration),
                        Some(digest.clone()),
                    ));
                }
            }
        }
    }

    Ok(SignedViewDiff::from_planes(params.prev, new_rows))
}

fn derived_record_type(rtype: Rtype) -> Result<DnssecRecordType, ServiceError> {
    DnssecRecordType::try_from(rtype.to_int() as i32).map_err(signing_internal)
}

/// The RRset's slot in the jitter window, taken from its identity rather than
/// drawn at random: [`compute_signed_view`] stays a function of its inputs,
/// and an RRset keeps its slot across re-signings.
fn expiration_for(params: &SignedViewParams<'_>, owner: &WireName, covered: i32) -> DateTime<Utc> {
    if params.expiration_jitter_secs <= 0 {
        return params.expiration;
    }

    let mut hasher = Sha256::new();
    hasher.update(owner.as_slice());
    hasher.update(covered.to_be_bytes());
    let slot = u64::from_be_bytes(
        hasher.finalize()[..8]
            .try_into()
            .expect("8 bytes of digest"),
    );
    params.expiration
        - chrono::Duration::seconds((slot % params.expiration_jitter_secs as u64) as i64)
}

fn is_key_rrset_type(rtype: Rtype) -> bool {
    matches!(rtype, Rtype::DNSKEY | Rtype::CDS | Rtype::CDNSKEY)
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
    fn new(apex: &WireName, key: &'a DnssecKey) -> Result<Self, ServiceError> {
        let dnskey = dnskey_for(key)?;
        let secret = SecretKeyBytes::parse_from_bind(&key.private_key)
            .map_err(|e| signing_internal(format!("stored private key is invalid: {}", e)))?;
        let key_pair = KeyPair::from_bytes(&secret, &dnskey)
            .map_err(|e| signing_internal(format!("failed to load signing key: {}", e)))?;
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
    ) -> Result<WireRecord<WireName, domain::rdata::Rrsig<Vec<u8>, WireName>>, ServiceError> {
        let rrset = Rrset::new_from_refs(rrset)
            .map_err(|e| signing_internal(format!("invalid RRset: {}", e)))?;
        sign_rrset(
            &self.signing_key,
            &rrset,
            Timestamp::from(inception.timestamp() as u32),
            Timestamp::from(expiration.timestamp() as u32),
        )
        .map_err(|e| signing_internal(format!("signing failed: {}", e)))
    }
}

/// The key's DNSKEY RDATA rebuilt from its stored public half.
pub(super) fn dnskey_for(key: &DnssecKey) -> Result<domain::rdata::Dnskey<Vec<u8>>, ServiceError> {
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(&key.public_key)
        .map_err(|e| signing_internal(format!("stored public key is not base64: {}", e)))?;
    domain::rdata::Dnskey::new(
        key.role.flags(),
        3,
        SecurityAlgorithm::from_int(key.algorithm.to_int() as u8),
        public_key,
    )
    .map_err(|e| signing_internal(format!("stored public key is invalid: {}", e)))
}

/// The key's DS RDATA (RFC 4034, Section 5.1.4): tag, algorithm, digest type,
/// then SHA-256 over the canonical apex name and the DNSKEY RDATA.
pub(super) fn ds_rdata_for(key: &DnssecKey, apex: &WireName) -> Result<Rdata, ServiceError> {
    let dnskey = dnskey_for(key)?;
    let mut hasher = Sha256::new();
    hasher.update(apex.as_slice());
    hasher.update(to_rdata(&dnskey).as_bytes());

    let mut rdata = Vec::with_capacity(4 + 32);
    rdata.extend_from_slice(&(key.key_tag as u16).to_be_bytes());
    rdata.push(key.algorithm.to_int() as u8);
    rdata.push(DS_DIGEST_TYPE_SHA256);
    rdata.extend_from_slice(&hasher.finalize());
    Rdata::new(rdata).map_err(signing_internal)
}

/// User records, the synthesized SOA, and the apex key RRsets in canonical
/// order — the exact content the chain and the signatures must cover.
fn build_signing_input(
    params: &SignedViewParams<'_>,
    apex: &WireName,
    signers: &[Signer<'_>],
) -> Result<Vec<SignRecord>, ServiceError> {
    let zone = params.zone;
    let mut input: Vec<SignRecord> = Vec::new();

    let soa_bytes = zone
        .soa_rdata(params.new_serial as u32)
        .map_err(signing_internal)?;
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
        if signer.key.wants_parent_ds() {
            let cds = UnknownRecordData::from_octets(
                Rtype::CDS,
                ds_rdata_for(signer.key, apex)?.into_bytes(),
            )
            .map_err(|e| signing_internal(format!("invalid CDS rdata: {}", e)))?;
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
            .map_err(|e| signing_internal(format!("invalid CDNSKEY rdata: {}", e)))?;
            input.push(WireRecord::new(
                apex.clone(),
                Class::IN,
                Ttl::from_secs(zone.default_ttl as u32),
                ZoneRecordData::Unknown(cdnskey),
            ));
        }
    }

    for record in params.records {
        let EncodedRdata { record_type, rdata } =
            EncodedRdata::from_columns(&record.record_type, &record.value, record.priority)
                .map_err(signing_internal)?;
        let data = UnknownRecordData::from_octets(Rtype::from_int(record_type), rdata.into_bytes())
            .map_err(|e| signing_internal(format!("invalid record rdata: {}", e)))?;
        let owner = to_wire_name(record.name.to_wire(&zone.name)).map_err(signing_internal)?;
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

fn owner_in_zone(owner: &WireName, zone: &ZoneName) -> Result<OwnerName, ServiceError> {
    OwnerName::parse_absolute_in_zone(&owner.to_string(), zone).map_err(|e| {
        signing_internal(format!(
            "derived owner '{}' is not inside zone '{}': {}",
            owner, zone, e
        ))
    })
}

#[allow(clippy::too_many_arguments)]
fn derived_row(
    zone: &Zone,
    name: OwnerName,
    record_type: DnssecRecordType,
    covered_record_type: Option<i32>,
    ttl: i32,
    rdata: Rdata,
    expires_at: Option<DateTime<Utc>>,
    rrset_digest: Option<String>,
) -> DnssecRecord {
    DnssecRecord {
        id: 0,
        zone_id: zone.id,
        name,
        record_type,
        covered_record_type,
        ttl,
        rdata,
        expires_at,
        rrset_digest,
    }
}

/// A typed name's wire bytes into the domain form.
pub(super) fn to_wire_name(wire: Result<Vec<u8>, ParseNameError>) -> Result<WireName, String> {
    let wire = wire.map_err(|e| e.to_string())?;
    Name::from_octets(wire).map_err(|e| format!("invalid wire name: {}", e))
}

/// Wire RDATA of `data`, without the length prefix. Composed protocol values
/// are bounded well under the RDLENGTH limit, so the cap cannot trip here.
fn to_rdata<D: ComposeRecordData>(data: &D) -> Rdata {
    let mut bytes = Vec::new();
    data.compose_rdata(&mut bytes)
        .expect("composing into a Vec cannot run out of space");
    Rdata::new(bytes).expect("composed RDATA exceeds the RDLENGTH limit")
}

/// The typed SOA the denial generators require (they read MINIMUM per
/// RFC 9077), parsed back from the one byte encoding the transfer serves.
fn parse_soa(rdata: &[u8]) -> Result<domain::rdata::Soa<WireName>, ServiceError> {
    let mut parser = Parser::from_ref(rdata);
    domain::rdata::Soa::parse(&mut parser)
        .map_err(|e| signing_internal(format!("invalid SOA rdata: {}", e)))?
        .try_flatten_into()
        .map_err(|e| signing_internal(format!("invalid SOA rdata: {}", e)))
}

fn signing_internal(message: impl std::fmt::Display) -> ServiceError {
    ServiceError::internal(format!("DNSSEC signing failed: {}", message))
}
