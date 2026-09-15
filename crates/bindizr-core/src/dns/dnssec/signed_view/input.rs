//! Canonical signing input and the denial chain derived from it.

use std::collections::BTreeMap;

use domain::{
    base::{
        Record as WireRecord, Ttl, UnknownRecordData,
        iana::{Class, Rtype},
        name::FlattenInto,
    },
    dep::octseq::Parser,
    dnssec::sign::{
        denial::{
            nsec::{GenerateNsecConfig, generate_nsecs},
            nsec3::{GenerateNsec3Config, Nsec3Records, generate_nsec3s},
        },
        records::{DefaultSorter, RecordsIter},
    },
    rdata::ZoneRecordData,
};

use super::{SignRr, SignedViewParams, Signer, WireName, to_rdata};
use crate::{
    dns::{
        dnssec::{rdata::ds_rdata_for, to_wire_name},
        record::EncodedRdata,
    },
    model::dnssec_policy::DnssecDenial,
};

impl SignedViewParams<'_> {
    /// User records, the synthesized SOA, and the apex key RRsets in canonical
    /// order — the exact content the chain and the signatures must cover.
    pub(crate) fn signing_input(
        &self,
        apex: &WireName,
        signers: &[Signer<'_>],
    ) -> Result<Vec<SignRr>, String> {
        let zone = self.zone;
        let mut input: Vec<SignRr> = Vec::new();

        // Synthesize the apex records owned by zone metadata and signing keys.
        let soa_bytes = zone.soa_rdata(self.new_serial as u32)?;
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
            if signer.key.wants_parent_ds() && !self.withdraw_parent_ds {
                let cds = UnknownRecordData::from_octets(
                    Rtype::CDS,
                    ds_rdata_for(signer.key, apex, signer.key.algorithm.ds_digest_type())?
                        .into_bytes(),
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
        if self.withdraw_parent_ds && !signers.is_empty() {
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

        // Add user records to the same input used for denial proofs and signatures.
        for record in self.records {
            let EncodedRdata { record_type, rdata } =
                EncodedRdata::from_columns(&record.record_type, &record.value, record.priority)?;
            let data =
                UnknownRecordData::from_octets(Rtype::from_int(record_type), rdata.into_bytes())
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
        for rr in &input {
            let key = (rr.owner().as_slice().to_vec(), rr.rtype().to_int());
            let entry = rrset_ttls.entry(key).or_insert_with(|| rr.ttl());
            *entry = (*entry).min(rr.ttl());
        }
        for rr in &mut input {
            let key = (rr.owner().as_slice().to_vec(), rr.rtype().to_int());
            rr.set_ttl(rrset_ttls[&key]);
        }

        // Canonical order keeps each RRset contiguous for the signing pass.
        input.sort_by(|a, b| {
            use domain::base::cmp::CanonicalOrd;
            a.canonical_cmp(b)
        });

        Ok(input)
    }
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
pub(crate) fn denial_rrs(
    apex: &WireName,
    input: &[SignRr],
    denial: DnssecDenial,
) -> Result<Vec<SignRr>, String> {
    /// Wrap a denial record's data in the signing record type.
    fn into_sign_rr<D>(
        rr: WireRecord<WireName, D>,
        wrap: impl FnOnce(D) -> ZoneRecordData<Vec<u8>, WireName>,
    ) -> SignRr {
        let class = rr.class();
        let ttl = rr.ttl();
        let (owner, data) = rr.into_owner_and_data();
        WireRecord::new(owner, class, ttl, wrap(data))
    }

    let mut rrs = Vec::new();
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
            rrs.push(into_sign_rr(nsec3, ZoneRecordData::Nsec3));
        }
        rrs.push(into_sign_rr(nsec3param, ZoneRecordData::Nsec3param));
    } else {
        let nsecs = generate_nsecs(
            apex,
            RecordsIter::new_from_owned(input),
            &GenerateNsecConfig::new(),
        )
        .map_err(|e| format!("NSEC generation failed: {}", e))?;
        for nsec in nsecs {
            rrs.push(into_sign_rr(nsec, ZoneRecordData::Nsec));
        }
    }
    Ok(rrs)
}
