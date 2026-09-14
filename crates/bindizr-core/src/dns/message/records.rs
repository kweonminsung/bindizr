//! Stored records, SOA versions, and catalog members as response answers.

use super::{DnsMessageBuilder, Name};
use crate::{
    dns::{
        name::{OwnerName, ZoneName, encode_name, to_fqdn},
        record::{EncodedRdata, SoaRecordValue, TxtRecordValue},
    },
    model::{
        dnssec_record::DnssecRecord,
        record::{Record, RecordType},
        zone::Zone,
    },
};

/// SOA is synthesized rather than stored as a user record.
const SOA_WIRE_TYPE: u16 = 6;

impl DnsMessageBuilder {
    pub fn add_soa(&mut self, zone: &Zone, serial: u32) -> Result<(), String> {
        let rdata = zone.soa_rdata(serial)?;
        self.add_raw_rdata(
            zone.name.to_wire(),
            SOA_WIRE_TYPE,
            zone.default_ttl as u32,
            rdata,
        )
    }

    /// Adds a catalog-zone SOA with placeholder `invalid` MNAME/RNAME.
    pub fn add_catalog_soa(&mut self, zone: &Zone, serial: u32) -> Result<(), String> {
        let rdata = SoaRecordValue {
            mname: "invalid",
            rname: "invalid",
            serial,
            refresh: zone.refresh as u32,
            retry: zone.retry as u32,
            expire: zone.expire as u32,
            minimum: zone.minimum_ttl as u32,
        }
        .to_rdata()?;
        self.add_raw_rdata(
            zone.name.to_wire(),
            SOA_WIRE_TYPE,
            zone.default_ttl as u32,
            rdata,
        )
    }

    /// Adds an SOA from a serial-specific version.
    pub fn add_version_soa(
        &mut self,
        soa: &crate::model::zone_version::ZoneVersion,
    ) -> Result<(), String> {
        let serial = crate::dns::serial_to_u32(soa.serial)?;
        let rdata = SoaRecordValue {
            mname: &soa.mname,
            rname: &soa.rname,
            serial,
            refresh: soa.refresh as u32,
            retry: soa.retry as u32,
            expire: soa.expire as u32,
            minimum: soa.minimum_ttl as u32,
        }
        .to_rdata()?;

        // IXFR SOA owner is the transfer QNAME.
        self.add_raw_rdata(
            self.qname.clone(),
            SOA_WIRE_TYPE,
            soa.default_ttl as u32,
            rdata,
        )
    }

    /// Adds one answer of any supported stored type at an absolute owner name.
    pub(crate) fn add_text_rdata(
        &mut self,
        name: &str,
        ttl: u32,
        record_type: &RecordType,
        value: &str,
        priority: Option<i32>,
    ) -> Result<(), String> {
        let EncodedRdata { record_type, rdata } =
            EncodedRdata::from_columns(record_type, value, priority)?;
        self.add_raw_rdata(parse_name(name)?, record_type, ttl, rdata)
    }

    /// Adds the catalog-zone NS record, which is the placeholder "invalid".
    pub fn add_catalog_ns(&mut self, zone: &Zone) -> Result<(), String> {
        let owner_name = zone.name.to_fqdn();
        self.add_text_rdata(
            &owner_name,
            zone.default_ttl as u32,
            &RecordType::NS,
            "invalid",
            None,
        )
    }

    /// Adds the catalog-zone version TXT record.
    pub fn add_catalog_schema_version(&mut self, zone: &Zone) -> Result<(), String> {
        let version_name = format!("version.{}.", zone.name);
        // "2" is the RFC 9432 catalog zone schema version.
        self.add_text_rdata(
            &version_name,
            zone.default_ttl as u32,
            &RecordType::TXT,
            &TxtRecordValue::from_string("2").to_presentation(),
            None,
        )
    }

    pub fn add_catalog_ptr(&mut self, zone: &Zone, member_zone: &str) -> Result<(), String> {
        let member_id = crate::dns::zone_name_to_member_id(member_zone);
        let ptr_name = format!("{}.zones.{}.", member_id, zone.name);
        let ptr_target = to_fqdn(member_zone);
        self.add_text_rdata(
            &ptr_name,
            zone.default_ttl as u32,
            &RecordType::PTR,
            &ptr_target,
            None,
        )
    }

    pub fn add_record(&mut self, record: &Record, zone_name: &ZoneName) -> Result<(), String> {
        self.add_record_parts(
            zone_name,
            &record.name,
            &record.record_type,
            &record.value,
            record.ttl,
            record.priority,
        )
    }

    /// Adds an answer from stored record columns (records and journal
    /// rows share this shape). Unsupported types are skipped.
    pub fn add_record_parts(
        &mut self,
        zone_name: &ZoneName,
        name: &OwnerName,
        record_type: &RecordType,
        value: &str,
        ttl: i32,
        priority: Option<i32>,
    ) -> Result<(), String> {
        let EncodedRdata { record_type, rdata } =
            EncodedRdata::from_columns(record_type, value, priority)?;
        self.add_raw_rdata(name.to_wire(zone_name), record_type, ttl as u32, rdata)
    }

    /// Adds a derived DNSSEC record; its RDATA is stored in wire form.
    pub fn add_dnssec_record(
        &mut self,
        record: &DnssecRecord,
        zone_name: &ZoneName,
    ) -> Result<(), String> {
        self.add_raw_rdata(
            record.name.to_wire(zone_name),
            record.record_type.wire_type(),
            record.ttl as u32,
            record.rdata.clone(),
        )
    }
}

/// Parses a presentation-form name through the one core name encoding.
fn parse_name(name: &str) -> Result<Name<Vec<u8>>, String> {
    let wire = encode_name(name)?;
    Name::from_octets(wire).map_err(|e| format!("Invalid domain name '{}': {}", name, e))
}
