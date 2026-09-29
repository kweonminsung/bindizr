//! Stored records, SOA versions, and catalog members as response answers.

use super::{DnsMessageBuilder, EncodeMessageError, Name};
use crate::{
    dns::{
        Serial, Ttl,
        dnssec::WireNameError,
        name::{OwnerName, ZoneName, encode_name, to_fqdn},
        record::{EncodedRdata, SoaRecordValue, TxtRecordValue},
    },
    model::{
        dnssec_record::DnssecRecord,
        record::{Record, RecordType},
        zone::Zone,
        zone_change::{JournalRecordType, ZoneChange},
    },
};

/// SOA is synthesized rather than stored as a user record.
const SOA_WIRE_TYPE: u16 = 6;

impl DnsMessageBuilder {
    /// Append one journal change to a DNS transfer message.
    pub fn add_change(
        &mut self,
        change: &ZoneChange,
        zone_name: &ZoneName,
    ) -> Result<(), EncodeMessageError> {
        match &change.record_type {
            JournalRecordType::Derived(record_type) => {
                let rdata = change
                    .record_rdata
                    .clone()
                    .ok_or(EncodeMessageError::MissingRdata)?;
                self.add_raw_rdata(
                    change.record_name.to_wire_name(zone_name)?,
                    record_type.wire_type(),
                    change.record_ttl.as_secs(),
                    rdata,
                )
            }
            JournalRecordType::User(record_type) => {
                let value = change
                    .record_value
                    .as_deref()
                    .ok_or(EncodeMessageError::MissingValue)?;
                self.add_record_parts(
                    zone_name,
                    &change.record_name,
                    record_type,
                    value,
                    change.record_ttl,
                    change.record_priority,
                )
            }
            // The delta's SOA boundaries come from the version rows above.
            JournalRecordType::Soa => Ok(()),
        }
    }

    /// Append the zone's synthesized SOA answer.
    pub fn add_soa(&mut self, zone: &Zone, serial: Serial) -> Result<(), EncodeMessageError> {
        let rdata = zone.soa_rdata(serial)?;
        self.add_raw_rdata(
            zone.name.to_wire_name()?,
            SOA_WIRE_TYPE,
            zone.default_ttl.as_secs(),
            rdata,
        )
    }

    /// Adds a catalog-zone SOA with placeholder `invalid` MNAME/RNAME.
    pub fn add_catalog_soa(
        &mut self,
        zone: &Zone,
        serial: Serial,
    ) -> Result<(), EncodeMessageError> {
        let rdata = SoaRecordValue {
            mname: "invalid",
            rname: "invalid",
            serial: serial.as_u32(),
            refresh: zone.refresh.as_secs(),
            retry: zone.retry.as_secs(),
            expire: zone.expire.as_secs(),
            minimum: zone.minimum_ttl.as_secs(),
        }
        .to_rdata()?;
        self.add_raw_rdata(
            zone.name.to_wire_name()?,
            SOA_WIRE_TYPE,
            zone.default_ttl.as_secs(),
            rdata,
        )
    }

    /// Adds an SOA from a serial-specific version.
    pub fn add_version_soa(
        &mut self,
        soa: &crate::model::zone_version::ZoneVersion,
    ) -> Result<(), EncodeMessageError> {
        let rdata = SoaRecordValue {
            mname: &soa.mname,
            rname: &soa.rname,
            serial: soa.serial.as_u32(),
            refresh: soa.refresh.as_secs(),
            retry: soa.retry.as_secs(),
            expire: soa.expire.as_secs(),
            minimum: soa.minimum_ttl.as_secs(),
        }
        .to_rdata()?;

        // IXFR SOA owner is the transfer QNAME.
        self.add_raw_rdata(
            self.qname.clone(),
            SOA_WIRE_TYPE,
            soa.default_ttl.as_secs(),
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
    ) -> Result<(), EncodeMessageError> {
        let EncodedRdata { record_type, rdata } =
            EncodedRdata::from_columns(record_type, value, priority)?;
        self.add_raw_rdata(parse_name(name)?, record_type, ttl, rdata)
    }

    /// Adds the catalog-zone NS record, which is the placeholder "invalid".
    pub fn add_catalog_ns(&mut self, zone: &Zone) -> Result<(), EncodeMessageError> {
        let owner_name = zone.name.to_fqdn();
        self.add_text_rdata(
            &owner_name,
            zone.default_ttl.as_secs(),
            &RecordType::Ns,
            "invalid",
            None,
        )
    }

    /// Adds the catalog-zone version TXT record.
    pub fn add_catalog_schema_version(&mut self, zone: &Zone) -> Result<(), EncodeMessageError> {
        let version_name = format!("version.{}.", zone.name);
        // "2" is the RFC 9432 catalog zone schema version.
        self.add_text_rdata(
            &version_name,
            zone.default_ttl.as_secs(),
            &RecordType::Txt,
            &TxtRecordValue::from_string("2").to_presentation(),
            None,
        )
    }

    /// Append a catalog membership PTR answer.
    pub fn add_catalog_ptr(
        &mut self,
        zone: &Zone,
        member_zone: &str,
    ) -> Result<(), EncodeMessageError> {
        let member_id = crate::dns::zone_name_to_member_id(member_zone);
        let ptr_name = format!("{}.zones.{}.", member_id, zone.name);
        let ptr_target = to_fqdn(member_zone);
        self.add_text_rdata(
            &ptr_name,
            zone.default_ttl.as_secs(),
            &RecordType::Ptr,
            &ptr_target,
            None,
        )
    }

    /// Encode a stored record and append it as an answer.
    pub fn add_record(
        &mut self,
        record: &Record,
        zone_name: &ZoneName,
    ) -> Result<(), EncodeMessageError> {
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
    pub(crate) fn add_record_parts(
        &mut self,
        zone_name: &ZoneName,
        name: &OwnerName,
        record_type: &RecordType,
        value: &str,
        ttl: Ttl,
        priority: Option<i32>,
    ) -> Result<(), EncodeMessageError> {
        let EncodedRdata { record_type, rdata } =
            EncodedRdata::from_columns(record_type, value, priority)?;
        self.add_raw_rdata(
            name.to_wire_name(zone_name)?,
            record_type,
            ttl.as_secs(),
            rdata,
        )
    }

    /// Adds a derived DNSSEC record; its RDATA is stored in wire form.
    pub fn add_dnssec_record(
        &mut self,
        record: &DnssecRecord,
        zone_name: &ZoneName,
    ) -> Result<(), EncodeMessageError> {
        self.add_raw_rdata(
            record.name.to_wire_name(zone_name)?,
            record.record_type.wire_type(),
            record.ttl.as_secs(),
            record.rdata.clone(),
        )
    }
}

/// Parses a presentation-form name through the one core name encoding.
fn parse_name(name: &str) -> Result<Name<Vec<u8>>, EncodeMessageError> {
    let wire = encode_name(name)?;
    Name::from_octets(wire).map_err(|e| WireNameError::Octets(Box::new(e)).into())
}
