//! Stored records, SOA versions, and catalog members as response answers.

use domain::base::iana::Rtype;

use crate::dns;
use crate::dns::message::{DnsMessageBuilder, EncodeMessageError};
use crate::dns::name::{OwnerName, ZoneName};
use crate::dns::record::{Rdata, SoaRecordValue, TxtRecordValue};
use crate::dns::{CatalogZone, Serial, Ttl};
use crate::model::dnssec_record::DnssecRecord;
use crate::model::record::{Record, RecordType};
use crate::model::zone::Zone;
use crate::model::zone_change::{JournalRecordType, ZoneChange};
use crate::model::zone_version::ZoneVersion;

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
                    &change.record_name,
                    zone_name,
                    *record_type,
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
            Rtype::SOA.to_int(),
            zone.default_ttl.as_secs(),
            rdata,
        )
    }

    /// Add a catalog-zone SOA with placeholder `invalid` MNAME/RNAME.
    pub fn add_catalog_soa(
        &mut self,
        catalog_zone: &CatalogZone,
    ) -> Result<(), EncodeMessageError> {
        let rdata = SoaRecordValue {
            mname: "invalid",
            rname: "invalid",
            serial: catalog_zone.serial.as_u32(),
            refresh: catalog_zone.refresh.as_secs(),
            retry: catalog_zone.retry.as_secs(),
            expire: catalog_zone.expire.as_secs(),
            minimum: catalog_zone.minimum_ttl.as_secs(),
        }
        .to_rdata()?;
        self.add_raw_rdata(
            catalog_zone.name.to_wire_name()?,
            Rtype::SOA.to_int(),
            catalog_zone.default_ttl.as_secs(),
            rdata,
        )
    }

    /// Add an SOA from a serial-specific version.
    pub fn add_version_soa(&mut self, version: &ZoneVersion) -> Result<(), EncodeMessageError> {
        let rdata = SoaRecordValue {
            mname: &version.mname,
            rname: &version.rname,
            serial: version.serial.as_u32(),
            refresh: version.refresh.as_secs(),
            retry: version.retry.as_secs(),
            expire: version.expire.as_secs(),
            minimum: version.minimum_ttl.as_secs(),
        }
        .to_rdata()?;

        // IXFR SOA owner is the transfer QNAME.
        self.add_raw_rdata(
            self.qname.clone(),
            Rtype::SOA.to_int(),
            version.default_ttl.as_secs(),
            rdata,
        )
    }

    /// Add the catalog-zone NS record, which is the placeholder "invalid".
    pub fn add_catalog_ns(&mut self, catalog_zone: &CatalogZone) -> Result<(), EncodeMessageError> {
        self.add_record_parts(
            &OwnerName::apex(),
            &catalog_zone.name,
            RecordType::Ns,
            "invalid",
            catalog_zone.default_ttl,
            None,
        )
    }

    /// Add the catalog-zone version TXT record.
    pub fn add_catalog_schema_version(
        &mut self,
        catalog_zone: &CatalogZone,
    ) -> Result<(), EncodeMessageError> {
        // "2" is the RFC 9432 catalog zone schema version.
        self.add_record_parts(
            &OwnerName::from_row("version"),
            &catalog_zone.name,
            RecordType::Txt,
            &TxtRecordValue::from_string("2").to_presentation(),
            catalog_zone.default_ttl,
            None,
        )
    }

    /// Append a catalog membership PTR answer.
    pub fn add_catalog_ptr(
        &mut self,
        catalog_zone: &CatalogZone,
        zone_name: &ZoneName,
    ) -> Result<(), EncodeMessageError> {
        self.add_record_parts(
            &dns::catalog_member_owner_name(zone_name),
            &catalog_zone.name,
            RecordType::Ptr,
            &zone_name.to_fqdn(),
            catalog_zone.default_ttl,
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
            &record.name,
            zone_name,
            record.record_type,
            &record.value,
            record.ttl,
            record.priority,
        )
    }

    /// Add an answer from stored record columns (records and journal
    /// rows share this shape). Unsupported types are skipped.
    pub fn add_record_parts(
        &mut self,
        owner: &OwnerName,
        zone_name: &ZoneName,
        record_type: RecordType,
        value: &str,
        ttl: Ttl,
        priority: Option<i32>,
    ) -> Result<(), EncodeMessageError> {
        let rdata = Rdata::from_columns(record_type, value, priority)?;
        let rtype = record_type.wire_type();
        self.add_raw_rdata(owner.to_wire_name(zone_name)?, rtype, ttl.as_secs(), rdata)
    }

    /// Add a derived DNSSEC record; its RDATA is stored in wire form.
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
