//! Resolve ordered SOA replacements before journaling records at the final serial.

use bindizr_core::dns::{
    Serial, Ttl,
    name::OwnerName,
    record::{SoaMailbox, SoaRecordValue},
};

use super::{NsupdateError, operation::RecordOperation};
use crate::{
    error::ServiceError,
    model::zone::Zone,
    serial::generate_serial,
    ttl::{validate_minimum_ttl, validate_soa_interval},
    zone::validation::normalize_soa,
};

/// A wire update targets either ordinary records or the zone's SOA metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UpdateOperation {
    Record(RecordOperation),
    ReplaceSoa {
        name: OwnerName,
        ttl: Ttl,
        value: SoaRecordValue<String>,
    },
}

/// All changes in a request share the resulting SOA and journal serial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpdatePlan {
    pub(crate) zone: Zone,
    pub(crate) records: Vec<RecordOperation>,
    pub(crate) soa_changed: bool,
}

impl UpdatePlan {
    /// Resolve SOAs in wire order, retaining the relative order of record operations.
    pub(crate) fn compute(
        zone: &Zone,
        updates: Vec<UpdateOperation>,
    ) -> Result<Self, NsupdateError> {
        let mut plan = Self {
            zone: zone.clone(),
            records: Vec::new(),
            soa_changed: false,
        };

        for update in updates {
            match update {
                UpdateOperation::Record(record) => plan.records.push(record),
                UpdateOperation::ReplaceSoa { name, ttl, value } => {
                    // RFC 2136, Section 3.4.2.2: SOA exists only at the apex;
                    // equal, older, and RFC 1982-undefined serials cannot replace it.
                    if !name.is_apex()
                        || !Serial::from(value.serial).is_newer_than(plan.zone.serial)
                    {
                        continue;
                    }

                    plan.zone = replace_soa(&plan.zone, ttl, value)?;
                    plan.soa_changed = true;
                }
            }
        }

        // RFC 2136, Section 3.6: only an update without an explicit SOA advance
        // needs an automatically generated serial.
        if (plan.soa_changed && plan.zone.serial == zone.serial)
            || (!plan.soa_changed && !plan.records.is_empty())
        {
            plan.zone.serial = generate_serial(Some(zone.serial));
        }

        Ok(plan)
    }
}

/// Apply the existing zone-write policy to an advancing wire SOA.
fn replace_soa(zone: &Zone, ttl: Ttl, value: SoaRecordValue<String>) -> Result<Zone, ServiceError> {
    let serial = Serial::from(value.serial);
    let interval = |value| i32::try_from(value).map_err(ServiceError::invalid_zone_field);
    let rname = SoaMailbox::from_encoded(value.rname)
        .to_email()
        .map_err(ServiceError::invalid_zone_field)?;
    let normalized = normalize_soa(&value.mname, &rname, i64::from(ttl))?;

    Ok(Zone {
        serial,
        mname: normalized.mname,
        rname: normalized.rname,
        default_ttl: normalized.ttl,
        refresh: validate_soa_interval(interval(value.refresh)?, "refresh")?,
        retry: validate_soa_interval(interval(value.retry)?, "retry")?,
        expire: validate_soa_interval(interval(value.expire)?, "expire")?,
        minimum_ttl: validate_minimum_ttl(i64::from(value.minimum))?,
        ..zone.clone()
    })
}
