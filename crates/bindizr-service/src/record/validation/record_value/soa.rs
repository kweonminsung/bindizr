use super::common::{canonical_domain_value, parse_u32_record_field, validate_domain_record_value};
use crate::error::ServiceError;

pub(super) struct SoaRecordValue<'a> {
    mname: &'a str,
    rname: &'a str,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}

impl<'a> SoaRecordValue<'a> {
    pub(super) fn parse(value: &'a str) -> Result<Self, ServiceError> {
        let fields = value.split_whitespace().collect::<Vec<_>>();
        match fields.as_slice() {
            [mname, rname, serial, refresh, retry, expire, minimum] => Ok(Self {
                mname,
                rname,
                serial: parse_u32_record_field("SOA serial", serial)?,
                refresh: parse_u32_record_field("SOA refresh", refresh)?,
                retry: parse_u32_record_field("SOA retry", retry)?,
                expire: parse_u32_record_field("SOA expire", expire)?,
                minimum: parse_u32_record_field("SOA minimum", minimum)?,
            }),
            _ => Err(ServiceError::BadRequest(format!(
                "SOA record value must be '<mname> <rname> <serial> <refresh> <retry> <expire> <minimum>': {value}"
            ))),
        }
    }

    pub(super) fn validate(&self) -> Result<(), ServiceError> {
        validate_domain_record_value("SOA mname", self.mname)?;
        validate_domain_record_value("SOA rname", self.rname)?;
        Ok(())
    }

    pub(super) fn canonical(&self) -> String {
        format!(
            "{} {} {} {} {} {} {}",
            canonical_domain_value(self.mname),
            canonical_domain_value(self.rname),
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum,
        )
    }
}
