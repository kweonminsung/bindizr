//! SOA record values, including the RNAME mailbox <-> email conversions.

use super::value::{canonical_domain_value, parse_u32_record_field, validate_domain_record_value};

pub(crate) struct SoaRecordValue<'a> {
    mname: &'a str,
    rname: &'a str,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}

impl<'a> SoaRecordValue<'a> {
    pub(crate) fn parse(value: &'a str) -> Result<Self, String> {
        // The trailing `None` rejects a value with more than seven fields.
        let mut fields = value.split_whitespace();
        match (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) {
            (
                Some(mname),
                Some(rname),
                Some(serial),
                Some(refresh),
                Some(retry),
                Some(expire),
                Some(minimum),
                None,
            ) => Ok(Self {
                mname,
                rname,
                serial: parse_u32_record_field("SOA serial", serial)?,
                refresh: parse_u32_record_field("SOA refresh", refresh)?,
                retry: parse_u32_record_field("SOA retry", retry)?,
                expire: parse_u32_record_field("SOA expire", expire)?,
                minimum: parse_u32_record_field("SOA minimum", minimum)?,
            }),
            _ => Err(format!(
                "SOA record value must be '<mname> <rname> <serial> <refresh> <retry> <expire> <minimum>': {value}"
            )),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        validate_domain_record_value("SOA mname", self.mname)?;
        validate_domain_record_value("SOA rname", self.rname)?;
        Ok(())
    }

    pub(crate) fn canonical(&self) -> String {
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

/// An SOA RNAME mailbox in presentation form, with the email local part's
/// dots escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoaMailbox(String);

impl SoaMailbox {
    /// Encode an email address into mailbox form.
    pub fn from_email(email: &str) -> Result<Self, String> {
        let (local, domain) = match email.split_once('@') {
            Some(parts) if email.matches('@').count() == 1 => parts,
            _ => return Err("email must contain exactly one @".to_string()),
        };

        Ok(Self(format!(
            "{}.{}.",
            escape_local_part(local),
            domain.trim_end_matches('.')
        )))
    }

    /// Wrap an already-encoded mailbox (e.g. a stored snapshot value) as-is;
    /// [`Self::to_email`] validates on decode.
    pub fn from_encoded(mailbox: impl Into<String>) -> Self {
        Self(mailbox.into())
    }

    /// Decode back into an email address. The first unescaped '.' separates
    /// the local part from the domain; `\.` and `\\` are unescaped.
    pub fn to_email(&self) -> Result<String, String> {
        let mailbox = self.0.trim_end_matches('.');
        let mut local = String::with_capacity(mailbox.len());
        let mut chars = mailbox.chars();

        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some(escaped) => local.push(escaped),
                    None => return Err("SOA mailbox contains a dangling escape".to_string()),
                },
                '.' => {
                    let domain: String = chars.collect();
                    if local.is_empty() || domain.is_empty() {
                        return Err("SOA mailbox is not a valid encoded email".to_string());
                    }
                    return Ok(format!("{}@{}", local, domain));
                }
                c => local.push(c),
            }
        }

        Err("SOA mailbox is not a valid encoded email".to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_encoded(self) -> String {
        self.0
    }
}

impl std::fmt::Display for SoaMailbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn escape_local_part(local: &str) -> String {
    let mut escaped = String::with_capacity(local.len());

    for c in local.chars() {
        if c == '.' || c == '\\' {
            escaped.push('\\');
        }
        escaped.push(c);
    }

    escaped
}

#[cfg(test)]
mod tests;
