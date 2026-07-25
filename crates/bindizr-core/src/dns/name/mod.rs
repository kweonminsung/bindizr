/// Maximum length of a single DNS label, in bytes (RFC 1035).
pub const MAX_DNS_LABEL_LEN: usize = 63;
/// Maximum length of a domain name, in bytes (RFC 1035).
pub const MAX_DOMAIN_LEN: usize = 253;

/// Errors from parsing domain names or email addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    DanglingEscape,
    InvalidEmail,
}

impl std::fmt::Display for NameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NameError::DanglingEscape => write!(f, "domain name contains a dangling escape"),
            NameError::InvalidEmail => write!(f, "email must contain exactly one @"),
        }
    }
}

impl std::error::Error for NameError {}

/// Labels of a presentation-format name.
pub enum PresentationLabels<'a> {
    Borrowed(std::str::Split<'a, char>),
    Owned(std::vec::IntoIter<String>),
}

impl<'a> Iterator for PresentationLabels<'a> {
    type Item = std::borrow::Cow<'a, str>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Borrowed(labels) => labels.next().map(std::borrow::Cow::Borrowed),
            Self::Owned(labels) => labels.next().map(std::borrow::Cow::Owned),
        }
    }
}

/// Iterate a presentation-format name's labels, honoring `\` escapes.
pub fn presentation_labels(name: &str) -> Result<PresentationLabels<'_>, NameError> {
    if name.contains('\\') {
        Ok(PresentationLabels::Owned(
            split_presentation_labels(name)?.into_iter(),
        ))
    } else {
        Ok(PresentationLabels::Borrowed(name.split('.')))
    }
}

/// Split a presentation-format name into labels, honoring `\` escapes.
fn split_presentation_labels(name: &str) -> Result<Vec<String>, NameError> {
    let mut labels = Vec::new();
    let mut label = String::new();
    let mut escaped = false;

    for c in name.chars() {
        if escaped {
            label.push(c);
            escaped = false;
            continue;
        }

        match c {
            '\\' => escaped = true,
            '.' => {
                labels.push(label);
                label = String::new();
            }
            _ => label.push(c),
        }
    }

    if escaped {
        return Err(NameError::DanglingEscape);
    }

    labels.push(label);
    Ok(labels)
}

/// Return `value` as a lowercase, trailing-dot FQDN.
pub fn to_fqdn_lowercase(value: &str) -> String {
    format!(
        "{}.",
        value.trim().trim_end_matches('.').to_ascii_lowercase()
    )
}

/// Return `value` with a single trailing dot, preserving case.
pub fn to_fqdn(value: &str) -> String {
    format!("{}.", value.trim_end_matches('.'))
}

/// Resolve an owner name to an absolute FQDN within `zone` (`@` = apex; absolute
/// or in-zone names pass through; otherwise `zone` is appended).
pub fn to_owner_fqdn(name: &str, zone: &str) -> String {
    if name.ends_with('.') {
        return name.to_string();
    }

    let zone_trimmed = zone.trim_end_matches('.');
    if name == "@" {
        return format!("{}.", zone_trimmed);
    }

    let owner_trimmed = name.trim_end_matches('.');
    let zone_lower = zone_trimmed.to_ascii_lowercase();
    let zone_suffix = format!(".{}", zone_lower);
    let owner_lower = owner_trimmed.to_ascii_lowercase();
    if owner_lower == zone_lower || owner_lower.ends_with(&zone_suffix) {
        return format!("{}.", owner_trimmed);
    }

    format!("{}.{}.", owner_trimmed, zone_trimmed)
}

/// Whether `name` equals `zone` or is a subdomain of it (exact string match).
pub fn is_same_or_subdomain_fqdn(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{}", zone))
}

/// Whether `name` refers to the zone apex (`@` or the zone name itself).
pub fn is_apex_name(name: &str, zone_name: &str) -> bool {
    name == "@" || to_fqdn(name).eq_ignore_ascii_case(&to_fqdn(zone_name))
}

/// Convert an email address into SOA RNAME mailbox form, escaping the
/// local part's dots.
pub fn email_to_soa_mailbox(value: &str) -> Result<String, NameError> {
    if value.matches('@').count() != 1 {
        return Err(NameError::InvalidEmail);
    }

    let (local, domain) = value.split_once('@').ok_or(NameError::InvalidEmail)?;

    Ok(format!(
        "{}.{}.",
        escape_soa_local_part(local),
        domain.trim_end_matches('.')
    ))
}

fn escape_soa_local_part(local: &str) -> String {
    let mut escaped = String::with_capacity(local.len());

    for c in local.chars() {
        if c == '.' || c == '\\' {
            escaped.push('\\');
        }
        escaped.push(c);
    }

    escaped
}

/// Inverse of [`email_to_soa_mailbox`]: convert an SOA RNAME mailbox back into
/// an email address. The first unescaped '.' separates the local part from the
/// domain; `\.` and `\\` in the local part are unescaped.
pub fn soa_mailbox_to_email(value: &str) -> Result<String, NameError> {
    let mailbox = value.trim_end_matches('.');
    let mut local = String::with_capacity(mailbox.len());
    let mut chars = mailbox.chars();

    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(escaped) => local.push(escaped),
                None => return Err(NameError::DanglingEscape),
            },
            '.' => {
                let domain: String = chars.collect();
                if local.is_empty() || domain.is_empty() {
                    return Err(NameError::InvalidEmail);
                }
                return Ok(format!("{}@{}", local, domain));
            }
            c => local.push(c),
        }
    }

    Err(NameError::InvalidEmail)
}

#[cfg(test)]
mod tests;
