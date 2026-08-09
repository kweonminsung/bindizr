//! Domain-name presentation-form handling: label and length limits,
//! escape-aware label iteration, FQDN normalization, containment/apex checks,
//! and the whitespace/control hygiene check shared by name-like inputs.

/// Maximum length of a single DNS label, in bytes (RFC 1035).
pub const MAX_DNS_LABEL_LEN: usize = 63;
/// Maximum length of a domain name, in bytes (RFC 1035).
pub const MAX_DOMAIN_LEN: usize = 253;

/// Whether the value contains any whitespace or ASCII control character.
pub fn has_whitespace_or_control(value: &str) -> bool {
    value
        .chars()
        .any(|c| c.is_ascii_control() || c.is_whitespace())
}

/// Classify one label's problem, if any: non-empty, at most 63 bytes, LDH
/// charset (plus `_` when `allow_underscore`), no leading/trailing hyphen.
pub fn classify_domain_label(label: &str, allow_underscore: bool) -> Result<(), ParseNameError> {
    if label.is_empty() {
        return Err(ParseNameError::EmptyLabel);
    }

    if label.len() > MAX_DNS_LABEL_LEN {
        return Err(ParseNameError::LabelTooLong);
    }

    if !label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || (allow_underscore && c == '_'))
    {
        return Err(ParseNameError::LabelCharset {
            underscore_allowed: allow_underscore,
        });
    }

    if label.starts_with('-') || label.ends_with('-') {
        return Err(ParseNameError::LabelHyphen);
    }

    Ok(())
}

/// [`classify_domain_label`] with the problem phrased against `field` and
/// mapped to the caller's error kind.
pub fn validate_domain_label<E>(
    label: &str,
    field: &str,
    allow_underscore: bool,
    invalid: impl Fn(String) -> E,
) -> Result<(), E> {
    classify_domain_label(label, allow_underscore).map_err(|e| invalid(format!("{} {}", field, e)))
}

/// Errors from parsing domain names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    DanglingEscape,
}

impl std::fmt::Display for NameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NameError::DanglingEscape => write!(f, "domain name contains a dangling escape"),
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

/// Inverse of [`presentation_labels`] for one label: escape `.` and `\` so the
/// label survives a round trip as a single label (RFC 1035, Section 5.1).
pub fn escape_presentation_label(label: &str) -> std::borrow::Cow<'_, str> {
    if !label.contains(['.', '\\']) {
        return std::borrow::Cow::Borrowed(label);
    }

    let mut escaped = String::with_capacity(label.len() + 1);
    for c in label.chars() {
        if c == '.' || c == '\\' {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    std::borrow::Cow::Owned(escaped)
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
    if is_same_or_subdomain_fqdn(
        &owner_trimmed.to_ascii_lowercase(),
        &zone_trimmed.to_ascii_lowercase(),
    ) {
        return format!("{}.", owner_trimmed);
    }

    format!("{}.{}.", owner_trimmed, zone_trimmed)
}

/// [`to_owner_fqdn`] normalized for display: trimmed and lowercased.
pub fn to_display_owner_fqdn(name: &str, zone: &str) -> String {
    to_fqdn_lowercase(&to_owner_fqdn(name.trim(), zone))
}

/// Inverse of [`to_owner_fqdn`]: reduce an owner name to the relative form
/// record rows encode (`@` at the apex), lowercased since record lookups bind
/// the lowercase form. `None` when the name resolves outside `zone`.
pub fn to_encoded_owner_name(name: &str, zone: &str) -> Option<String> {
    let owner = to_owner_fqdn(name, zone).to_ascii_lowercase();
    let zone_fqdn = to_fqdn(zone).to_ascii_lowercase();

    if owner == zone_fqdn {
        return Some("@".to_string());
    }

    let owner_labels = label_vec(&owner)?;
    let zone_labels = label_vec(&zone_fqdn)?;
    if owner_labels.len() <= zone_labels.len() || !is_label_suffix(&owner_labels, &zone_labels) {
        return None;
    }

    Some(
        owner_labels[..owner_labels.len() - zone_labels.len()]
            .iter()
            .map(|label| escape_presentation_label(label))
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// Whether `name` equals `zone` or is a subdomain of it, compared label by
/// label so an escaped dot cannot pose as a label boundary. Both sides must
/// already share the same case and trailing-dot form.
pub fn is_same_or_subdomain_fqdn(name: &str, zone: &str) -> bool {
    match (label_vec(name), label_vec(zone)) {
        (Some(name_labels), Some(zone_labels)) => is_label_suffix(&name_labels, &zone_labels),
        _ => false,
    }
}

fn label_vec(name: &str) -> Option<Vec<std::borrow::Cow<'_, str>>> {
    presentation_labels(name).ok().map(Iterator::collect)
}

fn is_label_suffix(
    name_labels: &[std::borrow::Cow<'_, str>],
    suffix: &[std::borrow::Cow<'_, str>],
) -> bool {
    name_labels.len() >= suffix.len() && name_labels[name_labels.len() - suffix.len()..] == *suffix
}

/// Whether `name` refers to the zone apex (`@` or the zone name itself).
pub fn is_apex_name(name: &str, zone_name: &str) -> bool {
    name == "@" || to_fqdn(name).eq_ignore_ascii_case(&to_fqdn(zone_name))
}

mod error;
mod owner_name;
mod zone_name;

pub use error::ParseNameError;
pub use owner_name::OwnerName;
pub use zone_name::ZoneName;

#[cfg(test)]
mod tests;
