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

pub fn split_presentation_labels(name: &str) -> Result<Vec<String>, NameError> {
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

pub fn to_fqdn_lowercase(value: &str) -> String {
    format!(
        "{}.",
        value.trim().trim_end_matches('.').to_ascii_lowercase()
    )
}

pub fn to_fqdn(value: &str) -> String {
    format!("{}.", value.trim_end_matches('.'))
}

pub fn is_same_or_subdomain_fqdn(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{}", zone))
}

pub fn to_relative_domain(fqdn: &str, zone_name: &str) -> String {
    let fqdn = to_fqdn(fqdn);
    let zone = to_fqdn(zone_name);

    if fqdn.eq_ignore_ascii_case(&zone) {
        return "@".to_string();
    }

    let fqdn_lower = fqdn.to_ascii_lowercase();
    let zone_lower = zone.to_ascii_lowercase();

    if is_same_or_subdomain_fqdn(&fqdn_lower, &zone_lower) {
        let relative_part = &fqdn[..fqdn.len() - zone.len()];
        relative_part.trim_end_matches('.').to_string()
    } else {
        fqdn.trim_end_matches('.').to_string()
    }
}

pub fn is_in_bailiwick(name: &str, zone_name: &str) -> bool {
    let name = to_fqdn(name).to_ascii_lowercase();
    let zone = to_fqdn(zone_name).to_ascii_lowercase();

    is_same_or_subdomain_fqdn(&name, &zone)
}

pub fn is_apex_name(name: &str, zone_name: &str) -> bool {
    name == "@" || to_fqdn(name).eq_ignore_ascii_case(&to_fqdn(zone_name))
}

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

#[cfg(test)]
mod tests;
