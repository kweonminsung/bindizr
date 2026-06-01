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

pub fn is_same_or_subdomain_fqdn(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{}", zone))
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
mod tests {
    use super::{
        NameError, email_to_soa_mailbox, is_same_or_subdomain_fqdn, split_presentation_labels,
        to_fqdn_lowercase,
    };

    // --- split_presentation_labels ---

    #[test]
    fn split_presentation_labels_single_label() {
        assert_eq!(
            split_presentation_labels("example").unwrap(),
            vec!["example".to_string()]
        );
    }

    #[test]
    fn split_presentation_labels_two_labels() {
        assert_eq!(
            split_presentation_labels("www.example").unwrap(),
            vec!["www".to_string(), "example".to_string()]
        );
    }

    #[test]
    fn split_presentation_labels_fqdn_with_trailing_dot() {
        // Trailing dot produces an empty final label, matching DNS wire format
        let labels = split_presentation_labels("example.com.").unwrap();
        assert_eq!(
            labels,
            vec!["example".to_string(), "com".to_string(), "".to_string()]
        );
    }

    #[test]
    fn split_presentation_labels_escaped_dot_is_not_separator() {
        let labels = split_presentation_labels(r"foo\.bar.example").unwrap();
        assert_eq!(
            labels,
            vec!["foo.bar".to_string(), "example".to_string()]
        );
    }

    #[test]
    fn split_presentation_labels_escaped_backslash() {
        let labels = split_presentation_labels(r"foo\\bar").unwrap();
        assert_eq!(labels, vec![r"foo\bar".to_string()]);
    }

    #[test]
    fn split_presentation_labels_multiple_escaped_chars() {
        let labels = split_presentation_labels(r"a\.b\.c").unwrap();
        assert_eq!(labels, vec!["a.b.c".to_string()]);
    }

    #[test]
    fn split_presentation_labels_dangling_escape_returns_error() {
        let err = split_presentation_labels(r"foo\").unwrap_err();
        assert_eq!(err, NameError::DanglingEscape);
    }

    #[test]
    fn split_presentation_labels_empty_string_returns_one_empty_label() {
        let labels = split_presentation_labels("").unwrap();
        assert_eq!(labels, vec!["".to_string()]);
    }

    #[test]
    fn split_presentation_labels_only_dot_returns_two_empty_labels() {
        let labels = split_presentation_labels(".").unwrap();
        assert_eq!(labels, vec!["".to_string(), "".to_string()]);
    }

    // --- to_fqdn_lowercase ---

    #[test]
    fn to_fqdn_lowercase_appends_trailing_dot() {
        assert_eq!(to_fqdn_lowercase("example.com"), "example.com.");
    }

    #[test]
    fn to_fqdn_lowercase_does_not_double_trailing_dot() {
        assert_eq!(to_fqdn_lowercase("example.com."), "example.com.");
    }

    #[test]
    fn to_fqdn_lowercase_lowercases_uppercase() {
        assert_eq!(to_fqdn_lowercase("EXAMPLE.COM"), "example.com.");
    }

    #[test]
    fn to_fqdn_lowercase_trims_surrounding_whitespace() {
        assert_eq!(to_fqdn_lowercase("  example.com  "), "example.com.");
    }

    #[test]
    fn to_fqdn_lowercase_mixed_case_with_trailing_dot() {
        assert_eq!(to_fqdn_lowercase("Ns1.Example.COM."), "ns1.example.com.");
    }

    #[test]
    fn to_fqdn_lowercase_root_dot() {
        // A single trailing dot represents the DNS root; should become "."
        assert_eq!(to_fqdn_lowercase("."), ".");
    }

    // --- is_same_or_subdomain_fqdn ---

    #[test]
    fn is_same_or_subdomain_fqdn_exact_match() {
        assert!(is_same_or_subdomain_fqdn("example.com.", "example.com."));
    }

    #[test]
    fn is_same_or_subdomain_fqdn_direct_subdomain() {
        assert!(is_same_or_subdomain_fqdn("www.example.com.", "example.com."));
    }

    #[test]
    fn is_same_or_subdomain_fqdn_deep_subdomain() {
        assert!(is_same_or_subdomain_fqdn(
            "a.b.c.example.com.",
            "example.com."
        ));
    }

    #[test]
    fn is_same_or_subdomain_fqdn_sibling_domain_returns_false() {
        assert!(!is_same_or_subdomain_fqdn(
            "other.com.",
            "example.com."
        ));
    }

    #[test]
    fn is_same_or_subdomain_fqdn_suffix_but_not_subdomain_returns_false() {
        // "notexample.com." ends with ".example.com." pattern only if the zone is prepended properly
        // "notexample.com." does NOT end with ".example.com." so should be false
        assert!(!is_same_or_subdomain_fqdn(
            "notexample.com.",
            "example.com."
        ));
    }

    #[test]
    fn is_same_or_subdomain_fqdn_empty_strings() {
        assert!(is_same_or_subdomain_fqdn("", ""));
    }

    // --- email_to_soa_mailbox ---

    #[test]
    fn email_to_soa_mailbox_simple_email() {
        assert_eq!(
            email_to_soa_mailbox("admin@example.com").unwrap(),
            "admin.example.com."
        );
    }

    #[test]
    fn email_to_soa_mailbox_local_part_with_dot_is_escaped() {
        // hostmaster.admin@example.com -> hostmaster\.admin.example.com.
        assert_eq!(
            email_to_soa_mailbox("hostmaster.admin@example.com").unwrap(),
            r"hostmaster\.admin.example.com."
        );
    }

    #[test]
    fn email_to_soa_mailbox_local_part_with_backslash_is_escaped() {
        assert_eq!(
            email_to_soa_mailbox(r"host\master@example.com").unwrap(),
            r"host\\master.example.com."
        );
    }

    #[test]
    fn email_to_soa_mailbox_strips_trailing_dot_from_domain() {
        assert_eq!(
            email_to_soa_mailbox("admin@example.com.").unwrap(),
            "admin.example.com."
        );
    }

    #[test]
    fn email_to_soa_mailbox_no_at_returns_error() {
        let err = email_to_soa_mailbox("adminexample.com").unwrap_err();
        assert_eq!(err, NameError::InvalidEmail);
    }

    #[test]
    fn email_to_soa_mailbox_multiple_at_returns_error() {
        let err = email_to_soa_mailbox("admin@host@example.com").unwrap_err();
        assert_eq!(err, NameError::InvalidEmail);
    }

    #[test]
    fn email_to_soa_mailbox_empty_local_part() {
        // "@example.com" has one '@' but empty local part - should succeed
        let result = email_to_soa_mailbox("@example.com").unwrap();
        assert_eq!(result, ".example.com.");
    }

    #[test]
    fn name_error_display_dangling_escape() {
        assert_eq!(
            NameError::DanglingEscape.to_string(),
            "domain name contains a dangling escape"
        );
    }

    #[test]
    fn name_error_display_invalid_email() {
        assert_eq!(
            NameError::InvalidEmail.to_string(),
            "email must contain exactly one @"
        );
    }
}
