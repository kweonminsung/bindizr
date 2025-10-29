pub(crate) fn to_fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    }
}

// pub(crate) fn is_fqdn(name: &str) -> bool {
//     name.ends_with('.')
// }

// pub(crate) fn normalize_domain_name(name: &str, zone_name: &str) -> String {
//     if name.ends_with('.') {
//         name.to_string()
//     } else if name.is_empty() || name == "@" {
//         format!("{}.", zone_name)
//     } else {
//         format!("{}.{}.", name, zone_name)
//     }
// }

pub(crate) fn normalize_email(email: &str) -> String {
    email.replace('@', ".")
}