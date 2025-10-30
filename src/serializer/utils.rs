pub fn to_fqdn(name: &str) -> String {
    name.trim_end_matches('.').to_string() + "."
}

// pub fn is_fqdn(name: &str) -> bool {
//     name.ends_with('.')
// }

pub fn to_relative_domain(fqdn: &str, zone_name: &str) -> String {
    let normalized_zone = to_fqdn(zone_name);

    if fqdn == normalized_zone {
        "@".to_string()
    } else if fqdn.ends_with(&normalized_zone) {
        let relative_part = &fqdn[..fqdn.len() - normalized_zone.len()];
        relative_part.trim_end_matches('.').to_string()
    } else {
        fqdn.trim_end_matches('.').to_string()
    }
}

pub fn to_bind_rname(email: &str) -> String {
    email.replace('@', ".").trim_end_matches('.').to_string() + "."
}
