use std::net::{IpAddr, SocketAddr};

pub(crate) enum ParsedAddress {
    SocketAddr(SocketAddr),
    HostPort(String),
}

pub(crate) fn parse_address_target(value: &str, default_port: u16) -> ParsedAddress {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return ParsedAddress::SocketAddr(addr);
    }

    if let Ok(ip) = value.parse::<IpAddr>() {
        return ParsedAddress::SocketAddr(SocketAddr::new(ip, default_port));
    }

    if let Some(bracketed) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']'))
        && let Ok(ip) = bracketed.parse::<IpAddr>()
    {
        return ParsedAddress::SocketAddr(SocketAddr::new(ip, default_port));
    }

    let host_port = if has_explicit_port(value) || value.contains(':') {
        value.to_string()
    } else {
        format!("{}:{}", value, default_port)
    };

    ParsedAddress::HostPort(host_port)
}

fn has_explicit_port(value: &str) -> bool {
    if let Some((_, rest)) = value.strip_prefix('[').and_then(|v| v.split_once(']')) {
        return rest.strip_prefix(':').is_some_and(is_valid_port);
    }

    match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => is_valid_port(port),
        _ => false,
    }
}

fn is_valid_port(value: &str) -> bool {
    value.parse::<u16>().is_ok()
}

#[cfg(test)]
mod tests;
