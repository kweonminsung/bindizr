use std::net::{IpAddr, SocketAddr};

use crate::{config, log_warn};

pub(crate) fn secondary_servers_from_config() -> Vec<IpAddr> {
    parse_ip_list_with_socket_fallback(&config::get_bindizr_config().dns.secondary_addrs)
}

pub(crate) fn is_client_allowed(client_ip: IpAddr, allowed_ips: &[IpAddr]) -> bool {
    allowed_ips.is_empty() || allowed_ips.contains(&client_ip)
}

fn parse_ip_list_with_socket_fallback(raw: &str) -> Vec<IpAddr> {
    raw.split(',')
        .filter_map(|item| {
            let trimmed = item.trim();
            if trimmed.is_empty() {
                return None;
            }

            match trimmed.parse::<SocketAddr>() {
                Ok(addr) => Some(addr.ip()),
                Err(_) => match trimmed.parse::<IpAddr>() {
                    Ok(ip) => Some(ip),
                    Err(_) => {
                        log_warn!("Ignoring invalid IP address in DNS ACL config: {}", trimmed);
                        None
                    }
                },
            }
        })
        .collect()
}
