use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A wildcard listen address is not connectable; probe it via loopback.
pub(crate) fn loopback_if_unspecified(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(a) if a.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(a) if a.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        addr => addr,
    }
}
