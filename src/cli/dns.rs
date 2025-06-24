use crate::{
    daemon::{self, socket::client::DAEMON_SOCKET_CLIENT},
    log_debug,
};
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum DnsCommand {
    /// Write DNS configuration to the server
    Write,
    /// Reload DNS configuration on the server
    Reload,
    /// Get the status of the DNS service
    Status,
}

pub fn handle_command(subcommand: DnsCommand) -> Result<(), String> {
    daemon::socket::client::initialize();

    match subcommand {
        DnsCommand::Write => write_dns_config(),
        DnsCommand::Reload => reload_dns_config(),
        DnsCommand::Status => get_dns_status(),
    }
}

fn write_dns_config() -> Result<(), String> {
    let res = DAEMON_SOCKET_CLIENT.send_command("dns_write_config", None)?;

    log_debug!("DNS configuration write result: {:?}", res);

    Ok(())
}

fn reload_dns_config() -> Result<(), String> {
    let res = DAEMON_SOCKET_CLIENT.send_command("dns_reload", None)?;

    log_debug!("DNS configuration reload result: {:?}", res);

    Ok(())
}

fn get_dns_status() -> Result<(), String> {
    let res = DAEMON_SOCKET_CLIENT.send_command("dns_status", None)?;

    log_debug!("DNS status result: {:?}", res);

    if let Some(status) = res.data.get("status") {
        println!("DNS Status: {}", status);
    } else {
        println!("DNS Status: No status available");
    }

    Ok(())
}
