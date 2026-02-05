use crate::{
    log_debug,
    socket::{client::DaemonSocketClient, dto::DaemonCommandKind},
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

pub async fn handle_command(subcommand: DnsCommand) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    match subcommand {
        DnsCommand::Write => write_dns_config(&client).await,
        DnsCommand::Reload => reload_dns_config(&client).await,
        DnsCommand::Status => get_dns_status(&client).await,
    }
}

async fn write_dns_config(client: &DaemonSocketClient) -> Result<(), String> {
    let res = client
        .send_command(DaemonCommandKind::DnsWriteConfig, None)
        .await?;

    log_debug!("DNS configuration write result: {:?}", res);

    Ok(())
}

async fn reload_dns_config(client: &DaemonSocketClient) -> Result<(), String> {
    let res = client
        .send_command(DaemonCommandKind::DnsReload, None)
        .await?;

    log_debug!("DNS configuration reload result: {:?}", res);

    Ok(())
}

async fn get_dns_status(client: &DaemonSocketClient) -> Result<(), String> {
    let res = client
        .send_command(DaemonCommandKind::DnsStatus, None)
        .await?;

    log_debug!("DNS status result: {:?}", res);

    if let Some(status) = res.data.get("status") {
        println!("DNS Status: {}", status);
    } else {
        println!("DNS Status: No status available");
    }

    Ok(())
}
