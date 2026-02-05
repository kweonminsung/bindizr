use crate::socket::client::DaemonSocketClient;
use crate::socket::dto::DaemonCommandKind;
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand, Debug)]
pub enum DeleteCommand {
    /// Delete a DNS instance
    Dns {
        /// The ID of the DNS instance
        id: i32,
    },

    /// Delete a DNS key
    DnsKey {
        /// The ID of the DNS key
        id: i32,
    },

    /// Delete a zone
    Zone {
        /// The ID of the zone
        id: i32,
    },

    /// Delete a record
    Record {
        /// The ID of the record
        id: i32,
    },
}

pub async fn handle_command(subcommand: DeleteCommand) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    match subcommand {
        DeleteCommand::Dns { id } => {
            let response = client
                .send_command(DaemonCommandKind::DeleteDns, Some(json!({ "id": id })))
                .await?;
            println!("{}", response.message);
        }
        DeleteCommand::DnsKey { id } => {
            let response = client
                .send_command(DaemonCommandKind::DeleteDnsKey, Some(json!({ "id": id })))
                .await?;
            println!("{}", response.message);
        }
        DeleteCommand::Zone { id } => {
            let response = client
                .send_command(DaemonCommandKind::DeleteZone, Some(json!({ "id": id })))
                .await?;
            println!("{}", response.message);
        }
        DeleteCommand::Record { id } => {
            let response = client
                .send_command(DaemonCommandKind::DeleteRecord, Some(json!({ "id": id })))
                .await?;
            println!("{}", response.message);
        }
    }

    Ok(())
}
