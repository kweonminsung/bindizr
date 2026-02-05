use crate::socket::client::DaemonSocketClient;
use crate::socket::dto::DaemonCommandKind;
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand, Debug)]
pub enum DeleteCommand {
    /// Delete a DNS instance
    Dns {
        /// The host address of the DNS instance
        host: String,
    },

    /// Delete a DNS key
    #[command(
        aliases = ["dns-key", "key", "keys"]
    )]
    DnsKey {
        /// The key name of the DNS key
        key_name: String,
    },

    /// Delete a zone
    #[command(
        aliases = ["zone"]
    )]
    Zone {
        /// The name of the zone
        name: String,
    },

    /// Delete a record
    #[command(
        aliases = ["record"]
    )]
    Record {
        /// The name of the record
        name: String,
        /// The record type
        #[arg(short = 't', long)]
        record_type: String,
    },
}

pub async fn handle_command(subcommand: DeleteCommand) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    match subcommand {
        DeleteCommand::Dns { host } => {
            let response = client
                .send_command(DaemonCommandKind::DeleteDns, Some(json!({ "host": host })))
                .await?;
            println!("{}", response.message);
        }
        DeleteCommand::DnsKey { key_name } => {
            let response = client
                .send_command(
                    DaemonCommandKind::DeleteDnsKey,
                    Some(json!({ "key_name": key_name })),
                )
                .await?;
            println!("{}", response.message);
        }
        DeleteCommand::Zone { name } => {
            let response = client
                .send_command(DaemonCommandKind::DeleteZone, Some(json!({ "name": name })))
                .await?;
            println!("{}", response.message);
        }
        DeleteCommand::Record { name, record_type } => {
            let response = client
                .send_command(
                    DaemonCommandKind::DeleteRecord,
                    Some(json!({ "name": name, "record_type": record_type })),
                )
                .await?;
            println!("{}", response.message);
        }
    }

    Ok(())
}
