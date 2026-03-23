use crate::socket::client::DaemonSocketClient;
use crate::socket::dto::DaemonCommandKind;
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand, Debug)]
pub enum DeleteCommand {
    /// Delete a zone
    Zone {
        /// The name of the zone
        name: String,
    },

    /// Delete a record
    Record {
        /// The name of the record
        name: String,
        /// The record type
        #[arg(long,
            aliases = ["type"]
        )]
        record_type: String,
    },
}

pub async fn handle_command(subcommand: DeleteCommand) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    match subcommand {
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
