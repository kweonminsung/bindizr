use clap::Subcommand;
use serde_json::json;

use crate::socket::{client::DaemonSocketClient, types::DaemonCommandKind};

#[derive(Subcommand, Debug)]
pub(crate) enum DeleteCommand {
    /// Delete a zone
    Zone {
        /// The name of the zone
        name: String,
    },

    /// Delete a record
    Record {
        /// The record ID
        record_id: i32,
    },
}

pub(crate) async fn handle_command(subcommand: DeleteCommand) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    match subcommand {
        DeleteCommand::Zone { name } => {
            let response = client
                .send_command(DaemonCommandKind::DeleteZone, Some(json!({ "name": name })))
                .await?;
            println!("{}", response.message);
        }
        DeleteCommand::Record { record_id } => {
            let response = client
                .send_command(
                    DaemonCommandKind::DeleteRecord,
                    Some(json!({ "id": record_id })),
                )
                .await?;
            println!("{}", response.message);
        }
    }

    Ok(())
}
