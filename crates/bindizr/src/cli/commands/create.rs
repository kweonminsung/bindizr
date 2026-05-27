use crate::socket::client::DaemonSocketClient;
use crate::socket::types::DaemonCommandKind;
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand, Debug)]
pub(crate) enum CreateCommand {
    /// Create a zone
    Zone {
        /// Zone name
        #[arg(long)]
        name: String,
        /// Primary nameserver
        #[arg(long)]
        primary_ns: String,
        /// Admin email
        #[arg(long)]
        admin_email: String,
        /// TTL
        #[arg(long)]
        ttl: i32,
        /// Serial number (optional, auto-generated if not provided)
        #[arg(long)]
        serial: Option<i32>,
    },

    /// Create a record
    Record {
        /// Record name
        #[arg(long)]
        name: String,
        /// Record type (A, AAAA, CNAME, MX, etc.)
        #[arg(
            long,
            aliases = ["type"]
        )]
        record_type: String,
        /// Record value
        #[arg(long)]
        value: String,
        /// Zone name
        #[arg(long,
            aliases = ["zone"]
        )]
        zone_name: String,
        /// TTL (optional)
        #[arg(long)]
        ttl: Option<i32>,
        /// Priority (for MX records)
        #[arg(long)]
        priority: Option<i32>,
    },
}

pub(crate) async fn handle_command(subcommand: CreateCommand) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    match subcommand {
        CreateCommand::Zone {
            name,
            primary_ns,
            admin_email,
            ttl,
            serial,
        } => {
            let data = json!({
                "name": name,
                "primary_ns": primary_ns,
                "admin_email": admin_email,
                "ttl": ttl,
                "serial": serial,
            });
            let response = client
                .send_command(DaemonCommandKind::CreateZone, Some(data))
                .await?;
            println!("{}", response.message);
        }
        CreateCommand::Record {
            name,
            record_type,
            value,
            zone_name,
            ttl,
            priority,
        } => {
            let data = json!({
                "name": name,
                "record_type": record_type,
                "value": value,
                "zone_name": zone_name,
                "ttl": ttl,
                "priority": priority,
            });
            let response = client
                .send_command(DaemonCommandKind::CreateRecord, Some(data))
                .await?;
            println!("{}", response.message);
        }
    }

    Ok(())
}
