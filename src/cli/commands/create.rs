use crate::socket::client::DaemonSocketClient;
use crate::socket::dto::DaemonCommandKind;
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand, Debug)]
pub enum CreateCommand {
    /// Create a DNS server
    Dns {
        /// Name of the DNS server
        #[arg(long)]
        name: String,
        /// Host address
        #[arg(long)]
        host: String,
        /// RNDC port
        #[arg(long, default_value = "953")]
        rndc_port: i32,
    },

    /// Create a DNS key
    Key {
        /// Name of the DNS key
        #[arg(long)]
        name: String,
        /// Key type (RNDC or TSIG)
        #[arg(
            long,
            aliases = ["type"]
        )]
        key_type: String,
        /// Key algorithm
        #[arg(
            long,
            aliases = ["algorithm", "alg"]
        )]
        key_algorithm: String,
        /// Secret
        #[arg(long)]
        secret: String,
    },

    /// Create a zone
    Zone {
        /// Zone name
        #[arg(long)]
        name: String,
        /// Primary nameserver
        #[arg(long)]
        primary_ns: String,
        /// Primary nameserver IPv4
        #[arg(long)]
        primary_ns_ip: Option<String>,
        /// Primary nameserver IPv6
        #[arg(long)]
        primary_ns_ipv6: Option<String>,
        /// Admin email
        #[arg(long)]
        admin_email: String,
        /// TTL
        #[arg(long)]
        ttl: i32,
        /// Serial number
        #[arg(long)]
        serial: i32,
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

pub async fn handle_command(subcommand: CreateCommand) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    match subcommand {
        CreateCommand::Dns {
            name,
            host,
            rndc_port,
        } => {
            let data = json!({
                "name": name,
                "host": host,
                "rndc_port": rndc_port,
            });
            let response = client
                .send_command(DaemonCommandKind::CreateDns, Some(data))
                .await?;
            println!("{}", response.message);
        }
        CreateCommand::Key {
            name,
            key_type,
            key_algorithm,
            secret,
        } => {
            let data = json!({
                "name": name,
                "key_type": key_type,
                "key_algorithm": key_algorithm,
                "secret": secret,
            });
            let response = client
                .send_command(DaemonCommandKind::CreateKey, Some(data))
                .await?;
            println!("{}", response.message);
        }
        CreateCommand::Zone {
            name,
            primary_ns,
            primary_ns_ip,
            primary_ns_ipv6,
            admin_email,
            ttl,
            serial,
        } => {
            let data = json!({
                "name": name,
                "primary_ns": primary_ns,
                "primary_ns_ip": primary_ns_ip,
                "primary_ns_ipv6": primary_ns_ipv6,
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
