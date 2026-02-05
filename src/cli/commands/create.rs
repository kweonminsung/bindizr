use crate::cli::output::{
    DnsInstanceRow, DnsKeyRow, OutputFormat, RecordRow, ZoneRow, print_output_with_table,
};
use crate::socket::client::DaemonSocketClient;
use crate::socket::dto::DaemonCommandKind;
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand, Debug)]
pub enum CreateCommand {
    /// Create a DNS instance
    Dns {
        /// Name of the DNS instance
        #[arg(short, long)]
        name: Option<String>,
        /// Host address
        #[arg(long)]
        host: String,
        /// RNDC port
        #[arg(long)]
        rndc_port: i32,
        /// RNDC key ID
        #[arg(long)]
        rndc_key_id: i32,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Create a DNS key
    DnsKey {
        /// Name of the DNS key
        #[arg(short, long)]
        name: Option<String>,
        /// Key type (RNDC or TSIG)
        #[arg(long)]
        key_type: String,
        /// Key algorithm
        #[arg(long)]
        key_algorithm: String,
        /// Key name
        #[arg(long)]
        key_name: String,
        /// Secret
        #[arg(long)]
        secret: String,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
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
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Create a record
    Record {
        /// Record name
        #[arg(long)]
        name: String,
        /// Record type (A, AAAA, CNAME, MX, etc.)
        #[arg(long)]
        record_type: String,
        /// Record value
        #[arg(long)]
        value: String,
        /// Zone ID
        #[arg(long)]
        zone_id: i32,
        /// TTL (optional)
        #[arg(long)]
        ttl: Option<i32>,
        /// Priority (for MX records)
        #[arg(long)]
        priority: Option<i32>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
}

pub async fn handle_command(subcommand: CreateCommand) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    match subcommand {
        CreateCommand::Dns {
            name,
            host,
            rndc_port,
            rndc_key_id,
            output,
        } => {
            let data = json!({
                "name": name,
                "host": host,
                "rndc_port": rndc_port,
                "rndc_key_id": rndc_key_id,
            });
            let response = client
                .send_command(DaemonCommandKind::CreateDns, Some(data))
                .await?;
            println!("{}", response.message);
            print_output_with_table(&response.data, output, |data| {
                vec![
                    DnsInstanceRow::from_json(data)
                        .unwrap_or_else(|_| panic!("Failed to parse DNS instance")),
                ]
            })?;
        }
        CreateCommand::DnsKey {
            name,
            key_type,
            key_algorithm,
            key_name,
            secret,
            output,
        } => {
            let data = json!({
                "name": name,
                "key_type": key_type,
                "key_algorithm": key_algorithm,
                "key_name": key_name,
                "secret": secret,
            });
            let response = client
                .send_command(DaemonCommandKind::CreateDnsKey, Some(data))
                .await?;
            println!("{}", response.message);
            print_output_with_table(&response.data, output, |data| {
                vec![
                    DnsKeyRow::from_json(data)
                        .unwrap_or_else(|_| panic!("Failed to parse DNS key")),
                ]
            })?;
        }
        CreateCommand::Zone {
            name,
            primary_ns,
            primary_ns_ip,
            primary_ns_ipv6,
            admin_email,
            ttl,
            serial,
            output,
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
            print_output_with_table(&response.data, output, |data| {
                vec![ZoneRow::from_json(data).unwrap_or_else(|_| panic!("Failed to parse zone"))]
            })?;
        }
        CreateCommand::Record {
            name,
            record_type,
            value,
            zone_id,
            ttl,
            priority,
            output,
        } => {
            let data = json!({
                "name": name,
                "record_type": record_type,
                "value": value,
                "zone_id": zone_id,
                "ttl": ttl,
                "priority": priority,
            });
            let response = client
                .send_command(DaemonCommandKind::CreateRecord, Some(data))
                .await?;
            println!("{}", response.message);
            print_output_with_table(&response.data, output, |data| {
                vec![
                    RecordRow::from_json(data).unwrap_or_else(|_| panic!("Failed to parse record")),
                ]
            })?;
        }
    }

    Ok(())
}
