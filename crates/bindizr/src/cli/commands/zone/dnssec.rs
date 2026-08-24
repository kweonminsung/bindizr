//! The `zone dnssec` subcommands.

use bindizr_service::types::{
    DisableDnssecRequest, DnssecRecordInfo, EnableDnssecRequest, GetDnssecStatusResponse,
    RolloverDnssecRequest,
};
use clap::Subcommand;

use crate::{
    cli::{error::CliError, output::parse_response},
    socket::{
        client::DaemonSocketClient,
        types::{
            DaemonCommandKind, DisableZoneDnssecParams, EnableZoneDnssecParams,
            RolloverZoneDnssecParams, ZoneNameParams,
        },
    },
};

/// Subcommands for managing a zone's DNSSEC signing.
#[derive(Subcommand, Debug)]
pub(crate) enum ZoneDnssecCommand {
    /// Enable DNSSEC: generate a signing key and sign the zone
    Enable {
        /// The name of the zone
        name: String,
        /// Signing algorithm: ecdsap256sha256 (default) or ed25519
        #[arg(long, value_name = "ALG")]
        algorithm: Option<String>,
        /// Denial-of-existence mode: nsec (default) or nsec3 (fixed at
        /// enable time)
        #[arg(long, value_name = "nsec|nsec3")]
        denial: Option<String>,
        /// Generate split KSK/ZSK keys instead of one CSK, so the ZSK rolls
        /// without touching the parent zone's DS
        #[arg(long)]
        split_keys: bool,
    },
    /// Disable DNSSEC: delete the zone's keys and signatures. Remove the DS
    /// record from the parent zone and wait out its TTL first, or validating
    /// resolvers will treat the zone as bogus
    Disable {
        /// The name of the zone
        name: String,
        /// Confirm the zone may go insecure: the DS record has been removed
        /// from the parent zone and its TTL has passed
        #[arg(long)]
        confirm_insecure: bool,
    },
    /// Show a zone's DNSSEC status (keys, DS records, signature expiry)
    Status {
        /// The name of the zone
        name: String,
    },
    /// Print a zone's DS records for pasting into the parent zone
    Ds {
        /// The name of the zone
        name: String,
    },
    /// Print the derived records of a zone's signed view (DNSKEY, RRSIG,
    /// NSEC chain, CDS/CDNSKEY), as dig would show them
    Records {
        /// The name of the zone
        name: String,
    },
    /// Re-sign a zone from scratch, discarding stored signatures
    Sign {
        /// The name of the zone
        name: String,
    },
    /// Roll a zone's signing key: pre-publish a replacement, then promote it
    Rollover {
        #[command(subcommand)]
        subcommand: ZoneDnssecRolloverCommand,
    },
}

/// Subcommands for rolling a zone's signing keys.
#[derive(Subcommand, Debug)]
pub(crate) enum ZoneDnssecRolloverCommand {
    /// Pre-publish a replacement key: it joins the DNSKEY RRset and
    /// CDS/CDNSKEY set but signs no zone data until `ds-seen` promotes it
    Start {
        /// The name of the zone
        name: String,
        /// Which key to roll: required for split-key zones (ksk or zsk),
        /// omitted for CSK zones
        #[arg(long, value_name = "ksk|zsk")]
        role: Option<String>,
    },
    /// Confirm the new DS has been seen at the parent (and its TTL has
    /// passed): promotes the pre-published key and retires the one it
    /// replaces. ZSK rollovers involve no DS and promote automatically
    DsSeen {
        /// The name of the zone
        name: String,
    },
}

pub(super) async fn handle_command(
    client: &DaemonSocketClient,
    subcommand: ZoneDnssecCommand,
) -> Result<(), CliError> {
    match subcommand {
        ZoneDnssecCommand::Enable {
            name,
            algorithm,
            denial,
            split_keys,
        } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneDnssecEnable,
                    EnableZoneDnssecParams {
                        zone_name: name,
                        request: EnableDnssecRequest {
                            algorithm,
                            denial,
                            split_keys,
                        },
                    },
                )
                .await?;
            println!("{}", response.message);
            print_status(&response.data)?;
        }
        ZoneDnssecCommand::Disable {
            name,
            confirm_insecure,
        } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneDnssecDisable,
                    DisableZoneDnssecParams {
                        zone_name: name,
                        request: DisableDnssecRequest { confirm_insecure },
                    },
                )
                .await?;
            println!("{}", response.message);
        }
        ZoneDnssecCommand::Status { name } => {
            let response = client
                .send_command(DaemonCommandKind::ZoneDnssecStatus, ZoneNameParams { name })
                .await?;
            print_status(&response.data)?;
        }
        ZoneDnssecCommand::Ds { name } => {
            let response = client
                .send_command(DaemonCommandKind::ZoneDnssecStatus, ZoneNameParams { name })
                .await?;
            print_ds_records(&response.data)?;
        }
        ZoneDnssecCommand::Records { name } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneDnssecRecords,
                    ZoneNameParams { name },
                )
                .await?;
            print_dnssec_records(&response.data)?;
        }
        ZoneDnssecCommand::Sign { name } => {
            let response = client
                .send_command(DaemonCommandKind::ZoneDnssecSign, ZoneNameParams { name })
                .await?;
            println!("{}", response.message);
        }
        ZoneDnssecCommand::Rollover { subcommand } => match subcommand {
            ZoneDnssecRolloverCommand::Start { name, role } => {
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneDnssecRolloverStart,
                        RolloverZoneDnssecParams {
                            zone_name: name,
                            request: RolloverDnssecRequest { role },
                        },
                    )
                    .await?;
                println!("{}", response.message);
                print_status(&response.data)?;
            }
            ZoneDnssecRolloverCommand::DsSeen { name } => {
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneDnssecRolloverDsSeen,
                        ZoneNameParams { name },
                    )
                    .await?;
                println!("{}", response.message);
                print_status(&response.data)?;
            }
        },
    }

    Ok(())
}

fn print_status(data: &serde_json::Value) -> Result<(), String> {
    let status: GetDnssecStatusResponse = parse_response(data)?;

    println!("Zone: {}", status.zone_name);
    println!(
        "DNSSEC: {}",
        if status.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    if status.enabled {
        println!("Denial of existence: {}", status.denial.to_uppercase());
    }
    println!("Serial: {}", status.serial);
    if let Some(expires_at) = status.earliest_signature_expires_at {
        println!(
            "Earliest signature expiry: {}",
            expires_at.format("%Y-%m-%d %H:%M:%S")
        );
    }

    if status.keys.is_empty() {
        return Ok(());
    }

    println!("Keys:");
    println!(
        "{:<5} {:<5} {:<10} {:<18} {:<9} DNSKEY",
        "ID", "ROLE", "STATE", "ALGORITHM", "KEY TAG"
    );
    println!("{}", "-".repeat(100));
    for key in &status.keys {
        println!(
            "{:<5} {:<5} {:<10} {:<18} {:<9} {}",
            key.id, key.role, key.state, key.algorithm, key.key_tag, key.dnskey
        );
    }

    println!("DS records (register in the parent zone):");
    for ds in &status.ds_records {
        println!("  {}", ds.presentation);
    }

    Ok(())
}

fn print_dnssec_records(data: &serde_json::Value) -> Result<(), String> {
    let records: Vec<DnssecRecordInfo> = parse_response(data)?;

    if records.is_empty() {
        println!("No DNSSEC records found");
        return Ok(());
    }

    // dig-style master-file lines, so the output reads like a transfer.
    for record in &records {
        println!(
            "{} {} IN {} {}",
            record.name, record.ttl, record.record_type, record.rdata
        );
    }

    Ok(())
}

fn print_ds_records(data: &serde_json::Value) -> Result<(), String> {
    let status: GetDnssecStatusResponse = parse_response(data)?;

    if status.ds_records.is_empty() {
        println!("No DS records found");
        return Ok(());
    }

    // Plain presentation lines only, so the output pastes into a parent zone.
    for ds in &status.ds_records {
        println!("{}", ds.presentation);
    }

    Ok(())
}
