//! The `zone dnssec` subcommands.

use bindizr_service::types::{
    EnableDnssecRequest, ExportDnssecKeysResponse, GetDnssecStatusResponse, ImportDnssecKeyRequest,
    RolloverDnssecRequest, SetDnssecTimingRequest, VerifyDnssecResponse,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{
            DnssecCheckRow, DnssecKeyRow, OutputFormat, parse_response, print_response, print_table,
        },
    },
    socket::{
        client::DaemonSocketClient,
        types::{
            DaemonCommandKind, DsSeenZoneDnssecParams, EnableZoneDnssecParams,
            ImportZoneDnssecKeyParams, RolloverZoneDnssecParams, TimingZoneDnssecParams,
            ZoneNameParams,
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
        /// Signing algorithm: ecdsap256sha256 (default), ecdsap384sha384, ed25519, ed448, rsasha256, or rsasha512
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
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Publish the RFC 8078 delete CDS/CDNSKEY pair, asking a CDS-consuming
    /// parent to drop the zone's DS: the first step of going insecure
    Withdraw {
        /// The name of the zone
        name: String,
        /// Cancel a published withdrawal instead
        #[arg(long)]
        cancel: bool,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Disable DNSSEC: delete the zone's keys and signatures. Remove the DS
    /// record from the parent zone and wait out its TTL first, or validating
    /// resolvers will treat the zone as bogus
    Disable {
        /// The name of the zone
        name: String,
    },
    /// Show a zone's DNSSEC status (keys, DS records, signature expiry)
    Status {
        /// The name of the zone
        name: String,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Print a zone's DS records for pasting into the parent zone
    Ds {
        /// The name of the zone
        name: String,
    },
    /// Re-sign a zone from scratch, discarding stored signatures
    Sign {
        /// The name of the zone
        name: String,
    },
    /// Verify the zone's DNSSEC state (keys, signatures, denial chain, and
    /// the parent DS when dnssec.parent_ds_resolver is set)
    Verify {
        /// The name of the zone
        name: String,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Roll a zone's signing key: pre-publish a replacement, then promote it
    Rollover {
        #[command(subcommand)]
        subcommand: ZoneDnssecRolloverCommand,
    },
    /// Import or export the zone's raw keys (BIND `K*.key`/`K*.private` form)
    Keys {
        #[command(subcommand)]
        subcommand: ZoneDnssecKeysCommand,
    },
    /// Replace the zone's timing overrides; an omitted flag reverts that
    /// knob to the global [dnssec] config
    Timing {
        /// The name of the zone
        name: String,
        /// Days a new signature stays valid
        #[arg(long, value_name = "DAYS")]
        signature_validity_days: Option<u32>,
        /// Re-sign when a signature has fewer than this many days left
        #[arg(long, value_name = "DAYS")]
        signature_refresh_days: Option<u32>,
        /// Days an active ZSK may sign before the scheduler rolls it
        /// (0 disables scheduled rolls for this zone)
        #[arg(long, value_name = "DAYS")]
        zsk_lifetime_days: Option<u32>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
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
        /// omitted for CSK zones and algorithm rollovers
        #[arg(long, value_name = "ksk|zsk")]
        role: Option<String>,
        /// Roll to this algorithm instead (replaces every key; the zone is
        /// double-signed until the old keys leave)
        #[arg(long, value_name = "ALG")]
        algorithm: Option<String>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Confirm the new DS has been seen at the parent (and its TTL has
    /// passed): promotes the pre-published key and retires the one it
    /// replaces. ZSK rollovers involve no DS and promote automatically
    DsSeen {
        /// The name of the zone
        name: String,
        /// Skip the parent DS verification against dnssec.parent_ds_resolver
        #[arg(long)]
        force: bool,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
}

/// Subcommands for moving raw key material in and out of bindizr.
#[derive(Subcommand, Debug)]
pub(crate) enum ZoneDnssecKeysCommand {
    /// Print the zone's keys in BIND key-file form, private halves
    /// included — redirect somewhere with tight permissions
    Export {
        /// The name of the zone
        name: String,
    },
    /// Import a BIND key pair as an active key and re-sign the zone: the
    /// migration path for a zone already signed elsewhere
    Import {
        /// The name of the zone
        name: String,
        /// Path to the K*.key file (the DNSKEY record)
        #[arg(long, value_name = "FILE")]
        key: String,
        /// Path to the matching K*.private file
        #[arg(long, value_name = "FILE")]
        private: String,
        /// csk, ksk, or zsk; required for a SEP key (flags 257), a 256 key
        /// imports as zsk
        #[arg(long, value_name = "ROLE")]
        role: Option<String>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
}

pub(crate) async fn handle_command(
    client: &DaemonSocketClient,
    subcommand: ZoneDnssecCommand,
) -> Result<(), CliError> {
    match subcommand {
        ZoneDnssecCommand::Enable {
            name,
            algorithm,
            denial,
            split_keys,
            output,
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
            if output == OutputFormat::Table {
                println!("{}", response.message);
            }
            print_status(&response.data, output)?;
        }
        ZoneDnssecCommand::Withdraw {
            name,
            cancel,
            output,
        } => {
            let kind = if cancel {
                DaemonCommandKind::ZoneDnssecWithdrawCancel
            } else {
                DaemonCommandKind::ZoneDnssecWithdraw
            };
            let response = client.send_command(kind, ZoneNameParams { name }).await?;
            if output == OutputFormat::Table {
                println!("{}", response.message);
            }
            print_status(&response.data, output)?;
        }
        ZoneDnssecCommand::Keys { subcommand } => match subcommand {
            ZoneDnssecKeysCommand::Export { name } => {
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneDnssecKeysExport,
                        ZoneNameParams { name },
                    )
                    .await?;
                let exported: ExportDnssecKeysResponse =
                    parse_response(&response.data).map_err(CliError::from)?;
                print_key_material(&exported);
            }
            ZoneDnssecKeysCommand::Import {
                name,
                key,
                private,
                role,
                output,
            } => {
                let dnskey = std::fs::read_to_string(&key)
                    .map_err(|e| CliError::from(format!("Failed to read '{}': {}", key, e)))?;
                let private_key = std::fs::read_to_string(&private)
                    .map_err(|e| CliError::from(format!("Failed to read '{}': {}", private, e)))?;
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneDnssecKeysImport,
                        ImportZoneDnssecKeyParams {
                            zone_name: name,
                            request: ImportDnssecKeyRequest {
                                dnskey,
                                private_key,
                                role,
                            },
                        },
                    )
                    .await?;
                if output == OutputFormat::Table {
                    println!("{}", response.message);
                }
                print_status(&response.data, output)?;
            }
        },
        ZoneDnssecCommand::Timing {
            name,
            signature_validity_days,
            signature_refresh_days,
            zsk_lifetime_days,
            output,
        } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneDnssecTiming,
                    TimingZoneDnssecParams {
                        zone_name: name,
                        request: SetDnssecTimingRequest {
                            signature_validity_days,
                            signature_refresh_days,
                            zsk_lifetime_days,
                        },
                    },
                )
                .await?;
            if output == OutputFormat::Table {
                println!("{}", response.message);
            }
            print_status(&response.data, output)?;
        }
        ZoneDnssecCommand::Disable { name } => {
            let response = client
                .send_command(
                    DaemonCommandKind::ZoneDnssecDisable,
                    ZoneNameParams { name },
                )
                .await?;
            println!("{}", response.message);
        }
        ZoneDnssecCommand::Status { name, output } => {
            let response = client
                .send_command(DaemonCommandKind::ZoneDnssecStatus, ZoneNameParams { name })
                .await?;
            print_status(&response.data, output)?;
        }
        ZoneDnssecCommand::Ds { name } => {
            let response = client
                .send_command(DaemonCommandKind::ZoneDnssecStatus, ZoneNameParams { name })
                .await?;
            print_ds_records(&response.data)?;
        }
        ZoneDnssecCommand::Sign { name } => {
            let response = client
                .send_command(DaemonCommandKind::ZoneDnssecSign, ZoneNameParams { name })
                .await?;
            println!("{}", response.message);
        }
        ZoneDnssecCommand::Verify { name, output } => {
            let response = client
                .send_command(DaemonCommandKind::ZoneDnssecVerify, ZoneNameParams { name })
                .await?;
            let report: VerifyDnssecResponse = parse_response(&response.data)?;
            if output != OutputFormat::Table {
                print_response(&response.data, output, |report: &VerifyDnssecResponse| {
                    report.checks.iter().map(DnssecCheckRow::from).collect()
                })?;
            } else {
                println!(
                    "Zone {}: {}",
                    report.zone_name,
                    if report.ok {
                        "all checks passed"
                    } else {
                        "checks FAILED"
                    }
                );
                print_table(report.checks.iter().map(DnssecCheckRow::from).collect());
            }
            // Scripts read the exit status, so a failed report must not exit 0.
            if !report.ok {
                return Err(
                    format!("DNSSEC verification failed for zone {}", report.zone_name).into(),
                );
            }
        }
        ZoneDnssecCommand::Rollover { subcommand } => match subcommand {
            ZoneDnssecRolloverCommand::Start {
                name,
                role,
                algorithm,
                output,
            } => {
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneDnssecRolloverStart,
                        RolloverZoneDnssecParams {
                            zone_name: name,
                            request: RolloverDnssecRequest { role, algorithm },
                        },
                    )
                    .await?;
                if output == OutputFormat::Table {
                    println!("{}", response.message);
                }
                print_status(&response.data, output)?;
            }
            ZoneDnssecRolloverCommand::DsSeen {
                name,
                force,
                output,
            } => {
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneDnssecRolloverDsSeen,
                        DsSeenZoneDnssecParams { name, force },
                    )
                    .await?;
                if output == OutputFormat::Table {
                    println!("{}", response.message);
                }
                print_status(&response.data, output)?;
            }
        },
    }

    Ok(())
}

fn print_status(data: &serde_json::Value, output: OutputFormat) -> Result<(), String> {
    if output != OutputFormat::Table {
        return print_response(data, output, |status: &GetDnssecStatusResponse| {
            status.keys.iter().map(DnssecKeyRow::from).collect()
        });
    }

    let status: GetDnssecStatusResponse = parse_response(data)?;
    if !status.enabled {
        println!(
            "Zone {} (serial {}): DNSSEC disabled",
            status.zone_name, status.serial
        );
        return Ok(());
    }

    println!(
        "Zone {} (serial {}): DNSSEC enabled, {} denial",
        status.zone_name,
        status.serial,
        status.denial.to_uppercase()
    );
    if status.withdrawing {
        println!(
            "DS withdrawal published (RFC 8078): the parent should drop this zone's DS records."
        );
    }
    if let Some(expires_at) = status.earliest_signature_expires_at {
        println!(
            "Earliest signature expiry: {}",
            expires_at.format("%Y-%m-%d %H:%M:%S")
        );
    }
    let timing = &status.timing;
    let overridden = [
        ("validity", timing.signature_validity_days_override),
        ("refresh", timing.signature_refresh_days_override),
        ("zsk-lifetime", timing.zsk_lifetime_days_override),
    ]
    .iter()
    .filter(|(_, value)| value.is_some())
    .map(|(label, _)| *label)
    .collect::<Vec<_>>();
    println!(
        "Timing: validity {}d, refresh {}d, zsk-lifetime {}d{}",
        timing.signature_validity_days,
        timing.signature_refresh_days,
        timing.zsk_lifetime_days,
        if overridden.is_empty() {
            String::new()
        } else {
            format!(" ({} overridden)", overridden.join(", "))
        }
    );
    print_table(status.keys.iter().map(DnssecKeyRow::from).collect());
    if !status.ds_records.is_empty() {
        println!("DS records (register in the parent zone):");
        for ds in &status.ds_records {
            println!("  {}", ds.presentation);
        }
    }

    Ok(())
}

fn print_ds_records(data: &serde_json::Value) -> Result<(), String> {
    let status: GetDnssecStatusResponse = parse_response(data)?;

    if status.ds_records.is_empty() {
        println!("No DS records found");
        return Ok(());
    }

    if status.withdrawing {
        println!("# DS withdrawal published: do not register these at the parent.");
    }
    // Plain presentation lines only, so the output pastes into a parent zone.
    for ds in &status.ds_records {
        println!("{}", ds.presentation);
    }

    Ok(())
}

/// Print each key as its BIND file pair, headed by the file name BIND
/// tooling expects, so the stream splits cleanly into `K*.key`/`K*.private`.
fn print_key_material(exported: &ExportDnssecKeysResponse) {
    for (i, key) in exported.keys.iter().enumerate() {
        let mut base = format!(
            "K{}.+{:03}+{:05}",
            exported.zone_name, key.algorithm, key.key_tag
        );
        // Distinct keys may share (algorithm, tag); the suffix keeps names unique.
        let dup = exported.keys[..i]
            .iter()
            .filter(|k| k.algorithm == key.algorithm && k.key_tag == key.key_tag)
            .count();
        if dup > 0 {
            base.push_str(&format!(".{}", dup + 1));
        }
        println!("; {}.key ({}, tag {})", base, key.role, key.key_tag);
        println!("{}", key.dnskey_record);
        println!("; {}.private", base);
        println!("{}", key.private_key.trim_end());
    }
}
