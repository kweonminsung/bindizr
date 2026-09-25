//! The `dnssec keys` subcommands: BIND key-file export and import.

use bindizr_core::outln;
use bindizr_service::types::{
    ExportDnssecKeysResponse, ImportDnssecKeyPair, ImportDnssecKeyRequest,
};
use clap::Subcommand;

use super::print_status;
use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, parse_response},
    },
    socket::{
        client,
        types::{DaemonCommandKind, ImportZoneDnssecKeysParams, NameParams},
    },
};

/// Subcommands for moving raw key material in and out of bindizr.
#[derive(Subcommand, Debug)]
pub(crate) enum DnssecKeysCommand {
    /// Print the zone's keys in BIND key-file form, private halves
    /// included — redirect somewhere with tight permissions
    #[command(after_help = "\
Examples:
  umask 077 && bindizr dnssec keys export example.com > example.com.keys

The output carries the private halves, so anyone who reads it can sign the
zone.")]
    Export {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
    },
    /// Import the zone's key set as BIND key pairs and sign it: one CSK
    /// pair, or a KSK pair and a ZSK pair for a split-key policy, plus any
    /// key a rollover still holds — each private file's timing places it.
    /// The migration path for a zone signed elsewhere; the zone must be
    /// unsigned
    #[command(after_help = "\
Examples:
  bindizr dnssec keys import example.com \\
    --key Kexample.com.+013+12345.key --private Kexample.com.+013+12345.private

  bindizr dnssec keys import example.com --policy split \\
    --key Kexample.com.+013+11111.key --private Kexample.com.+013+11111.private \\
    --key Kexample.com.+013+22222.key --private Kexample.com.+013+22222.private

Repeat --key and --private once per pair, in the same order: the Nth --private
is matched with the Nth --key.")]
    Import {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Path to a K*.key file (the DNSKEY record); repeat with --private
        /// for each pair
        #[arg(long, value_name = "FILE", required = true)]
        key: Vec<String>,
        /// Path to the matching K*.private file, in the same order as --key
        #[arg(long, value_name = "FILE", required = true)]
        private: Vec<String>,
        /// Policy the zone signs under (default: "default"); its algorithm
        /// and key layout decide what the keys must be
        #[arg(long, value_name = "POLICY_NAME")]
        policy: Option<String>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
}

/// Run the requested DNSSEC key import or export command.
pub(crate) async fn handle_command(subcommand: DnssecKeysCommand) -> Result<(), CliError> {
    match subcommand {
        DnssecKeysCommand::Export { name } => {
            let response =
                client::send_command(DaemonCommandKind::ExportDnssecKeys, NameParams { name })
                    .await?;
            let exported: ExportDnssecKeysResponse =
                parse_response(&response.data).map_err(CliError::from)?;
            print_key_material(&exported);
        }
        DnssecKeysCommand::Import {
            name,
            key,
            private,
            policy,
            output,
        } => {
            if key.len() != private.len() {
                return Err(CliError::from(format!(
                    "--key and --private must be given in pairs ({} and {})",
                    key.len(),
                    private.len()
                )));
            }
            let mut keys = Vec::with_capacity(key.len());
            for (key, private) in key.iter().zip(&private) {
                let dnskey = std::fs::read_to_string(key)
                    .map_err(|e| CliError::from(format!("Failed to read '{}': {}", key, e)))?;
                let private_key = std::fs::read_to_string(private)
                    .map_err(|e| CliError::from(format!("Failed to read '{}': {}", private, e)))?;
                keys.push(ImportDnssecKeyPair {
                    dnskey,
                    private_key,
                });
            }
            let response = client::send_command(
                DaemonCommandKind::ImportDnssecKeys,
                ImportZoneDnssecKeysParams {
                    zone_name: name,
                    request: ImportDnssecKeyRequest { keys, policy },
                },
            )
            .await?;
            print_status(&response.data, output)?;
        }
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
        outln!("; {}.key ({}, tag {})", base, key.role, key.key_tag);
        outln!("{}", key.dnskey_record);
        outln!("; {}.private", base);
        outln!("{}", key.private_key.trim_end());
    }
}
