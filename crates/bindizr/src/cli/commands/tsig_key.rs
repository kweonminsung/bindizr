use bindizr_core::log_debug;
use bindizr_service::types::{CreateTsigKeyRequest, GetTsigKeyResponse};
use clap::Subcommand;

use crate::{
    cli::error::CliError,
    socket::{
        client::DaemonSocketClient,
        types::{DaemonCommandKind, TsigKeyNameParams},
    },
};

/// Subcommands for managing TSIG keys used for nsupdate authentication.
#[derive(Subcommand, Debug)]
pub(crate) enum TsigKeyCommand {
    /// Create a TSIG key (generates a secret unless one is provided)
    Create {
        /// Key name; appears on the wire in the TSIG record (e.g. "update-key")
        #[arg(long)]
        name: String,
        /// HMAC algorithm: hmac-sha256 (default), hmac-sha384, hmac-sha512
        #[arg(long, value_name = "ALG")]
        algorithm: Option<String>,
        /// Existing base64 secret to import (omit to generate a random one)
        #[arg(long, value_name = "BASE64")]
        secret: Option<String>,
        /// Make the key global: it may update EVERY zone (all names, all
        /// types) without any policy. Effectively write access to all DNS
        /// data — use sparingly. Fixed at creation.
        #[arg(long)]
        global: bool,
    },
    /// List all TSIG keys (secrets are not shown; use `get`)
    #[command(alias = "ls")]
    List,
    /// Show one TSIG key including its secret
    Get {
        /// Name of the key
        name: String,
    },
    /// Delete a TSIG key (refused while zone TSIG policies still use it)
    Delete {
        /// Name of the key
        name: String,
    },
}

/// Handle the `tsig-key` subcommand by dispatching to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: TsigKeyCommand) -> Result<(), CliError> {
    let client = DaemonSocketClient::new();

    match subcommand {
        TsigKeyCommand::Create {
            name,
            algorithm,
            secret,
            global,
        } => create_tsig_key(&client, name, algorithm, secret, global).await,
        TsigKeyCommand::List => list_tsig_keys(&client).await,
        TsigKeyCommand::Get { name } => get_tsig_key(&client, name).await,
        TsigKeyCommand::Delete { name } => delete_tsig_key(&client, name).await,
    }
}

async fn create_tsig_key(
    client: &DaemonSocketClient,
    name: String,
    algorithm: Option<String>,
    secret: Option<String>,
    global: bool,
) -> Result<(), CliError> {
    let res = client
        .send_command(
            DaemonCommandKind::TsigKeyCreate,
            CreateTsigKeyRequest {
                name,
                algorithm,
                secret,
                global,
            },
        )
        .await?;

    log_debug!("TSIG key creation result: {:?}", res);

    let key: GetTsigKeyResponse = serde_json::from_value(res.data)
        .map_err(|e| format!("Failed to parse TSIG key creation response: {}", e))?;

    println!("TSIG key created successfully:");
    print_key(&key);
    if key.global {
        println!("Warning: this key can update every zone without any policy.");
    }

    Ok(())
}

async fn list_tsig_keys(client: &DaemonSocketClient) -> Result<(), CliError> {
    let res = client
        .send_command(DaemonCommandKind::TsigKeyList, ())
        .await?;

    log_debug!("TSIG key list result: {:?}", res);

    let keys: Vec<GetTsigKeyResponse> = serde_json::from_value(res.data)
        .map_err(|e| format!("Failed to parse TSIG key list response: {}", e))?;

    if keys.is_empty() {
        println!("No TSIG keys found");
        return Ok(());
    }

    println!("TSIG Keys:");
    println!(
        "{:<5} {:<30} {:<15} {:<8} {:<20}",
        "ID", "NAME", "ALGORITHM", "GLOBAL", "CREATED AT"
    );
    println!("{}", "-".repeat(84));

    for key in keys {
        println!(
            "{:<5} {:<30} {:<15} {:<8} {:<20}",
            key.id,
            key.name,
            key.algorithm,
            if key.global { "yes" } else { "no" },
            key.created_at.format("%Y-%m-%d %H:%M:%S")
        );
    }

    Ok(())
}

async fn get_tsig_key(client: &DaemonSocketClient, name: String) -> Result<(), CliError> {
    let res = client
        .send_command(DaemonCommandKind::TsigKeyGet, TsigKeyNameParams { name })
        .await?;

    log_debug!("TSIG key get result: {:?}", res);

    let key: GetTsigKeyResponse = serde_json::from_value(res.data)
        .map_err(|e| format!("Failed to parse TSIG key response: {}", e))?;

    print_key(&key);

    Ok(())
}

async fn delete_tsig_key(client: &DaemonSocketClient, name: String) -> Result<(), CliError> {
    let res = client
        .send_command(DaemonCommandKind::TsigKeyDelete, TsigKeyNameParams { name })
        .await?;

    log_debug!("TSIG key deletion result: {:?}", res);

    println!("TSIG key deleted successfully");
    Ok(())
}

fn print_key(key: &GetTsigKeyResponse) {
    println!("ID: {}", key.id);
    println!("Name: {}", key.name);
    println!("Algorithm: {}", key.algorithm);
    if let Some(secret) = &key.secret {
        println!("Secret: {}", secret);
    }
    println!("Global: {}", if key.global { "yes" } else { "no" });
    println!("Created at: {}", key.created_at.format("%Y-%m-%d %H:%M:%S"));
}
