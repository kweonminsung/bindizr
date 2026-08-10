use bindizr_core::{log_debug, model::api_token::ApiToken};
use clap::Subcommand;

use crate::{
    cli::error::CliError,
    socket::{
        client::DaemonSocketClient,
        types::{CreateTokenParams, DaemonCommandKind, TokenNameParams},
    },
};

/// Subcommands for managing API tokens.
#[derive(Subcommand, Debug)]
pub(crate) enum TokenCommand {
    /// Create a new API token
    Create {
        /// Unique token name (e.g. "external-dns"); used to reference the
        /// token in other commands
        #[arg(long)]
        name: String,
        /// Description of the token
        #[arg(long, value_name = "TEXT")]
        description: Option<String>,
        /// Number of days until the token expires (default: never expires)
        #[arg(long, value_name = "N")]
        expires_in_days: Option<i64>,
        /// Make the token global: it may manage every zone and the zone
        /// plane without policies. Fixed at creation.
        #[arg(long)]
        global: bool,
    },
    /// List all API tokens
    List,
    /// Delete an API token by name
    Delete {
        /// Name of the token to delete
        name: String,
    },
}

/// Handle the `token` subcommand by dispatching to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: TokenCommand) -> Result<(), CliError> {
    let client = DaemonSocketClient::new();

    match subcommand {
        TokenCommand::Create {
            name,
            description,
            expires_in_days,
            global,
        } => create_token(&client, name, description, expires_in_days, global).await,
        TokenCommand::List => list_tokens(&client).await,
        TokenCommand::Delete { name } => delete_token(&client, name).await,
    }
}

async fn create_token(
    client: &DaemonSocketClient,
    name: String,
    description: Option<String>,
    expires_in_days: Option<i64>,
    global: bool,
) -> Result<(), CliError> {
    let res = client
        .send_command(
            DaemonCommandKind::TokenCreate,
            CreateTokenParams {
                name,
                description,
                expires_in_days,
                global,
            },
        )
        .await?;

    log_debug!("Token creation result: {:?}", res);

    let token: ApiToken = serde_json::from_value(res.data)
        .map_err(|e| format!("Failed to parse token creation response: {}", e))?;

    println!("API token created successfully:");
    println!("Name: {}", token.name);
    println!("Token: {}", token.token);
    println!("Global: {}", if token.is_global { "yes" } else { "no" });
    if let Some(desc) = token.description {
        println!("Description: {}", desc);
    }
    println!(
        "Created at: {}",
        token.created_at.format("%Y-%m-%d %H:%M:%S")
    );
    if let Some(expires) = token.expires_at {
        println!("Expires at: {}", expires.format("%Y-%m-%d %H:%M:%S"));
    } else {
        println!("Expires at: Never");
    }

    Ok(())
}

async fn list_tokens(client: &DaemonSocketClient) -> Result<(), CliError> {
    let res = client
        .send_command(DaemonCommandKind::TokenList, ())
        .await?;

    log_debug!("Token list result: {:?}", res);

    let tokens: Vec<ApiToken> = serde_json::from_value(res.data)
        .map_err(|e| format!("Failed to parse token list response: {}", e))?;

    if tokens.is_empty() {
        println!("No API tokens found");
        return Ok(());
    }

    println!("API Tokens:");
    println!(
        "{:<25} {:<8} {:<20} {:<20}",
        "NAME", "GLOBAL", "DESCRIPTION", "EXPIRES AT"
    );
    println!("{}", "-".repeat(75));

    for token in tokens {
        let desc = token.description.unwrap_or_else(|| "-".to_string());
        let expires = token
            .expires_at
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "Never".to_string());

        println!(
            "{:<25} {:<8} {:<20} {:<20}",
            token.name,
            if token.is_global { "yes" } else { "no" },
            desc,
            expires
        );
    }

    Ok(())
}

async fn delete_token(client: &DaemonSocketClient, name: String) -> Result<(), CliError> {
    let res = client
        .send_command(DaemonCommandKind::TokenDelete, TokenNameParams { name })
        .await?;

    log_debug!("Token deletion result: {:?}", res);

    println!("Token deleted successfully");
    Ok(())
}
