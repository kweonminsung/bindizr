use crate::{
    daemon::{self, socket::client::DAEMON_SOCKET_CLIENT},
    database::model::api_token::ApiToken,
    log_debug,
};
use chrono::DateTime;
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand, Debug)]
pub enum TokenCommand {
    /// Create a new API token
    Create {
        /// Description of the token
        #[arg(long, value_name = "TEXT")]
        description: Option<String>,
        /// Number of days until the token expires (default: never expires)
        #[arg(long, value_name = "N", default_value_t = 0)]
        expires_in_days: i64,
    },
    /// List all API tokens
    List,
    /// Delete an API token by ID
    Delete {
        /// ID of the token to delete
        token_id: i32,
    },
}

pub fn handle_command(subcommand: TokenCommand) -> Result<(), String> {
    daemon::socket::client::initialize();

    match subcommand {
        TokenCommand::Create {
            description,
            expires_in_days,
        } => create_token(description, Some(expires_in_days)),
        TokenCommand::List => list_tokens(),
        TokenCommand::Delete { token_id } => delete_token(token_id),
    }
}

fn create_token(description: Option<String>, expires_in_days: Option<i64>) -> Result<(), String> {
    // Create socket request
    let res = DAEMON_SOCKET_CLIENT.send_command(
        "token_create",
        Some(json!({
            "description": description,
            "expires_in_days": expires_in_days,
        })),
    )?;

    log_debug!("Token creation result: {:?}", res);

    let token: ApiToken = serde_json::from_value(res.data)
        .map_err(|e| format!("Failed to parse token creation response: {}", e))?;

    // Print token details
    println!("API token created successfully:");
    println!("ID: {}", token.id);
    println!("Token: {}", token.token);
    if let Some(desc) = token.description {
        println!("Description: {}", desc);
    }
    println!(
        "Created at: {}",
        DateTime::parse_from_rfc3339(&token.created_at)
            .map_err(|e| format!("Failed to parse created_at: {}", e))?
            .format("%Y-%m-%d %H:%M:%S")
    );
    if let Some(expires) = token.expires_at {
        println!(
            "Expires at: {}",
            DateTime::parse_from_rfc3339(&expires)
                .map_err(|e| format!("Failed to parse expires_at: {}", e))?
                .format("%Y-%m-%d %H:%M:%S")
        );
    } else {
        println!("Expires at: Never");
    }

    Ok(())
}

fn list_tokens() -> Result<(), String> {
    // Create socket request
    let res = DAEMON_SOCKET_CLIENT.send_command("token_list", None)?;

    log_debug!("Token list result: {:?}", res);

    let tokens: Vec<ApiToken> = serde_json::from_value(res.data)
        .map_err(|e| format!("Failed to parse token list response: {}", e))?;

    if tokens.is_empty() {
        println!("No API tokens found");
        return Ok(());
    }

    println!("API Tokens:");
    println!(
        "{:<5} {:<40} {:<20} {:<20}",
        "ID", "TOKEN", "DESCRIPTION", "EXPIRES AT"
    );
    println!("{}", "-".repeat(85));

    for token in tokens {
        let desc = token.description.unwrap_or_else(|| "-".to_string());
        let expires = token
            .expires_at
            .map(|dt| {
                DateTime::parse_from_rfc3339(&dt)
                    .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|_| "Invalid date".to_string())
            })
            .unwrap_or_else(|| "Never".to_string());

        println!(
            "{:<5} {:<40} {:<20} {:<20}",
            token.id, token.token, desc, expires
        );
    }

    Ok(())
}

fn delete_token(token_id: i32) -> Result<(), String> {
    // Create socket request
    let res = DAEMON_SOCKET_CLIENT.send_command("token_delete", Some(json!({ "id": token_id })))?;

    log_debug!("Token deletion result: {:?}", res);

    println!("Token deleted successfully");
    Ok(())
}
