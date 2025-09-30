use crate::{database::model::api_token::ApiToken, log_debug, socket::client::DaemonSocketClient};
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
        #[arg(long, value_name = "N")]
        expires_in_days: Option<i64>,
    },
    /// List all API tokens
    List,
    /// Delete an API token by ID
    Delete {
        /// ID of the token to delete
        token_id: i32,
    },
}

pub async fn handle_command(subcommand: TokenCommand) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    match subcommand {
        TokenCommand::Create {
            description,
            expires_in_days,
        } => create_token(&client, description, expires_in_days).await,
        TokenCommand::List => list_tokens(&client).await,
        TokenCommand::Delete { token_id } => delete_token(&client, token_id).await,
    }
}

async fn create_token(
    client: &DaemonSocketClient,
    description: Option<String>,
    expires_in_days: Option<i64>,
) -> Result<(), String> {
    // Create socket request
    let res = client
        .send_command(
            "token_create",
            Some(json!({
                "description": description,
                "expires_in_days": expires_in_days,
            })),
        )
        .await?;

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
        &token.created_at.format("%Y-%m-%d %H:%M:%S")
    );
    if let Some(expires) = token.expires_at {
        println!("Expires at: {}", &expires.format("%Y-%m-%d %H:%M:%S"));
    } else {
        println!("Expires at: Never");
    }

    Ok(())
}

async fn list_tokens(client: &DaemonSocketClient) -> Result<(), String> {
    // Create socket request
    let res = client.send_command("token_list", None).await?;

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
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "Never".to_string());

        println!(
            "{:<5} {:<40} {:<20} {:<20}",
            token.id, token.token, desc, expires
        );
    }

    Ok(())
}

async fn delete_token(client: &DaemonSocketClient, token_id: i32) -> Result<(), String> {
    // Create socket request
    let res = client
        .send_command("token_delete", Some(json!({ "id": token_id })))
        .await?;

    log_debug!("Token deletion result: {:?}", res);

    println!("Token deleted successfully");
    Ok(())
}
