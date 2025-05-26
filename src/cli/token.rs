use crate::{api::auth::AuthService, database::DATABASE_POOL};
use std::{collections::HashMap, process::exit};

pub fn help_message(subcommand: &str) -> String {
    match subcommand {
        "create" => "Usage: bindizr token create [OPTIONS]\n\
            \n\
            Create a new API token\n\
            \n\
            Options:\n\
            --description TEXT    Token description\n\
            --expires-in-days N   Token expiration in days (default: never expires)"
            .to_string(),
        "list" => "Usage: bindizr token list\n\
            \n\
            List all API tokens"
            .to_string(),
        "delete" => "Usage: bindizr token delete TOKEN_ID\n\
            \n\
            Delete an API token by ID"
            .to_string(),
        _ => "Usage: bindizr token COMMAND\n\
            \n\
            Commands:\n\
            create    Create a new API token\n\
            list      List all API tokens\n\
            delete    Delete an API token"
            .to_string(),
    }
}

pub fn handle_command(
    subcommand: Option<&str>,
    args: &[String],
    option_values: &HashMap<String, String>,
) -> Result<(), String> {
    match subcommand {
        Some("create") => create_token(args, option_values),
        Some("list") => list_tokens(),
        Some("delete") => delete_token(args),
        _ => {
            eprintln!("{}", help_message(""));
            exit(1);
        }
    }
}

fn create_token(args: &[String], options: &HashMap<String, String>) -> Result<(), String> {
    let description = options.get("--description");
    let expires_in_days =
        match options.get("--expires-in-days") {
            Some(days_str) => Some(days_str.parse::<i64>().map_err(|_| {
                "Invalid value for --expires-in-days, must be a number".to_string()
            })?),
            None => None,
        };

    // Generate token
    let token = AuthService::generate_token(
        &DATABASE_POOL,
        description.map(|s| s.as_str()),
        expires_in_days,
    )?;

    // Print token details
    println!("API token created successfully:");
    println!("ID: {}", token.id);
    println!("Token: {}", token.token);
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

fn list_tokens() -> Result<(), String> {
    let tokens = AuthService::list_tokens(&DATABASE_POOL)?;

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

fn delete_token(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("Token ID is required".to_string());
    }

    let token_id = args[0]
        .parse::<i32>()
        .map_err(|_| "Invalid token ID, must be a number".to_string())?;

    AuthService::delete_token(&DATABASE_POOL, token_id)?;

    println!("Token deleted successfully");
    Ok(())
}
