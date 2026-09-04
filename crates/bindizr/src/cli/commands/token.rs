use bindizr_core::log_debug;
use bindizr_service::types::{CreateTokenRequest, GetTokenResponse};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, TokenRow, print_response},
    },
    socket::{
        client::DaemonSocketClient,
        types::{DaemonCommandKind, TokenNameParams},
    },
};

/// Subcommands for managing API tokens.
#[derive(Subcommand, Debug)]
pub(crate) enum TokenCommand {
    /// Create a new API token; the plaintext token is shown once, here
    Create {
        /// Unique token name (e.g. "external-dns"); used to reference the
        /// token in other commands
        #[arg(long, value_name = "TOKEN_NAME")]
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
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// List all API tokens
    #[command(alias = "ls")]
    List {
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Delete an API token by name
    #[command(alias = "rm")]
    Delete {
        /// Name of the token to delete
        #[arg(value_name = "TOKEN_NAME")]
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
            output,
        } => {
            let res = client
                .send_command(
                    DaemonCommandKind::TokenCreate,
                    CreateTokenRequest {
                        name,
                        description,
                        expires_in_days,
                        global,
                    },
                )
                .await?;

            log_debug!("Token creation result: {:?}", res);

            print_response(&res.data, output, |token: &GetTokenResponse| {
                vec![TokenRow::from(token)]
            })?;
        }
        TokenCommand::List { output } => {
            let res = client
                .send_command(DaemonCommandKind::TokenList, ())
                .await?;

            log_debug!("Token list result: {:?}", res);

            print_response(&res.data, output, |tokens: &Vec<GetTokenResponse>| {
                tokens.iter().map(TokenRow::from).collect()
            })?;
        }
        TokenCommand::Delete { name } => {
            let res = client
                .send_command(DaemonCommandKind::TokenDelete, TokenNameParams { name })
                .await?;

            log_debug!("Token deletion result: {:?}", res);

            println!("{}", res.message);
        }
    }

    Ok(())
}
