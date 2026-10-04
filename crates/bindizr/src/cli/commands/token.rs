use bindizr_core::outln;
use bindizr_service::types::{
    CreateTokenRequest, CreatedTokenResponse, GetTokenResponse, MessageResponse, PaginatedResponse,
    TokenFilter,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, TokenRow, print_page, print_payload, print_response},
    },
    socket::{client, types::DaemonCommand},
};

/// Subcommands for managing API tokens.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub(crate) enum TokenCommand {
    /// Create a new API token in a role; the plaintext token is shown once, here
    #[command(after_help = "\
Examples:
  bindizr token create admin --role admin
  bindizr token create cluster-a --role external-dns-prod --expires-in-days 90")]
    Create {
        /// Unique name (letters, digits, '.', '_', '-'); how other commands refer to it
        #[arg(value_name = "TOKEN_NAME")]
        name: String,
        /// Role whose grants decide what the token may do (see `role grant`)
        #[arg(long, value_name = "ROLE_NAME")]
        role: String,
        /// Description of the token
        #[arg(long, value_name = "TEXT")]
        description: Option<String>,
        /// Days until the token expires, up to 36500 (default: never expires)
        #[arg(long, value_name = "N")]
        expires_in_days: Option<i64>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// List API tokens, every one or one role's
    #[command(alias = "ls")]
    List {
        /// Only the API tokens authenticating into this role
        #[arg(long, value_name = "ROLE_NAME")]
        role: Option<String>,
        /// Maximum number of tokens to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of tokens to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Delete an API token by name
    #[command(alias = "rm")]
    Delete {
        /// Name of the token to delete
        #[arg(value_name = "TOKEN_NAME")]
        name: String,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
}

/// Handle the `token` subcommand by dispatching to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: TokenCommand) -> Result<(), CliError> {
    match subcommand {
        TokenCommand::Create {
            name,
            description,
            expires_in_days,
            role,
            output,
        } => {
            let res = client::send_command::<CreatedTokenResponse>(DaemonCommand::CreateToken(
                CreateTokenRequest {
                    name,
                    description,
                    expires_in_days,
                    role_name: role,
                },
            ))
            .await?;
            log::debug!("Token creation result: {:?}", res);
            print_response(&res.data, output, |created| vec![TokenRow::from(created)])?;
        }
        TokenCommand::List {
            role,
            limit,
            offset,
            output,
        } => {
            let res = client::send_command::<PaginatedResponse<GetTokenResponse>>(
                DaemonCommand::ListTokens(TokenFilter {
                    role_name: role,
                    limit,
                    offset,
                }),
            )
            .await?;
            log::debug!("Token list result: {:?}", res);
            print_page(&res.data, output, |item| TokenRow::from(item))?;
        }
        TokenCommand::Delete { name, output } => {
            let res = client::send_command::<MessageResponse>(DaemonCommand::DeleteToken { name })
                .await?;
            log::debug!("Token deletion result: {:?}", res);
            match output {
                OutputFormat::Table => outln!("{}", res.message),
                _ => print_payload(&res.data, output)?,
            }
        }
    }
    Ok(())
}
