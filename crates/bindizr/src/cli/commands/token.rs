use bindizr_core::outln;
use bindizr_service::types::{
    ApiTokenFilter, ApiTokenResponse, CreateApiTokenRequest, CreateApiTokenResponse,
    MessageResponse, PaginatedResponse,
};
use clap::Subcommand;

use crate::cli::error::CliError;
use crate::cli::output;
use crate::cli::output::{ApiTokenRow, OutputFormat};
use crate::socket::client;
use crate::socket::types::DaemonCommand;

/// Subcommands for managing API tokens.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub(crate) enum ApiTokenCommand {
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
pub(crate) async fn handle_command(subcommand: ApiTokenCommand) -> Result<(), CliError> {
    match subcommand {
        ApiTokenCommand::Create {
            name,
            role,
            description,
            expires_in_days,
            output,
        } => {
            let response = client::send_command::<CreateApiTokenResponse>(
                DaemonCommand::CreateToken(CreateApiTokenRequest {
                    name,
                    description,
                    expires_in_days,
                    role_name: role,
                }),
            )
            .await?;
            output::print_response(&response.data, output, |response| {
                vec![ApiTokenRow::from(response)]
            })?;
        }
        ApiTokenCommand::List {
            role,
            limit,
            offset,
            output,
        } => {
            let response = client::send_command::<PaginatedResponse<ApiTokenResponse>>(
                DaemonCommand::ListTokens(ApiTokenFilter {
                    role_name: role,
                    limit,
                    offset,
                }),
            )
            .await?;
            output::print_page(&response.data, output, |token| ApiTokenRow::from(token))?;
        }
        ApiTokenCommand::Delete { name, output } => {
            let response =
                client::send_command::<MessageResponse>(DaemonCommand::DeleteToken { name })
                    .await?;

            if output == OutputFormat::Table {
                outln!("{}", response.message);
            } else {
                output::print_payload(&response.data, output)?;
            }
        }
    }

    Ok(())
}
