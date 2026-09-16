use bindizr_service::types::{
    CreateTokenGrantRequest, CreateTokenRequest, CreatedTokenResponse, GetTokenGrantResponse,
    GetTokenResponse, PaginatedResponse, TokenGrantResponse,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, TokenGrantRow, TokenRow, print_response},
    },
    socket::{
        client,
        types::{
            CreateTokenGrantParams, DaemonCommandKind, DeleteTokenGrantParams, TokenNameParams,
        },
    },
};

/// Subcommands for managing API tokens.
#[derive(Subcommand, Debug)]
pub(crate) enum TokenCommand {
    /// Create a new API token; the plaintext token is shown once, here
    Create {
        /// Unique name (letters, digits, '.', '_', '-'); how other commands refer to it
        #[arg(long, value_name = "TOKEN_NAME")]
        name: String,
        /// Description of the token
        #[arg(long, value_name = "TEXT")]
        description: Option<String>,
        /// Days until the token expires, up to 36500 (default: never expires)
        #[arg(long, value_name = "N")]
        expires_in_days: Option<i64>,
        /// Make the token global: it may manage every zone and the zone
        /// plane without grants. Fixed at creation.
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
    /// Grant an API token record rights in a zone
    Grant {
        /// Name of an existing non-global token (global tokens already cover every zone)
        #[arg(value_name = "TOKEN_NAME")]
        name: String,
        /// Name of the zone
        #[arg(value_name = "ZONE_NAME")]
        zone: String,
        /// Record name pattern: '*' (any), '@' (apex), '*.sub', or an exact relative name (default: '*')
        #[arg(long, value_name = "PATTERN")]
        pattern: Option<String>,
        /// Allowed record types: '*' or a comma-separated list, e.g. 'A,AAAA,TXT' (default: '*')
        #[arg(long, value_name = "TYPES")]
        types: Option<String>,
        /// Grant read access only; the zone stays visible, narrowed the same way
        #[arg(long)]
        read_only: bool,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// List a token's grants (`zone token-grants` lists a zone's)
    Grants {
        /// Name of the token
        #[arg(value_name = "TOKEN_NAME")]
        name: String,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Revoke one of a token's grants by grant ID
    Revoke {
        /// Name of the token
        #[arg(value_name = "TOKEN_NAME")]
        name: String,
        /// ID of the grant to revoke (see `token grants`)
        #[arg(value_name = "GRANT_ID")]
        id: i32,
    },
}

/// Handle the `token` subcommand by dispatching to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: TokenCommand) -> Result<(), CliError> {
    match subcommand {
        TokenCommand::Create {
            name,
            description,
            expires_in_days,
            global,
            output,
        } => {
            let res = client::send_command(
                DaemonCommandKind::CreateToken,
                CreateTokenRequest {
                    name,
                    description,
                    expires_in_days,
                    global,
                },
            )
            .await?;

            log::debug!("Token creation result: {:?}", res);

            print_response(&res.data, output, |created: &CreatedTokenResponse| {
                vec![TokenRow::from(created)]
            })?;
        }
        TokenCommand::List { output } => {
            let res = client::send_command(DaemonCommandKind::ListTokens, ()).await?;

            log::debug!("Token list result: {:?}", res);

            print_response(
                &res.data,
                output,
                |tokens: &PaginatedResponse<GetTokenResponse>| {
                    tokens.items.iter().map(TokenRow::from).collect()
                },
            )?;
        }
        TokenCommand::Delete { name } => {
            let res =
                client::send_command(DaemonCommandKind::DeleteToken, TokenNameParams { name })
                    .await?;

            log::debug!("Token deletion result: {:?}", res);

            println!("{}", res.message);
        }
        TokenCommand::Grant {
            name,
            zone,
            pattern,
            types,
            read_only,
            output,
        } => {
            let res = client::send_command(
                DaemonCommandKind::CreateTokenGrant,
                CreateTokenGrantParams {
                    token_name: name,
                    request: CreateTokenGrantRequest {
                        zone_name: zone,
                        record_name_pattern: pattern,
                        record_types: types,
                        can_write: !read_only,
                    },
                },
            )
            .await?;
            print_response(&res.data, output, |response: &TokenGrantResponse| {
                vec![TokenGrantRow::from(&response.token_grant)]
            })?;
        }
        TokenCommand::Grants { name, output } => {
            let res =
                client::send_command(DaemonCommandKind::ListTokenGrants, TokenNameParams { name })
                    .await?;
            print_response(
                &res.data,
                output,
                |grants: &PaginatedResponse<GetTokenGrantResponse>| {
                    grants.items.iter().map(TokenGrantRow::from).collect()
                },
            )?;
        }
        TokenCommand::Revoke { name, id } => {
            let res = client::send_command(
                DaemonCommandKind::DeleteTokenGrant,
                DeleteTokenGrantParams {
                    token_name: name,
                    id,
                },
            )
            .await?;
            println!("{}", res.message);
        }
    }

    Ok(())
}
