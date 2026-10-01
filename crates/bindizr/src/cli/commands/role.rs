use bindizr_core::{model::role_grant::RoleGrantId, outln};
use bindizr_service::types::{
    CreateRoleGrantRequest, CreateRoleRequest, GetRoleGrantResponse, GetRoleResponse,
    MessageResponse, PageRequest, PaginatedResponse, RoleGrantResponse, RoleResponse,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, RoleGrantRow, RoleRow, print_page, print_payload, print_response},
    },
    socket::{client, types::DaemonCommand},
};

/// Subcommands for managing roles and their grants.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub(crate) enum RoleCommand {
    /// Create a role holding no grants yet
    #[command(after_help = "\
Examples:
  bindizr role create external-dns-prod --description 'ExternalDNS in the prod clusters'
  bindizr role grant external-dns-prod --zone example.com \\
    --actions record:read,record:create,record:update,record:delete \\
    --pattern '*.apps' --types A,AAAA,CNAME,TXT
  bindizr token create cluster-a --role external-dns-prod")]
    Create {
        /// Unique name (letters, digits, '.', '_', '-'); how other commands refer to it
        #[arg(value_name = "ROLE_NAME")]
        name: String,
        /// Description of the role
        #[arg(long, value_name = "TEXT")]
        description: Option<String>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// List all roles
    #[command(alias = "ls")]
    List {
        /// Maximum number of roles to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of roles to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Show one role
    Get {
        /// Name of the role
        #[arg(value_name = "ROLE_NAME")]
        name: String,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Delete a role and its grants (refused while a token or key holds it)
    #[command(alias = "rm")]
    Delete {
        /// Name of the role
        #[arg(value_name = "ROLE_NAME")]
        name: String,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Grant a role actions in one zone, or in every zone without --zone
    #[command(after_help = "\
Examples:
  bindizr role grant dns-admins --actions zone:read,zone:update,record:read
  bindizr role grant secondaries --actions zone:transfer
  bindizr role grant acme --zone example.com --actions record:create,record:delete \\
    --pattern '_acme-challenge' --types TXT

Actions: zone:read, zone:create, zone:update, zone:delete, zone:transfer,
record:read, record:create, record:update, record:delete, dnssec:read,
dnssec:manage, secondary:read, secondary:manage, access:manage.
--pattern and --types narrow the record:* actions only.")]
    Grant {
        /// Name of the role
        #[arg(value_name = "ROLE_NAME")]
        name: String,
        /// Zone the grant covers (default: every zone, including later ones)
        #[arg(long, value_name = "ZONE_NAME")]
        zone: Option<String>,
        /// Comma-separated actions the grant permits
        #[arg(long, value_name = "ACTIONS", value_delimiter = ',', required = true)]
        actions: Vec<String>,
        /// Record name pattern: '*' (any), '@' (apex), '*.sub', or an exact relative name (default: '*')
        #[arg(long, value_name = "PATTERN")]
        pattern: Option<String>,
        /// Record types: '*' or a comma-separated list, e.g. 'A,AAAA,TXT' (default: '*')
        #[arg(long, value_name = "TYPES")]
        types: Option<String>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// List a role's grants
    Grants {
        /// Name of the role
        #[arg(value_name = "ROLE_NAME")]
        name: String,
        /// Maximum number of grants to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of grants to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Revoke one of a role's grants by ID (see `role grants`)
    Revoke {
        /// Name of the role
        #[arg(value_name = "ROLE_NAME")]
        name: String,
        /// ID of the grant to revoke
        #[arg(value_name = "GRANT_ID")]
        id: i32,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
}

/// Handle the `role` subcommand by dispatching to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: RoleCommand) -> Result<(), CliError> {
    match subcommand {
        RoleCommand::Create {
            name,
            description,
            output,
        } => {
            let res = client::send_command::<RoleResponse>(DaemonCommand::CreateRole(
                CreateRoleRequest { name, description },
            ))
            .await?;
            print_response(&res.data, output, |response| {
                vec![RoleRow::from(&response.role)]
            })?;
        }
        RoleCommand::List {
            limit,
            offset,
            output,
        } => {
            let res = client::send_command::<PaginatedResponse<GetRoleResponse>>(
                DaemonCommand::ListRoles(PageRequest { limit, offset }),
            )
            .await?;
            print_page(&res.data, output, |item| RoleRow::from(item))?;
        }
        RoleCommand::Get { name, output } => {
            let res = client::send_command::<RoleResponse>(DaemonCommand::GetRole { name }).await?;
            print_response(&res.data, output, |response| {
                vec![RoleRow::from(&response.role)]
            })?;
        }
        RoleCommand::Delete { name, output } => {
            let res =
                client::send_command::<MessageResponse>(DaemonCommand::DeleteRole { name }).await?;
            match output {
                OutputFormat::Table => outln!("{}", res.message),
                _ => print_payload(&res.data, output)?,
            }
        }
        RoleCommand::Grant {
            name,
            zone,
            actions,
            pattern,
            types,
            output,
        } => {
            let res = client::send_command::<RoleGrantResponse>(DaemonCommand::CreateRoleGrant {
                role_name: name,
                request: CreateRoleGrantRequest {
                    zone_name: zone,
                    actions,
                    record_name_pattern: pattern,
                    record_types: types,
                },
            })
            .await?;
            print_response(&res.data, output, |response| {
                vec![RoleGrantRow::from(&response.role_grant)]
            })?;
        }
        RoleCommand::Grants {
            name,
            limit,
            offset,
            output,
        } => {
            let res = client::send_command::<PaginatedResponse<GetRoleGrantResponse>>(
                DaemonCommand::ListRoleGrants {
                    role_name: name,
                    page: PageRequest { limit, offset },
                },
            )
            .await?;
            print_page(&res.data, output, |item| RoleGrantRow::from(item))?;
        }
        RoleCommand::Revoke { name, id, output } => {
            let res = client::send_command::<MessageResponse>(DaemonCommand::DeleteRoleGrant {
                role_name: name,
                id: RoleGrantId::from(id),
            })
            .await?;
            match output {
                OutputFormat::Table => outln!("{}", res.message),
                _ => print_payload(&res.data, output)?,
            }
        }
    }
    Ok(())
}
