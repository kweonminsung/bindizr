//! Serve globally authorized CLI commands over Unix sockets, restricted to the daemon user or root.

pub(crate) mod control;
mod dnssec;
mod dnssec_policy;
mod doctor;
mod logs;
mod notify;
mod path;
mod record;
mod role;
mod secondary;
mod status;
mod token;
mod tsig_key;
mod zone;

use std::future::Future;
use std::io;
use std::sync::Arc;

use bindizr_service::Context;
use bindizr_service::error::{ErrorCode, ServiceError};
use bindizr_service::types::ErrorResponse;
pub(crate) use path::{BindSocketError, bind, remove_socket_file};
use serde::Serialize;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::{JoinHandle, JoinSet};

use crate::daemon::ConfigReloader;
use crate::shutdown::Shutdown;
use crate::socket;
use crate::socket::server::control::DaemonControlSender;
use crate::socket::types::{DaemonCommand, DaemonResponse};

/// Bound command allocation above the 32 MB HTTP cap to accommodate JSON-escaped zone files.
const MAX_COMMAND_LINE_BYTES: u64 = 64 * 1024 * 1024;

/// Why the bound socket could not be served.
#[derive(Debug, Error)]
pub(crate) enum ServeSocketError {
    #[error("failed to read the daemon's uid: {0}")]
    ReadUid(#[source] io::Error),
}

/// Daemon context and lifecycle control channel; only control commands need the latter.
#[derive(Debug)]
pub(crate) struct SocketContext {
    daemon: Arc<Context>,
    control: DaemonControlSender,
    reloader: Arc<ConfigReloader>,
}

impl SocketContext {
    /// Build the front end's context over the daemon's.
    pub(crate) fn new(
        daemon: Arc<Context>,
        control: DaemonControlSender,
        reloader: Arc<ConfigReloader>,
    ) -> Self {
        Self {
            daemon,
            control,
            reloader,
        }
    }

    /// Return the daemon's context.
    pub(crate) fn daemon(&self) -> &Arc<Context> {
        &self.daemon
    }

    /// Return the daemon's shared reload handler.
    pub(crate) fn reloader(&self) -> &ConfigReloader {
        &self.reloader
    }

    /// Return the sender a shutdown or restart request goes down.
    pub(crate) fn control(&self) -> &DaemonControlSender {
        &self.control
    }
}

/// Dispatch a control request and send its JSON response.
async fn handle_client(
    socket_cx: &SocketContext,
    stream: UnixStream,
    stop: impl Future<Output = ()>,
) {
    let mut reader = BufReader::new(stream).take(MAX_COMMAND_LINE_BYTES);
    let mut line = String::new();

    tokio::pin!(stop);
    let read = tokio::select! {
        biased;
        () = &mut stop => return,

        read = reader.read_line(&mut line) => read,
    };

    if read.is_ok() {
        // A connect-and-close is another `bindizr start` probing whether this
        // daemon is alive (`remove_stale_socket`), not a command.
        if line.is_empty() {
            return;
        }

        let response = match serde_json::from_str::<DaemonCommand>(&line) {
            Ok(command) => handle_command(socket_cx, command).await,
            Err(error) => reject_invalid_command(socket::SocketDecodeError(error)),
        };

        let mut stream = reader.into_inner().into_inner();

        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(b"\n").await;
    }
}

/// Reject an invalid command without copying its values into diagnostics.
fn reject_invalid_command(error: socket::SocketDecodeError) -> String {
    let reason = format!("failed to parse command ({error})");

    log::warn!("{reason}");
    encode_error(&ServiceError::invalid_input(reason))
}

/// Serve control commands for the daemon's user and root until `shutdown` fires.
/// Remove the socket only after draining: `bindizr stop` uses its disappearance as completion.
pub(crate) fn serve(
    socket_cx: Arc<SocketContext>,
    listener: Arc<UnixListener>,
    shutdown: &Shutdown,
) -> Result<JoinHandle<()>, ServeSocketError> {
    let own_uid = socket::read_own_uid().map_err(ServeSocketError::ReadUid)?;
    let stop = shutdown.waiter();
    let client_shutdown = shutdown.clone();

    Ok(tokio::spawn(async move {
        tokio::pin!(stop);
        let mut clients = JoinSet::new();

        loop {
            let accepted = tokio::select! {
                biased;
                () = &mut stop => break,

                Some(result) = clients.join_next(), if !clients.is_empty() => {
                    if let Err(error) = result {
                        log::warn!("Daemon socket client task failed: {error}");
                    }
                    continue;
                }

                accepted = listener.accept() => accepted,
            };

            match accepted {
                // Connecting grants global access, so the peer is checked before a byte is read.
                Ok((stream, _)) => match stream.peer_cred() {
                    Ok(peer) if socket::is_trusted_peer(peer.uid(), own_uid) => {
                        let socket_cx = socket_cx.clone();
                        let stop = client_shutdown.waiter();
                        clients.spawn(async move {
                            handle_client(&socket_cx, stream, stop).await;
                        });
                    }
                    Ok(peer) => {
                        log::warn!("Refused a daemon socket connection from uid {}", peer.uid());
                    }
                    // Another `bindizr start` probing whether this daemon is alive
                    // has hung up already, and macOS keeps no credentials past that.
                    Err(error) if error.kind() == io::ErrorKind::NotConnected => {}
                    Err(error) => {
                        log::warn!(
                            "Refused a daemon socket connection with no peer credentials: {error}"
                        );
                    }
                },
                Err(error) => {
                    log::error!("Error accepting connection: {error}");
                }
            }
        }

        drop(listener);

        while let Some(result) = clients.join_next().await {
            if let Err(error) = result {
                log::warn!("Daemon socket client task failed: {error}");
            }
        }

        log::info!("Daemon socket server stopped");
    }))
}

/// Run one command and encode its answer as the line the client reads.
async fn handle_command(socket_cx: &SocketContext, command: DaemonCommand) -> String {
    let cx = socket_cx.daemon();

    match command {
        DaemonCommand::Status => encode_response(status::get_daemon_status(cx).await),
        DaemonCommand::Config => encode_response(Ok(status::get_config(cx))),
        DaemonCommand::ReloadConfig => encode_response(control::reload_config(socket_cx)),
        DaemonCommand::Doctor => encode_response(doctor::check_installation(cx).await),
        DaemonCommand::Shutdown => encode_response(control::shutdown(socket_cx).await),
        DaemonCommand::Restart => encode_response(control::restart(socket_cx).await),
        DaemonCommand::CreateToken(request) => {
            encode_response(token::create_token(cx, &request).await)
        }
        DaemonCommand::ListTokens(filter) => encode_response(token::list_tokens(cx, &filter).await),
        DaemonCommand::DeleteToken { name } => {
            encode_response(token::delete_token(cx, &name).await)
        }
        DaemonCommand::CreateTsigKey(request) => {
            encode_response(tsig_key::create_tsig_key(cx, &request).await)
        }
        DaemonCommand::ListTsigKeys(filter) => {
            encode_response(tsig_key::list_tsig_keys(cx, &filter).await)
        }
        DaemonCommand::GetTsigKey { name } => {
            encode_response(tsig_key::get_tsig_key(cx, &name).await)
        }
        DaemonCommand::DeleteTsigKey { name } => {
            encode_response(tsig_key::delete_tsig_key(cx, &name).await)
        }
        DaemonCommand::ListAuditLogs(filter) => {
            encode_response(logs::list_audit_logs(cx, &filter).await)
        }
        DaemonCommand::ListAccessLogs(filter) => {
            encode_response(logs::list_access_logs(cx, &filter).await)
        }
        DaemonCommand::ListTransferLogs(filter) => {
            encode_response(logs::list_transfer_logs(cx, &filter).await)
        }
        DaemonCommand::CreateRole(request) => {
            encode_response(role::create_role(cx, &request).await)
        }
        DaemonCommand::ListRoles(page) => encode_response(role::list_roles(cx, page).await),
        DaemonCommand::GetRole { name } => encode_response(role::get_role(cx, &name).await),
        DaemonCommand::DeleteRole { name } => encode_response(role::delete_role(cx, &name).await),
        DaemonCommand::CreateRoleGrant { role_name, request } => {
            encode_response(role::create_role_grant(cx, &role_name, &request).await)
        }
        DaemonCommand::ListRoleGrants { role_name, page } => {
            encode_response(role::list_role_grants(cx, &role_name, page).await)
        }
        DaemonCommand::DeleteRoleGrant {
            role_name,
            id: grant_id,
        } => encode_response(role::delete_role_grant(cx, &role_name, grant_id).await),
        DaemonCommand::CreateSecondary(request) => {
            encode_response(secondary::create_secondary(cx, &request).await)
        }
        DaemonCommand::ListSecondaries(page) => {
            encode_response(secondary::list_secondaries(cx, page).await)
        }
        DaemonCommand::GetSecondary { name } => {
            encode_response(secondary::get_secondary(cx, &name).await)
        }
        DaemonCommand::UpdateSecondary { name, request } => {
            encode_response(secondary::update_secondary(cx, &name, &request).await)
        }
        DaemonCommand::DeleteSecondary { name } => {
            encode_response(secondary::delete_secondary(cx, &name).await)
        }
        DaemonCommand::CheckSecondary { name } => {
            encode_response(secondary::check_secondary(cx, &name).await)
        }
        DaemonCommand::CreateDnssecPolicy(request) => {
            encode_response(dnssec_policy::create_dnssec_policy(cx, &request).await)
        }
        DaemonCommand::ListDnssecPolicies(page) => {
            encode_response(dnssec_policy::list_dnssec_policies(cx, page).await)
        }
        DaemonCommand::GetDnssecPolicy { name } => {
            encode_response(dnssec_policy::get_dnssec_policy(cx, &name).await)
        }
        DaemonCommand::UpdateDnssecPolicy { name, request } => {
            encode_response(dnssec_policy::update_dnssec_policy(cx, &name, &request).await)
        }
        DaemonCommand::DeleteDnssecPolicy { name } => {
            encode_response(dnssec_policy::delete_dnssec_policy(cx, &name).await)
        }
        DaemonCommand::CreateZone(request) => {
            encode_response(zone::create_zone(cx, &request).await)
        }
        DaemonCommand::ListZones(filter) => encode_response(zone::list_zones(cx, &filter).await),
        DaemonCommand::GetZone { name: zone_name } => {
            encode_response(zone::get_zone(cx, &zone_name).await)
        }
        DaemonCommand::UpdateZone { zone_name, request } => {
            encode_response(zone::update_zone(cx, &zone_name, &request).await)
        }
        DaemonCommand::DeleteZone {
            name: zone_name,
            run,
        } => encode_response(zone::delete_zone(cx, &zone_name, run).await),
        DaemonCommand::ImportZone { zone_name, request } => {
            encode_response(zone::import_zone(cx, &zone_name, &request).await)
        }
        DaemonCommand::ImportZones(request) => {
            encode_response(zone::import_zones(cx, &request).await)
        }
        DaemonCommand::ExportZone {
            name: zone_name,
            view,
        } => encode_response(zone::export_zone(cx, &zone_name, view).await),
        DaemonCommand::GetZoneStatus { name: zone_name } => {
            encode_response(zone::get_zone_status(cx, &zone_name).await)
        }
        DaemonCommand::NotifyZone { zone_name, serial } => {
            encode_response(notify::notify_zone(cx, &zone_name, serial).await)
        }
        DaemonCommand::NotifyAllZones { serial } => {
            encode_response(notify::notify_all_zones(cx, serial).await)
        }
        DaemonCommand::ListZoneVersions {
            name: zone_name,
            limit,
            offset,
            filter,
        } => encode_response(zone::list_zone_versions(cx, &zone_name, limit, offset, filter).await),
        DaemonCommand::GetZoneVersion {
            name: zone_name,
            serial,
        } => encode_response(zone::get_zone_version(cx, &zone_name, serial).await),
        DaemonCommand::DiffZoneVersions {
            name: zone_name,
            from_serial,
            to_serial,
        } => {
            encode_response(zone::diff_zone_versions(cx, &zone_name, from_serial, to_serial).await)
        }
        DaemonCommand::RollbackZone {
            name: zone_name,
            serial,
            run,
        } => encode_response(zone::rollback_zone(cx, &zone_name, serial, run).await),
        DaemonCommand::CreateRecord(request) => {
            encode_response(record::create_record(cx, &request).await)
        }
        DaemonCommand::CreateBulkRecords(request) => {
            encode_response(record::create_bulk_records(cx, &request).await)
        }
        DaemonCommand::ListRecords(filter) => {
            encode_response(record::list_records(cx, &filter).await)
        }
        DaemonCommand::GetRecord { id: record_id } => {
            encode_response(record::get_record(cx, record_id).await)
        }
        DaemonCommand::UpdateRecord {
            id: record_id,
            request,
        } => encode_response(record::update_record(cx, record_id, &request).await),
        DaemonCommand::UpdateRecordByName {
            zone_name,
            record_name,
            request,
        } => encode_response(
            record::update_record_by_name(cx, &zone_name, &record_name, &request).await,
        ),
        DaemonCommand::DeleteRecord { id: record_id, run } => {
            encode_response(record::delete_record(cx, record_id, run).await)
        }
        DaemonCommand::DeleteMatchingRecords(request) => {
            encode_response(record::delete_matching_records(cx, &request).await)
        }
        DaemonCommand::EnableDnssec { zone_name, request } => {
            encode_response(dnssec::enable_dnssec(cx, &zone_name, &request).await)
        }
        DaemonCommand::DisableDnssec {
            zone_name,
            ds_check,
        } => encode_response(dnssec::disable_dnssec(cx, &zone_name, ds_check).await),
        DaemonCommand::GetDnssecStatus { name: zone_name } => {
            encode_response(dnssec::get_dnssec_status(cx, &zone_name).await)
        }
        DaemonCommand::SignZone { name: zone_name } => {
            encode_response(dnssec::sign_zone(cx, &zone_name).await)
        }
        DaemonCommand::StartDnssecRollover { zone_name, request } => {
            encode_response(dnssec::start_dnssec_rollover(cx, &zone_name, &request).await)
        }
        DaemonCommand::AdvanceDnssecRollover {
            zone_name,
            ds_check,
            holddown,
        } => encode_response(
            dnssec::advance_dnssec_rollover(cx, &zone_name, ds_check, holddown).await,
        ),
        DaemonCommand::WithdrawDnssec { name: zone_name } => {
            encode_response(dnssec::withdraw_dnssec(cx, &zone_name).await)
        }
        DaemonCommand::CancelDnssecWithdrawal { name: zone_name } => {
            encode_response(dnssec::cancel_dnssec_withdrawal(cx, &zone_name).await)
        }
        DaemonCommand::UpdateDnssecSettings { zone_name, request } => {
            encode_response(dnssec::update_dnssec_settings(cx, &zone_name, &request).await)
        }
        DaemonCommand::CheckDnssecDs { name: zone_name } => {
            encode_response(dnssec::check_dnssec_ds(cx, &zone_name).await)
        }
        DaemonCommand::ExportDnssecKeys { name: zone_name } => {
            encode_response(dnssec::export_dnssec_keys(cx, &zone_name).await)
        }
        DaemonCommand::ImportDnssecKeys { zone_name, request } => {
            encode_response(dnssec::import_dnssec_keys(cx, &zone_name, &request).await)
        }
    }
}

/// Encode a handler's response, or the error it failed with, as one JSON line.
fn encode_response<T: Serialize>(result: Result<DaemonResponse<T>, ServiceError>) -> String {
    match result {
        Ok(response) => serde_json::to_string(&response).unwrap_or_else(|error| {
            encode_error(&ServiceError::internal_with_source(
                "failed to serialize response",
                error,
            ))
        }),
        Err(error) => encode_error(&error),
    }
}

/// Encode a service error as one JSON line, logging the cause of a server
/// fault, which leaves the daemon here.
fn encode_error(error: &ServiceError) -> String {
    if error.code().is_internal() {
        log::error!("Socket command failed with a server fault: {error:?}");
    }

    serde_json::to_string(&ErrorResponse::from(error)).unwrap_or_else(|_| {
        format!(
            r#"{{"error":"failed to serialize error response","code":"{}"}}"#,
            ErrorCode::Internal.as_str()
        )
    })
}

#[cfg(test)]
mod tests;
