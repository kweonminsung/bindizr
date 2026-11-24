//! Zone imports share execution choices and reconciliation across independent input sources.

mod apply;
mod multiple;
mod plan;
mod single;

use bindizr_core::dns::address;
use bindizr_core::dns::name::ZoneName;
use bindizr_core::dns::zonefile::ParsedZoneFile;
use bindizr_core::model::role_grant::Action;
use bindizr_core::model::zone::Zone;
pub use multiple::import_many;
pub use single::import;

use crate::authorization::Caller;
use crate::dns_client::axfr::AxfrClient;
use crate::error::ServiceError;
use crate::types::{ImportMode, ImportZoneResponse, Run};
use crate::{Context, zone};

/// Text needs the locked zone's default TTL; AXFR carries every TTL explicitly.
#[derive(Debug)]
pub(crate) enum ImportSource<'a> {
    Text(&'a str),
    Transfer(ParsedZoneFile),
}

/// What an import does when its target zone is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MissingZoneAction {
    Create,
    Reject,
}

/// Execution choices shared by text, transfer, and catalog imports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ImportOptions {
    pub(crate) mode: ImportMode,
    pub(crate) run: Run,
    pub(crate) missing_zone_action: MissingZoneAction,
}

/// Import one zone over `client`'s connection; `create` was authorized by the
/// caller, the zone is checked here and again in the transaction.
async fn import_transfer(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    client: &mut AxfrClient,
    address: &str,
    options: ImportOptions,
) -> Result<ImportZoneResponse, ServiceError> {
    // Reject invalid or unauthorized requests before AXFR; recheck in the transaction.
    if options.missing_zone_action == MissingZoneAction::Reject {
        let zone = zone::lookup_by_name(cx, zone_name).await?;
        authorize_import(caller, options.mode, &zone)?;
    }

    let config = cx.config();

    let records = client
        .fetch_zone(zone_name, &config.dns.import)
        .await
        .map_err(|error| {
            ServiceError::invalid_input_with_source(
                format!("AXFR from {address} failed: {error}"),
                error,
            )
        })?;
    let source = ImportSource::Transfer(ParsedZoneFile::from_transfer(&records, zone_name));

    apply::apply_import(cx, caller, zone_name, source, options).await
}

/// Trim the server an import transfers from, which must name one `host[:port]`.
fn normalize_from_server(value: &str) -> Result<&str, ServiceError> {
    let address = value.trim();

    if !address::is_address_target(address) {
        return Err(ServiceError::invalid_input(
            "from_server must name one server as host[:port]",
        ));
    }

    Ok(address)
}

/// Return the record actions an import mode performs.
fn import_actions(mode: ImportMode) -> &'static [Action] {
    match mode {
        ImportMode::Append => &[Action::RecordCreate],
        ImportMode::Upsert | ImportMode::Replace => &[Action::RecordCreate, Action::RecordDelete],
    }
}

/// Authorize zone creation and the import mode's record actions in all zones.
fn authorize_new_zone_import(caller: &Caller, mode: ImportMode) -> Result<(), ServiceError> {
    caller.authorize_action(Action::ZoneCreate)?;
    for action in import_actions(mode) {
        caller.authorize_all_whole_zones(*action)?;
    }
    Ok(())
}

/// Authorize each record action the import mode performs over the zone whole.
fn authorize_import(caller: &Caller, mode: ImportMode, zone: &Zone) -> Result<(), ServiceError> {
    for action in import_actions(mode) {
        caller.authorize_whole_zone(*action, zone)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::TcpListener;

    use bindizr_core::config::Config;
    use bindizr_core::metrics::Metrics;
    use bindizr_db::Db;
    use tokio::sync::{mpsc, watch};

    use super::*;
    use crate::dns_client::axfr::FetchZoneError;
    use crate::error::ErrorCode;
    use crate::types::{ImportZoneRequest, ImportZonesRequest};
    use crate::zone;

    /// Verify that a failed external import keeps its network cause without creating a zone.
    #[tokio::test]
    async fn failed_zone_and_catalog_transfers_preserve_their_sources() {
        use std::error::Error;

        let mut config: Config = serde_json::from_str("{}").unwrap();
        config.database.sqlite.file_path = "sqlite::memory:".to_string();

        let db = Db::connect(&config.database).await.unwrap();
        let cx = Context::new(
            config,
            String::new(),
            db,
            Metrics::new().unwrap(),
            mpsc::unbounded_channel().0,
            mpsc::channel(1).0,
            watch::channel(0).0,
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        drop(listener);
        let zone_name = ZoneName::parse("example.com").unwrap();
        let caller = Caller::socket();

        let single = import(
            &cx,
            &caller,
            &zone_name,
            &ImportZoneRequest {
                content: None,
                from_server: Some(address.clone()),
                mode: "append".to_string(),
                dry_run: false,
                create: true,
            },
        )
        .await
        .unwrap_err();
        let catalog = import_many(
            &cx,
            &caller,
            &ImportZonesRequest {
                from_server: address.clone(),
                zone_names: None,
                from_catalog: Some("catalog.example".to_string()),
                mode: "append".to_string(),
                dry_run: false,
                create: true,
            },
        )
        .await
        .unwrap_err();

        for (error, context) in [
            (single, format!("AXFR from {address} failed")),
            (
                catalog,
                format!("AXFR of catalog catalog.example from {address} failed"),
            ),
        ] {
            assert_eq!(error.code(), ErrorCode::InvalidInput);
            let source = error.source().unwrap();

            assert!(source.downcast_ref::<FetchZoneError>().is_some());
            assert_eq!(error.to_string(), format!("{context}: {source}"));
            let cause = source.source().unwrap().source().unwrap();

            assert!(matches!(
                cause.downcast_ref::<io::Error>(),
                Some(cause) if cause.kind() == io::ErrorKind::ConnectionRefused
            ));
        }

        assert!(zone::list_enabled(&cx).await.unwrap().is_empty());
    }
}
