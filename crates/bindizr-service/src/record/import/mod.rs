//! Zone imports share execution choices and reconciliation across independent input sources.

mod apply;
mod multiple;
mod plan;
mod single;

use std::collections::HashSet;

use apply::apply_import;
use bindizr_core::{
    dns::{name::ZoneName, zonefile::ParsedZoneFile},
    model::role_grant::Action,
};
pub use multiple::import_zones;
pub use single::import_zone;

use crate::{
    Context,
    authorization::Caller,
    dns_client::axfr::AxfrClient,
    error::ServiceError,
    model::zone::Zone,
    types::{ImportMode, ImportZoneResponse, Run},
    zone,
};

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
    server: &str,
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
        .map_err(|e| {
            ServiceError::invalid_input_with_source(
                format!("AXFR from {} failed: {}", server, e),
                e,
            )
        })?;
    let source = ImportSource::Transfer(ParsedZoneFile::from_transfer(&records, zone_name));
    apply_import(cx, caller, zone_name, source, options).await
}

/// The zones a bulk import names, in request order without repeats.
fn normalize_zone_names(names: &[String]) -> Result<Vec<ZoneName>, ServiceError> {
    if names.is_empty() {
        return Err(ServiceError::invalid_input(
            "zone_names must name at least one zone",
        ));
    }
    let mut zone_names: Vec<ZoneName> = Vec::with_capacity(names.len());
    let mut seen: HashSet<ZoneName> = HashSet::with_capacity(names.len());
    for name in names {
        let zone_name = zone::normalize_name(name)?;
        if seen.insert(zone_name.clone()) {
            zone_names.push(zone_name);
        }
    }
    Ok(zone_names)
}

/// The record actions an import mode performs.
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
mod tests;
