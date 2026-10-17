//! Shared secondary registry for NOTIFY, unsigned-transfer ACLs, and serial probes.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use bindizr_core::{
    dns::{
        address::{AddressTarget, DEFAULT_DNS_PORT, is_address_target, loopback_if_unspecified},
        name::has_whitespace_or_control,
        tsig::TsigSigningKey,
    },
    model::{
        audit_log::{AuditEntity, AuditOperation},
        role_grant::Action,
        secondary::SecondaryId,
        tsig_key::TsigKeyId,
    },
};
use bindizr_db::LockLevel;
use chrono::Utc;

use crate::{
    Context, audit,
    authorization::Caller,
    dns_client::{notify, probe, resolve_address_entry},
    error::ServiceError,
    model::{secondary::Secondary, tsig_key::TsigKey},
    pagination::{build_page, normalize_page_limit},
    text::{MAX_COLUMN_TEXT_LEN, normalize_identifier},
    transaction, transfer, tsig_key,
    types::{
        CheckSecondaryResponse, CreateSecondaryRequest, PageRequest, PaginatedResponse,
        SecondaryResponse, SecondaryTransferFilter, SecondaryTransfersResponse, TransferResponse,
        TransferSummaryResponse, UpdateSecondaryRequest,
    },
    zone,
};

/// Register a secondary by name and `host[:port]` address; with
/// `notify_key_name`, NOTIFY to it is signed with that TSIG key.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    request: &CreateSecondaryRequest,
) -> Result<SecondaryResponse, ServiceError> {
    caller.authorize_action(Action::SecondaryManage)?;

    let name = normalize_secondary_name(&request.name)?;
    let address = normalize_secondary_address(&request.address)?;
    // Unlocked read to learn the FK target; the constraint backstops.
    let notify_tsig_key = match request.notify_key_name.as_deref() {
        Some(key_name) => Some(tsig_key::lookup_by_name(cx, key_name).await?),
        None => None,
    };

    // Friendly pre-checks; the UNIQUE backstops cover the race.
    if bindizr_db::secondary::get_by_name(cx.db(), &name)
        .await?
        .is_some()
    {
        return Err(ServiceError::secondary_conflict(format!(
            "secondary with name '{}' already exists",
            name
        )));
    }
    if let Some(other) = bindizr_db::secondary::get_by_address(cx.db(), &address).await? {
        return Err(ServiceError::secondary_conflict(format!(
            "secondary with address '{}' already exists (name '{}')",
            address, other.name
        )));
    }

    let mut tx = transaction::begin_tx(cx, "failed to create secondary").await?;
    let result: Result<_, ServiceError> = async {
        caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_action(Action::SecondaryManage)?;
        let secondary = bindizr_db::secondary::create_tx(
            &mut tx,
            Secondary {
                id: SecondaryId::UNWRITTEN,
                name: name.clone(),
                address: address.clone(),
                enabled: true,
                notify_tsig_key_id: notify_tsig_key.as_ref().map(|tsig_key| tsig_key.id),
                created_at: Utc::now(),
            },
        )
        .await
        .map_err(|e| {
            // The UNIQUE(name) / UNIQUE(address) backstop for the pre-checks above.
            if e.is_unique_violation() {
                ServiceError::secondary_conflict(format!(
                    "secondary with name '{}' or address '{}' already exists",
                    name, address
                ))
            } else {
                e.into()
            }
        })?;
        audit::save_tx(
            &mut tx,
            AuditEntity::Secondary,
            &secondary.name,
            AuditOperation::Create,
            Some(format!(
                "address {}, notify_key_name {}",
                secondary.address,
                notify_tsig_key
                    .as_ref()
                    .map_or("none", |tsig_key| tsig_key.name.as_str())
            )),
            caller.change_attribution(),
        )
        .await?;
        Ok(secondary)
    }
    .await;
    let secondary = transaction::finish_tx(tx, result, "failed to create secondary").await?;
    Ok(SecondaryResponse::from_secondary(
        &secondary,
        notify_tsig_key
            .as_ref()
            .map(|tsig_key| tsig_key.name.as_str()),
    ))
}

/// List every secondary, disabled ones included.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    page: PageRequest,
) -> Result<PaginatedResponse<SecondaryResponse>, ServiceError> {
    caller.authorize_action(Action::SecondaryRead)?;

    let secondaries = bindizr_db::secondary::list_all(cx.db()).await?;
    // One statement names every key rather than one per secondary.
    let key_names: HashMap<TsigKeyId, String> = bindizr_db::tsig_key::list_all(cx.db())
        .await?
        .into_iter()
        .map(|tsig_key| (tsig_key.id, tsig_key.name))
        .collect();
    build_page(
        secondaries
            .iter()
            .map(|secondary| {
                SecondaryResponse::from_secondary(
                    secondary,
                    secondary
                        .notify_tsig_key_id
                        .and_then(|id| key_names.get(&id))
                        .map(String::as_str),
                )
            })
            .collect(),
        page.limit,
        page.offset,
    )
}

/// Fetch one secondary by name.
pub async fn get(
    cx: &Context,
    caller: &Caller,
    name: &str,
) -> Result<SecondaryResponse, ServiceError> {
    caller.authorize_action(Action::SecondaryRead)?;
    let secondary = lookup_by_name(cx, name).await?;
    load_response(cx, secondary).await
}

/// Change a secondary's address, enabled flag, or NOTIFY key; an empty
/// key name sends NOTIFY unsigned again.
pub async fn update(
    cx: &Context,
    caller: &Caller,
    name: &str,
    request: UpdateSecondaryRequest,
) -> Result<SecondaryResponse, ServiceError> {
    caller.authorize_action(Action::SecondaryManage)?;

    let name = normalize_secondary_name(name)?;
    let address = request
        .address
        .as_deref()
        .map(normalize_secondary_address)
        .transpose()?;
    if address.is_none() && request.enabled.is_none() && request.notify_key_name.is_none() {
        return Err(ServiceError::invalid_input(
            "nothing to update: give an address, enabled, or notify_key_name",
        ));
    }
    // Unlocked read to learn the FK target; the constraint backstops.
    let notify_tsig_key: Option<Option<TsigKey>> = match request.notify_key_name.as_deref() {
        None => None,
        Some("") => Some(None),
        Some(key_name) => Some(Some(tsig_key::lookup_by_name(cx, key_name).await?)),
    };
    // Friendly pre-check; the UNIQUE(address) backstop covers the race.
    if let Some(address) = &address
        && let Some(other) = bindizr_db::secondary::get_by_address(cx.db(), address).await?
        && other.name != name
    {
        return Err(ServiceError::secondary_conflict(format!(
            "secondary with address '{}' already exists (name '{}')",
            address, other.name
        )));
    }

    // Read and write under the row lock, or two partial updates would
    // each restore the field the other changed.
    let mut tx = transaction::begin_tx(cx, "failed to update secondary").await?;
    let result: Result<_, ServiceError> = async {
        caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_action(Action::SecondaryManage)?;
        let secondary = bindizr_db::secondary::get_by_name_tx(&mut tx, &name, LockLevel::Exclusive)
            .await?
            .ok_or_else(|| ServiceError::secondary_not_found(&name))?;

        let address = address.unwrap_or_else(|| secondary.address.clone());
        let enabled = request.enabled.unwrap_or(secondary.enabled);
        // The detail names keys, so the replaced one is read by id; gone
        // meanwhile, it reads as the id.
        let notify_key_change = match &notify_tsig_key {
            None => None,
            Some(next) => {
                let previous = match secondary.notify_tsig_key_id {
                    None => "none".to_string(),
                    Some(id) => bindizr_db::tsig_key::get(cx.db(), id)
                        .await?
                        .map_or_else(|| format!("key {id}"), |key| key.name),
                };
                audit::changed(
                    "notify_key_name",
                    previous,
                    next.as_ref()
                        .map_or("none".to_string(), |key| key.name.clone()),
                )
            }
        };
        let detail = audit::join_changes([
            audit::changed("address", &secondary.address, &address),
            audit::changed("enabled", secondary.enabled, enabled),
            notify_key_change,
        ]);
        let secondary = bindizr_db::secondary::update_tx(
            &mut tx,
            Secondary {
                address: address.clone(),
                enabled,
                notify_tsig_key_id: match &notify_tsig_key {
                    Some(tsig_key) => tsig_key.as_ref().map(|tsig_key| tsig_key.id),
                    None => secondary.notify_tsig_key_id,
                },
                ..secondary
            },
        )
        .await
        .map_err(|e| {
            // The UNIQUE(address) backstop for the pre-check above.
            if e.is_unique_violation() {
                ServiceError::secondary_conflict(format!(
                    "secondary with address '{}' already exists",
                    address
                ))
            } else {
                e.into()
            }
        })?;
        audit::save_tx(
            &mut tx,
            AuditEntity::Secondary,
            &secondary.name,
            AuditOperation::Update,
            detail,
            caller.change_attribution(),
        )
        .await?;
        Ok(secondary)
    }
    .await;
    let secondary = transaction::finish_tx(tx, result, "failed to update secondary").await?;
    load_response(cx, secondary).await
}

/// Check one secondary, enabled or not: resolve it, compare its catalog serial
/// with Bindizr's listener, and send catalog NOTIFY.
pub async fn check(
    cx: &Context,
    caller: &Caller,
    name: &str,
) -> Result<CheckSecondaryResponse, ServiceError> {
    caller.authorize_action(Action::SecondaryManage)?;
    let secondary = lookup_by_name(cx, name).await?;

    let config = cx.config();
    let catalog_zone = config.dns.catalog_zone_name.clone();
    let timeout = config.dns.notify.timeout();
    // The listener's serial is the reference: it reflects the catalog's
    // current membership, which a stored serial would not.
    let dns_addr = SocketAddr::new(
        loopback_if_unspecified(config.dns.listen_addr),
        config.dns.listen_port,
    );
    let (catalog_serial, listener_error) =
        match probe::probe_server(dns_addr, &catalog_zone, timeout).await {
            Ok(serial) => (Some(serial), None),
            Err(e) => (None, Some(format!("{}: {}", dns_addr, e))),
        };

    let (addresses, resolve_error) = match resolve_address_entry(&secondary.address, timeout).await
    {
        Ok(addrs) => (addrs.iter().map(ToString::to_string).collect(), None),
        Err(e) => (Vec::new(), Some(e.to_string())),
    };
    let catalog = probe::probe_secondary(cx, &catalog_zone, &secondary, catalog_serial).await?;
    let notifies = notify::send_notify_to_secondary(cx, &catalog_zone, &secondary).await?;
    let transfers = summarize_transfers(cx, &secondary).await?;

    Ok(CheckSecondaryResponse {
        secondary: load_response(cx, secondary).await?,
        addresses,
        resolve_error,
        catalog_zone_name: catalog_zone.to_string(),
        catalog_serial,
        listener_error,
        catalog,
        notifies,
        transfers,
    })
}

/// The transfers Bindizr served `name`, newest first, with how each zone
/// was last served.
pub async fn list_transfers(
    cx: &Context,
    caller: &Caller,
    name: &str,
    filter: SecondaryTransferFilter,
) -> Result<SecondaryTransfersResponse, ServiceError> {
    caller.authorize_action(Action::SecondaryRead)?;
    let secondary = lookup_by_name(cx, name).await?;
    let limit = normalize_page_limit(filter.limit)? as usize;
    let zone_filter = filter
        .zone_name
        .as_deref()
        .map(zone::normalize_name)
        .transpose()?;

    let served = transfer::list_by_clients(cx, &resolve_ips(cx, &secondary).await).await?;
    let summary = TransferSummaryResponse::from(served.as_slice());
    let transfers = served
        .iter()
        .filter(|transfer| {
            zone_filter
                .as_ref()
                .is_none_or(|zone| transfer.zone_name == *zone)
        })
        .take(limit)
        .map(TransferResponse::from)
        .collect();
    Ok(SecondaryTransfersResponse {
        secondary_name: secondary.name,
        address: secondary.address.to_string(),
        summary,
        transfers,
    })
}

/// How Bindizr served `secondary`, for the check and doctor.
pub async fn summarize_transfers(
    cx: &Context,
    secondary: &Secondary,
) -> Result<TransferSummaryResponse, ServiceError> {
    let served = transfer::list_by_clients(cx, &resolve_ips(cx, secondary).await).await?;
    Ok(TransferSummaryResponse::from(served.as_slice()))
}

/// The addresses the secondary resolves to now, which key the transfer
/// rows; none when it does not resolve.
async fn resolve_ips(cx: &Context, secondary: &Secondary) -> Vec<IpAddr> {
    let timeout = cx.config().dns.notify.timeout();
    match resolve_address_entry(&secondary.address, timeout).await {
        Ok(addrs) => addrs.iter().map(|addr| addr.ip()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Delete a secondary by name.
pub async fn delete(cx: &Context, caller: &Caller, name: &str) -> Result<(), ServiceError> {
    caller.authorize_action(Action::SecondaryManage)?;

    let secondary = lookup_by_name(cx, name).await?;
    let mut tx = transaction::begin_tx(cx, "failed to delete secondary").await?;
    let result: Result<_, ServiceError> = async {
        caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_action(Action::SecondaryManage)?;
        // Removed meanwhile: not found, and no audit row for a deletion that was not one.
        if !bindizr_db::secondary::delete_tx(&mut tx, secondary.id).await? {
            return Err(ServiceError::secondary_not_found(&secondary.name));
        }
        audit::save_tx(
            &mut tx,
            AuditEntity::Secondary,
            &secondary.name,
            AuditOperation::Delete,
            None,
            caller.change_attribution(),
        )
        .await
    }
    .await;
    transaction::finish_tx(tx, result, "failed to delete secondary").await
}

/// The enabled secondaries, for the DNS plane, which takes no caller.
/// Read per use, so a change takes effect on the next NOTIFY or transfer.
pub async fn list_enabled(cx: &Context) -> Result<Vec<Secondary>, ServiceError> {
    Ok(bindizr_db::secondary::list_all(cx.db())
        .await?
        .into_iter()
        .filter(|secondary| secondary.enabled)
        .collect())
}

/// The key a secondary's NOTIFY is signed with, ready to sign; `None`
/// for one notified unsigned. The FK keeps a referenced key present.
pub(crate) async fn find_notify_signing_key(
    cx: &Context,
    secondary: &Secondary,
) -> Result<Option<TsigSigningKey>, ServiceError> {
    match find_notify_tsig_key(cx, secondary).await? {
        Some(tsig_key) => tsig_key.to_signing_key().map(Some).map_err(|e| {
            ServiceError::internal_with_source(
                format!("NOTIFY key '{}' is unusable: {:?}", tsig_key.name, e),
                e,
            )
        }),
        None => Ok(None),
    }
}

/// The stored key a secondary's NOTIFY is signed with, if any.
async fn find_notify_tsig_key(
    cx: &Context,
    secondary: &Secondary,
) -> Result<Option<TsigKey>, ServiceError> {
    match secondary.notify_tsig_key_id {
        Some(id) => Ok(Some(
            bindizr_db::tsig_key::get(cx.db(), id)
                .await?
                .ok_or_else(|| ServiceError::internal(format!("TSIG key {} is missing", id)))?,
        )),
        None => Ok(None),
    }
}

/// The API form of a secondary, naming its NOTIFY key.
async fn load_response(
    cx: &Context,
    secondary: Secondary,
) -> Result<SecondaryResponse, ServiceError> {
    let tsig_key = find_notify_tsig_key(cx, &secondary).await?;
    Ok(SecondaryResponse::from_secondary(
        &secondary,
        tsig_key.as_ref().map(|tsig_key| tsig_key.name.as_str()),
    ))
}

/// Fetch one secondary by name, unchecked.
pub(crate) async fn lookup_by_name(cx: &Context, name: &str) -> Result<Secondary, ServiceError> {
    let name = normalize_secondary_name(name)?;
    bindizr_db::secondary::get_by_name(cx.db(), &name)
        .await?
        .ok_or_else(|| ServiceError::secondary_not_found(&name))
}

/// Lowercased so one name means one secondary on every backend; a plain
/// identifier, since it travels in URL paths.
pub(crate) fn normalize_secondary_name(value: &str) -> Result<String, ServiceError> {
    normalize_identifier(value, "secondary name", MAX_COLUMN_TEXT_LEN)
}

/// Canonicalize `host[:port]` with an explicit port and a lowercase host without a trailing dot
/// so `UNIQUE(address)` identifies one secondary.
pub(crate) fn normalize_secondary_address(value: &str) -> Result<AddressTarget, ServiceError> {
    let address = value.trim();

    if address.is_empty() {
        return Err(ServiceError::invalid_input(
            "secondary address must not be empty",
        ));
    }
    if has_whitespace_or_control(address) || !is_address_target(address) {
        return Err(ServiceError::invalid_input(format!(
            "secondary address '{}' must be host[:port] with a numeric port",
            address
        )));
    }
    let address = AddressTarget::parse(address, DEFAULT_DNS_PORT);
    if address.to_string().len() > MAX_COLUMN_TEXT_LEN {
        return Err(ServiceError::invalid_input(format!(
            "secondary address must be {} characters or fewer",
            MAX_COLUMN_TEXT_LEN
        )));
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    /// Verify that `normalize_secondary_name` lowercases and trims.
    #[test]
    fn normalize_secondary_name_lowercases_and_trims() {
        assert_eq!(
            normalize_secondary_name("  NS2.Example ").unwrap(),
            "ns2.example"
        );
    }

    /// Verify that `normalize_secondary_name` rejects a name that is not a plain identifier.
    #[test]
    fn normalize_secondary_name_rejects_a_name_that_is_not_a_plain_identifier() {
        for name in ["", "ns 2", "ns2/eu", &"n".repeat(256)] {
            let err = normalize_secondary_name(name).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidInput, "{name:?}");
        }
    }

    /// Verify that `normalize_secondary_address` spells the port out and lowercases a hostname.
    #[test]
    fn normalize_secondary_address_spells_the_port_out_and_lowercases_a_hostname() {
        assert_eq!(
            normalize_secondary_address(" NS2.Example.net ")
                .unwrap()
                .to_string(),
            "ns2.example.net:53"
        );
        assert_eq!(
            normalize_secondary_address("ns2.example.net.")
                .unwrap()
                .to_string(),
            "ns2.example.net:53"
        );
        assert_eq!(
            normalize_secondary_address("192.0.2.7")
                .unwrap()
                .to_string(),
            "192.0.2.7:53"
        );
        assert_eq!(
            normalize_secondary_address("2001:db8::7")
                .unwrap()
                .to_string(),
            "[2001:db8::7]:53"
        );
        assert_eq!(
            normalize_secondary_address("[2001:db8::7]:5300")
                .unwrap()
                .to_string(),
            "[2001:db8::7]:5300"
        );
    }

    /// Verify that `normalize_secondary_address` rejects an entry that is not an address target.
    #[test]
    fn normalize_secondary_address_rejects_an_entry_that_is_not_an_address_target() {
        for address in ["", "not a host", "ns2.example.net:port", "192.0.2.7:0"] {
            let err = normalize_secondary_address(address).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidInput, "{address:?}");
        }
    }
}
