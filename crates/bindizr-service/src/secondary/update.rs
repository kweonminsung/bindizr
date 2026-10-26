//! Apply a partial secondary update against its locked row.

use bindizr_core::model::audit_log::{AuditEntity, AuditOperation};
use bindizr_core::model::role_grant::Action;
use bindizr_db::LockLevel;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::model::secondary::Secondary;
use crate::model::tsig_key::TsigKey;
use crate::types::{SecondaryResponse, UpdateSecondaryRequest};
use crate::{Context, audit, transaction, tsig_key};

/// Change a secondary's address, enabled flag, or NOTIFY key; an empty
/// key name sends NOTIFY unsigned again.
pub async fn update(
    cx: &Context,
    caller: &Caller,
    name: &str,
    request: UpdateSecondaryRequest,
) -> Result<SecondaryResponse, ServiceError> {
    caller.authorize_action(Action::SecondaryManage)?;

    let name = super::normalize_secondary_name(name)?;
    let address = request
        .address
        .as_deref()
        .map(super::normalize_secondary_address)
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
                    Some(id) => bindizr_db::tsig_key::get_tx(&mut tx, id, LockLevel::Unlocked)
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
        .map_err(|error| {
            // The UNIQUE(address) backstop for the pre-check above.
            if error.is_unique_violation() {
                ServiceError::secondary_conflict(format!(
                    "secondary with address '{}' already exists",
                    address
                ))
            } else {
                error.into()
            }
        })?;
        audit::save_tx(
            &mut tx,
            AuditEntity::Secondary,
            &secondary.name,
            AuditOperation::Update,
            detail,
            caller.change_origin(),
        )
        .await?;

        Ok(secondary)
    }
    .await;
    let secondary = transaction::finish_tx(tx, result, "failed to update secondary").await?;

    super::load_response(cx, secondary).await
}
