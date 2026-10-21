//! Register a secondary and save its management audit entry.

use bindizr_core::model::{
    audit_log::{AuditEntity, AuditOperation},
    role_grant::Action,
    secondary::SecondaryId,
};
use chrono::Utc;

use super::{normalize_secondary_address, normalize_secondary_name};
use crate::{
    Context, audit,
    authorization::Caller,
    error::ServiceError,
    model::secondary::Secondary,
    transaction, tsig_key,
    types::{CreateSecondaryRequest, SecondaryResponse},
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
        .map_err(|error| {
            // The UNIQUE(name) / UNIQUE(address) backstop for the pre-checks above.
            if error.is_unique_violation() {
                ServiceError::secondary_conflict(format!(
                    "secondary with name '{}' or address '{}' already exists",
                    name, address
                ))
            } else {
                error.into()
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
