//! Delete a registered secondary and save its management audit entry.

use bindizr_core::model::{
    audit_log::{AuditEntity, AuditOperation},
    role_grant::Action,
};

use super::lookup_by_name;
use crate::{Context, audit, authorization::Caller, error::ServiceError, transaction};

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
