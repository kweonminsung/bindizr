//! Delete a registered secondary and save the activity log row.

use bindizr_core::model::activity_log::{ActivityOperation, ActivityResult};
use bindizr_core::model::role_grant::Action;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::types::MessageResponse;
use crate::{Context, activity, secondary, transaction};

/// Delete a secondary by name.
pub async fn delete(
    cx: &Context,
    caller: &Caller,
    name: &str,
) -> Result<MessageResponse, ServiceError> {
    caller.authorize_action(Action::SecondaryManage)?;

    // Unlocked read to learn the row to delete; a row gone meanwhile reads as not found below.
    let secondary = secondary::lookup_by_name(cx, name).await?;

    let mut tx = transaction::begin_tx(cx, "failed to delete secondary").await?;

    let apply_result: Result<_, ServiceError> = async {
        caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_action(Action::SecondaryManage)?;

        // A concurrent removal makes this deletion report not found.
        if !bindizr_db::secondary::delete_tx(&mut tx, secondary.id).await? {
            return Err(ServiceError::secondary_not_found(&secondary.name));
        }

        activity::save_detail_tx(
            &mut tx,
            ActivityOperation::SecondaryDelete,
            ActivityResult::Changed,
            activity::named_target(&secondary.name),
            None,
            caller.change_origin(),
        )
        .await
    }
    .await;

    transaction::finish_tx(tx, apply_result, "failed to delete secondary").await?;

    Ok(MessageResponse {
        message: format!("Secondary '{}' deleted successfully", secondary.name),
    })
}
