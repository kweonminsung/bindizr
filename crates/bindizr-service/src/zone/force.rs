use bindizr_core::dns::name::ZoneName;
use bindizr_core::model::role_grant::Action;
use bindizr_core::model::zone::Zone;
use bindizr_db::LockLevel;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::{Context, dnssec, serial, transaction, zone};

/// Advance a named zone's serial and save its signed version atomically.
pub(crate) async fn force_increment_serial(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
) -> Result<(), ServiceError> {
    let mut tx = transaction::begin_tx(cx, "failed to force increment zone serial").await?;

    let apply_result: Result<_, ServiceError> = async {
        let zone = zone::lookup_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        let caller = &caller.reauthenticate_tx(&mut tx).await?;
        caller.authorize_zone_action(Action::ZoneUpdate, &zone)?;

        let new_serial = serial::generate_serial(Some(zone.serial));

        let updated_zone = bindizr_db::zone::update_tx(
            &mut tx,
            Zone {
                serial: new_serial,
                ..zone
            },
        )
        .await
        .map_err(|error| {
            ServiceError::internal_with_source("failed to force increment zone serial", error)
        })?;

        // The SOA rdata carries the serial, so its signature must follow
        // every bump — forced ones included.
        dnssec::sign_zone_tx(&mut tx, &updated_zone, new_serial).await?;
        zone::save_version_tx(&mut tx, &updated_zone, new_serial, caller.change_origin()).await?;

        Ok(updated_zone)
    }
    .await;

    let updated_zone =
        transaction::finish_tx(tx, apply_result, "failed to force increment zone serial").await?;

    cx.metrics().track_serial_bumps(1);
    log::info!(
        "event=zone_force_serial zone={} new_serial={} zone_id={}",
        updated_zone.name,
        updated_zone.serial,
        updated_zone.id
    );

    Ok(())
}
