use bindizr_core::dns::name::ZoneName;
use bindizr_core::model::activity_log::ActivityOperation;
use bindizr_core::model::role_grant::Action;
use bindizr_core::model::zone::Zone;
use bindizr_db::LockLevel;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::{Context, dnssec, serial, transaction, zone};

/// Advance a named zone's serial for a manual NOTIFY and save its signed version atomically.
/// Report whether the locked zone was still enabled and could be bumped.
pub(super) async fn bump_zone_serial(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
) -> Result<bool, ServiceError> {
    let mut tx = transaction::begin_tx(cx, "failed to force increment zone serial").await?;

    let apply_result: Result<_, ServiceError> = async {
        let zone = zone::lookup_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        let caller = &caller.reauthenticate_tx(&mut tx).await?;
        caller.authorize_zone_action(Action::ZoneUpdate, &zone)?;
        if !zone.enabled {
            return Ok(None);
        }

        let new_serial = serial::generate_serial(Some(zone.serial));

        // The bump's SOA pair is its only journal row, so IXFR can step across
        // it rather than read a gap and answer AXFR.
        let bumped = Zone {
            serial: new_serial,
            ..zone.clone()
        };
        let changes = zone::soa_replacement_changes(&zone, &bumped, new_serial)?;
        bindizr_db::zone_change::create_many_tx(&mut tx, &changes).await?;

        // The SOA rdata carries the serial, so its signature must follow
        // every bump — forced ones included.
        dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;
        zone::advance_serial_tx(&mut tx, &zone, new_serial, caller.change_origin()).await?;

        crate::activity::save_tx(
            &mut tx,
            ActivityOperation::ZoneNotify,
            zone::activity_target(&zone.name),
            caller.change_origin(),
        )
        .await?;

        Ok(Some((zone, new_serial)))
    }
    .await;

    let Some((zone, new_serial)) =
        transaction::finish_tx(tx, apply_result, "failed to force increment zone serial").await?
    else {
        return Ok(false);
    };

    cx.metrics().track_serial_bumps(1);
    log::info!(
        "event=zone_force_serial zone={} new_serial={} zone_id={}",
        zone.name,
        new_serial,
        zone.id
    );

    Ok(true)
}
