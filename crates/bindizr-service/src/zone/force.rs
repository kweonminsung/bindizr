use bindizr_core::dns::name::ZoneName;
use bindizr_db::LockLevel;

use crate::{
    Context, dnssec, error::ServiceError, model::zone::Zone, notify::NotifyTarget,
    serial::generate_serial, transaction, zone::version::ChangeSubject,
};

/// Force-increment the serial of one zone by name, or of every zone.
pub(crate) async fn force_increment_serial(
    cx: &Context,
    target: NotifyTarget<'_>,
    subject: &ChangeSubject,
) -> Result<Vec<Zone>, ServiceError> {
    match target {
        NotifyTarget::Zone(name) => {
            let zone = force_increment_serial_by_name(cx, name, subject).await?;
            Ok(vec![zone])
        }
        NotifyTarget::All => {
            let zones = super::list(cx).await?;
            let mut bumped_zones = Vec::with_capacity(zones.len());

            for zone in zones {
                // Bump each zone in its own transaction so the new serial
                // derives from the current row and a concurrent edit to other
                // fields is not clobbered.
                bumped_zones.push(force_increment_serial_by_name(cx, &zone.name, subject).await?);
            }

            Ok(bumped_zones)
        }
    }
}

/// Advance a named zone's serial and save its signed version atomically.
async fn force_increment_serial_by_name(
    cx: &Context,
    zone_name: &ZoneName,
    subject: &ChangeSubject,
) -> Result<Zone, ServiceError> {
    let mut tx = transaction::begin_tx(cx, "Failed to force increment zone serial").await?;

    let apply_result = async {
        let zone = super::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;

        let new_serial = generate_serial(Some(zone.serial))?;
        let updated_zone = bindizr_db::zone::update_tx(
            &mut tx,
            Zone {
                serial: new_serial,
                ..zone
            },
        )
        .await
        .map_err(|e| {
            log::error!("Failed to force increment zone serial: {}", e);
            ServiceError::internal("Failed to force increment zone serial")
        })?;

        // The SOA rdata carries the serial, so its signature must follow
        // every bump — forced ones included.
        dnssec::sign_zone_tx(&mut tx, &updated_zone, new_serial).await?;
        super::save_version_tx(cx, &mut tx, &updated_zone, new_serial, subject).await?;

        Ok::<Zone, ServiceError>(updated_zone)
    }
    .await;

    let updated_zone =
        transaction::finish_tx(tx, apply_result, "Failed to force increment zone serial").await?;

    log::info!(
        "event=zone_force_serial zone={} new_serial={} zone_id={}",
        updated_zone.name,
        updated_zone.serial,
        updated_zone.id
    );

    Ok(updated_zone)
}
