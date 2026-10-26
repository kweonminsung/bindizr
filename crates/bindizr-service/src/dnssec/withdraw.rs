//! The RFC 8078 DS withdrawal: publishing the delete CDS/CDNSKEY pair that
//! asks a CDS-consuming parent to drop the zone's DS, and taking it back.

use bindizr_core::dns::dnssec::SigningPass;
use bindizr_core::dns::name::ZoneName;
use bindizr_core::model::role_grant::Action;
use bindizr_db::LockLevel;

use super::status;
use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::types::DnssecStatusResponse;
use crate::{Context, transaction};

/// Publish the RFC 8078 delete CDS/CDNSKEY pair, asking a CDS-consuming
/// parent to drop the zone's DS: the first step of going insecure.
pub async fn withdraw(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
) -> Result<DnssecStatusResponse, ServiceError> {
    let mut tx = transaction::begin_tx(cx, "failed to withdraw the parent DS").await?;
    let result = async {
        let signed = super::get_signed_zone_tx(
            &mut tx,
            caller,
            Action::DnssecManage,
            zone_name,
            LockLevel::Exclusive,
        )
        .await?;

        if bindizr_db::dnssec_withdrawal::get_tx(&mut tx, signed.zone.id)
            .await?
            .is_some()
        {
            return Err(ServiceError::invalid_input(
                "the DS withdrawal is already published",
            ));
        }

        bindizr_db::dnssec_withdrawal::create_tx(&mut tx, signed.zone.id).await?;

        let new_serial = super::resign_zone_tx(
            &mut tx,
            &signed,
            SigningPass::Refresh,
            caller.change_origin(),
        )
        .await?
        .unwrap_or(signed.zone.serial);

        let response = status::load_status_tx(
            &mut tx,
            &signed.zone,
            Some(&signed.policy),
            &signed.keys,
            new_serial,
        )
        .await?;

        Ok((response, new_serial != signed.zone.serial))
    }
    .await;
    let (response, changed) =
        transaction::finish_tx(tx, result, "failed to withdraw the parent DS").await?;

    if changed {
        cx.metrics().track_serial_bumps(1);
    }

    log::info!("event=dnssec_withdraw zone={}", response.zone_name);

    if changed {
        crate::notify::notify_after_update(cx, zone_name).await;
    }

    Ok(response)
}

/// Take back a published DS withdrawal: the per-key CDS/CDNSKEY set
/// returns on the next signing pass.
pub async fn cancel_withdrawal(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
) -> Result<DnssecStatusResponse, ServiceError> {
    let mut tx = transaction::begin_tx(cx, "failed to cancel the DS withdrawal").await?;
    let result = async {
        let signed = super::get_signed_zone_tx(
            &mut tx,
            caller,
            Action::DnssecManage,
            zone_name,
            LockLevel::Exclusive,
        )
        .await?;

        if bindizr_db::dnssec_withdrawal::get_tx(&mut tx, signed.zone.id)
            .await?
            .is_none()
        {
            return Err(ServiceError::invalid_input("no DS withdrawal is published"));
        }

        bindizr_db::dnssec_withdrawal::delete_tx(&mut tx, signed.zone.id).await?;

        let new_serial = super::resign_zone_tx(
            &mut tx,
            &signed,
            SigningPass::Refresh,
            caller.change_origin(),
        )
        .await?
        .unwrap_or(signed.zone.serial);

        let response = status::load_status_tx(
            &mut tx,
            &signed.zone,
            Some(&signed.policy),
            &signed.keys,
            new_serial,
        )
        .await?;

        Ok((response, new_serial != signed.zone.serial))
    }
    .await;
    let (response, changed) =
        transaction::finish_tx(tx, result, "failed to cancel the DS withdrawal").await?;

    if changed {
        cx.metrics().track_serial_bumps(1);
    }

    log::info!("event=dnssec_withdraw_cancel zone={}", response.zone_name);

    if changed {
        crate::notify::notify_after_update(cx, zone_name).await;
    }

    Ok(response)
}
