//! The RFC 8078 DS withdrawal: publishing the delete CDS/CDNSKEY pair that
//! asks a CDS-consuming parent to drop the zone's DS, and taking it back.

use bindizr_core::dns::{dnssec::SigningPass, name::ZoneName};
use bindizr_db::LockLevel;

use super::status::build_status_tx;
use crate::{
    Context, authorization::Caller, error::ServiceError, transaction, types::DnssecStatusResponse,
};

/// Publish the RFC 8078 delete CDS/CDNSKEY pair, asking a CDS-consuming
/// parent to drop the zone's DS: the first step of going insecure.
pub async fn withdraw(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
) -> Result<DnssecStatusResponse, ServiceError> {
    caller.authorize_global("manage DNSSEC signing")?;

    let mut tx = transaction::begin_tx(cx, "failed to withdraw the parent DS").await?;
    let result = async {
        let signed = super::lookup_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
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
            cx,
            &signed,
            SigningPass::Refresh,
            caller.change_attribution(),
        )
        .await?
        .unwrap_or(signed.zone.serial);

        build_status_tx(
            &mut tx,
            &signed.zone,
            Some(&signed.policy),
            &signed.keys,
            new_serial,
        )
        .await
    }
    .await;
    let response = transaction::finish_tx(tx, result, "failed to withdraw the parent DS").await?;

    log::info!("event=dnssec_withdraw zone={}", response.zone_name);
    crate::notify::notify_after_update(cx, zone_name).await;
    Ok(response)
}

/// Take back a published DS withdrawal: the per-key CDS/CDNSKEY set
/// returns on the next signing pass.
pub async fn cancel_withdrawal(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
) -> Result<DnssecStatusResponse, ServiceError> {
    caller.authorize_global("manage DNSSEC signing")?;

    let mut tx = transaction::begin_tx(cx, "failed to cancel the DS withdrawal").await?;
    let result = async {
        let signed = super::lookup_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        if bindizr_db::dnssec_withdrawal::get_tx(&mut tx, signed.zone.id)
            .await?
            .is_none()
        {
            return Err(ServiceError::invalid_input("no DS withdrawal is published"));
        }
        bindizr_db::dnssec_withdrawal::delete_tx(&mut tx, signed.zone.id).await?;

        let new_serial = super::resign_zone_tx(
            &mut tx,
            cx,
            &signed,
            SigningPass::Refresh,
            caller.change_attribution(),
        )
        .await?
        .unwrap_or(signed.zone.serial);

        build_status_tx(
            &mut tx,
            &signed.zone,
            Some(&signed.policy),
            &signed.keys,
            new_serial,
        )
        .await
    }
    .await;
    let response = transaction::finish_tx(tx, result, "failed to cancel the DS withdrawal").await?;

    log::info!("event=dnssec_withdraw_cancel zone={}", response.zone_name);
    crate::notify::notify_after_update(cx, zone_name).await;
    Ok(response)
}
