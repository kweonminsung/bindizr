//! The RFC 8078 DS withdrawal: publishing the delete CDS/CDNSKEY pair that
//! asks a CDS-consuming parent to drop the zone's DS, and taking it back.

use super::{DnssecService, status::build_status_tx};
use crate::{
    authorization::Caller, database::repository::LockLevel, error::ServiceError,
    repository::RepositoryService, types::DnssecStatusResponse,
};

impl DnssecService {
    /// Publish the RFC 8078 delete CDS/CDNSKEY pair, asking a CDS-consuming
    /// parent to drop the zone's DS: the first step of going insecure.
    pub async fn withdraw(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<DnssecStatusResponse, ServiceError> {
        caller.authorize_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to withdraw the parent DS").await?;
        let result = async {
            let signed = Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            if RepositoryService::get_dnssec_withdrawal_tx(&mut tx, signed.zone.id)
                .await?
                .is_some()
            {
                return Err(ServiceError::invalid_input(
                    "the DS withdrawal is already published",
                ));
            }
            RepositoryService::create_dnssec_withdrawal_tx(&mut tx, signed.zone.id).await?;

            let new_serial =
                Self::resign_zone_tx(&mut tx, &signed, false, &caller.change_subject())
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
        let response =
            RepositoryService::finish_tx(tx, result, "failed to withdraw the parent DS").await?;

        log::info!("event=dnssec_withdraw zone={}", response.zone_name);
        crate::notify::notify_after_update(&response.zone_name).await;
        Ok(response)
    }

    /// Take back a published DS withdrawal: the per-key CDS/CDNSKEY set
    /// returns on the next signing pass.
    pub async fn cancel_withdrawal(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<DnssecStatusResponse, ServiceError> {
        caller.authorize_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to cancel the DS withdrawal").await?;
        let result = async {
            let signed = Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            if RepositoryService::get_dnssec_withdrawal_tx(&mut tx, signed.zone.id)
                .await?
                .is_none()
            {
                return Err(ServiceError::invalid_input("no DS withdrawal is published"));
            }
            RepositoryService::delete_dnssec_withdrawal_tx(&mut tx, signed.zone.id).await?;

            let new_serial =
                Self::resign_zone_tx(&mut tx, &signed, false, &caller.change_subject())
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
        let response =
            RepositoryService::finish_tx(tx, result, "failed to cancel the DS withdrawal").await?;

        log::info!("event=dnssec_withdraw_cancel zone={}", response.zone_name);
        crate::notify::notify_after_update(&response.zone_name).await;
        Ok(response)
    }
}
