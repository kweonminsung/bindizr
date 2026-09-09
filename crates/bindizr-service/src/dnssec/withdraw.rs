//! The RFC 8078 DS withdrawal: publishing the delete CDS/CDNSKEY pair that
//! asks a CDS-consuming parent to drop the zone's DS, and taking it back.

use super::{DnssecService, notify_zone, status::build_status_tx};
use crate::{
    authorization::Caller, database::repository::LockLevel, error::ServiceError,
    repository::RepositoryService, types::GetDnssecStatusResponse,
};

impl DnssecService {
    /// Publish the RFC 8078 delete CDS/CDNSKEY pair, asking a CDS-consuming
    /// parent to drop the zone's DS: the first step of going insecure.
    pub async fn withdraw(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to withdraw the parent DS").await?;
        let result = async {
            let (zone, policy, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            if RepositoryService::get_dnssec_withdrawal_tx(&mut tx, zone.id)
                .await?
                .is_some()
            {
                return Err(ServiceError::invalid_input(
                    "the DS withdrawal is already published",
                ));
            }
            RepositoryService::create_dnssec_withdrawal_tx(&mut tx, zone.id).await?;

            let new_serial = Self::resign_zone_tx(&mut tx, &zone, &policy, &keys, false)
                .await?
                .unwrap_or(zone.serial);

            build_status_tx(&mut tx, &zone, Some(&policy), &keys, new_serial).await
        }
        .await;
        let response =
            RepositoryService::finish_tx(tx, result, "failed to withdraw the parent DS").await?;

        crate::log_info!("event=dnssec_withdraw zone={}", response.zone_name);
        notify_zone(&response.zone_name).await;
        Ok(response)
    }

    /// Take back a published DS withdrawal: the per-key CDS/CDNSKEY set
    /// returns on the next signing pass.
    pub async fn withdraw_cancel(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to cancel the DS withdrawal").await?;
        let result = async {
            let (zone, policy, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            if RepositoryService::get_dnssec_withdrawal_tx(&mut tx, zone.id)
                .await?
                .is_none()
            {
                return Err(ServiceError::invalid_input("no DS withdrawal is published"));
            }
            RepositoryService::delete_dnssec_withdrawal_tx(&mut tx, zone.id).await?;

            let new_serial = Self::resign_zone_tx(&mut tx, &zone, &policy, &keys, false)
                .await?
                .unwrap_or(zone.serial);

            build_status_tx(&mut tx, &zone, Some(&policy), &keys, new_serial).await
        }
        .await;
        let response =
            RepositoryService::finish_tx(tx, result, "failed to cancel the DS withdrawal").await?;

        crate::log_info!("event=dnssec_withdraw_cancel zone={}", response.zone_name);
        notify_zone(&response.zone_name).await;
        Ok(response)
    }
}
