//! DNSSEC verification with the parent checked: the service's stored-state
//! checks plus, with a resolver configured, the DS the parent serves.
//! One home shared by the HTTP API and the daemon socket.

use bindizr_core::config::bindizr_config;
use bindizr_service::{
    authorization::Caller,
    dnssec::DnssecService,
    error::ServiceError,
    types::{DnssecCheckInfo, VerifyDnssecResponse},
};

use crate::dns::client::probe;

pub(crate) async fn verify(
    caller: &Caller,
    zone_name: &str,
) -> Result<VerifyDnssecResponse, ServiceError> {
    let mut response = DnssecService::verify(caller, zone_name).await?;

    let resolver = bindizr_config().dnssec.ds_probe_resolver.trim().to_string();
    if !resolver.is_empty() {
        let expected = DnssecService::get_status(caller, zone_name)
            .await?
            .ds_records;
        let (ok, detail) = match probe::probe_parent_ds(&response.zone_name).await {
            Ok(seen) if seen.is_empty() => (
                false,
                format!("no DS at {} (delegation is insecure)", resolver),
            ),
            Ok(seen) => {
                let matched = seen
                    .iter()
                    .filter(|answer| {
                        expected.iter().any(|ds| {
                            i32::from(answer.key_tag) == ds.key_tag
                                && answer.algorithm == ds.algorithm
                                && answer.digest_type == ds.digest_type
                                && answer.digest == ds.digest
                        })
                    })
                    .count();
                (
                    matched > 0,
                    format!(
                        "{} of {} DS records at {} match this zone's keys",
                        matched,
                        seen.len(),
                        resolver
                    ),
                )
            }
            Err(e) => (false, format!("probe at {} failed: {}", resolver, e)),
        };
        response.ok &= ok;
        response.checks.push(DnssecCheckInfo {
            check: "parent-ds".to_string(),
            ok,
            detail,
        });
    }
    Ok(response)
}
