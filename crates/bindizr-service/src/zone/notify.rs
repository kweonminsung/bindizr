//! Manual NOTIFY requests after authorization and optional zone serial increments.

use std::sync::Arc;

use bindizr_core::model::role_grant::Action;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::notify::NotifyTarget;
use crate::types::{MessageResponse, NotifySerial};
use crate::{Context, notify, zone};

/// Send a manual NOTIFY for one zone or all zones, bumping the serial
/// first when `serial` says to; an all-zones round runs the zones concurrently.
pub async fn notify(
    cx: &Arc<Context>,
    caller: &Caller,
    target: NotifyTarget<'_>,
    serial: NotifySerial,
) -> Result<MessageResponse, ServiceError> {
    let mut serial_bumped = false;
    match target {
        // The virtual catalog zone has no row to bump and lists all zones.
        NotifyTarget::Zone(zone_name) if zone_name == &cx.config().dns.catalog_zone_name => {
            caller.authorize_action(Action::ZoneUpdate)?;
            if serial == NotifySerial::Bump {
                log::info!("Skipping forced serial increment for virtual catalog zone");
            }
        }
        NotifyTarget::Zone(zone_name) => {
            let zone = zone::lookup_by_name(cx, zone_name).await?;
            caller.authorize_zone_action(Action::ZoneUpdate, &zone)?;
            if !zone.enabled {
                return Err(ServiceError::invalid_input(format!(
                    "zone '{zone_name}' is disabled, so the DNS plane does not serve it; enable it to send NOTIFY"
                )));
            }
            if serial == NotifySerial::Bump {
                zone::force_increment_serial(cx, caller, zone_name).await?;
                serial_bumped = true;
            }
        }
        NotifyTarget::All => {
            caller.authorize_action(Action::ZoneUpdate)?;
            if serial == NotifySerial::Bump {
                for zone in zone::list(cx).await? {
                    zone::force_increment_serial(cx, caller, &zone.name).await?;
                    serial_bumped = true;
                }
            }
        }
    }

    notify::send_notify(cx, target).await?;

    let scope = match target {
        NotifyTarget::Zone(zone_name) => format!("zone: {zone_name}"),
        NotifyTarget::All => "all zones".to_string(),
    };
    let suffix = if serial_bumped {
        " (serial bumped)"
    } else {
        ""
    };

    Ok(MessageResponse {
        message: format!("NOTIFY sent successfully for {scope}{suffix}"),
    })
}

#[cfg(test)]
mod tests {
    use bindizr_core::config::Config;
    use bindizr_core::dns::name::ZoneName;
    use bindizr_core::metrics::Metrics;
    use bindizr_db::Db;
    use tokio::sync::{mpsc, watch};

    use super::*;
    use crate::types::CreateZoneRequest;
    use crate::zone;

    /// Verify that messages describe completed increments, including requests whose target has
    /// none.
    #[tokio::test]
    async fn notify_reports_only_serials_it_advanced() {
        let mut config: Config = serde_json::from_str("{}").unwrap();
        config.database.sqlite.file_path = "sqlite::memory:".to_string();
        let db = Db::connect(&config.database).await.unwrap();
        let cx = Arc::new(Context::new(
            config,
            String::new(),
            db,
            Metrics::new().unwrap(),
            mpsc::unbounded_channel().0,
            mpsc::channel(1).0,
            watch::channel(0).0,
        ));
        let caller = Caller::socket();

        let empty = notify(&cx, &caller, NotifyTarget::All, NotifySerial::Bump)
            .await
            .unwrap();
        assert_eq!(empty.message, "NOTIFY sent successfully for all zones");

        let (catalog_zone, _) = zone::refresh_catalog(&cx).await.unwrap();
        let response = notify(
            &cx,
            &caller,
            NotifyTarget::Zone(&catalog_zone.name),
            NotifySerial::Bump,
        )
        .await
        .unwrap();
        assert_eq!(
            response.message,
            format!("NOTIFY sent successfully for zone: {}", catalog_zone.name)
        );
        assert_eq!(
            zone::refresh_catalog(&cx).await.unwrap().0.serial,
            catalog_zone.serial
        );

        let request = CreateZoneRequest {
            name: "example.test".to_string(),
            mname: "ns.example.test".to_string(),
            rname: "hostmaster@example.test".to_string(),
            default_ttl: None,
            serial: None,
            refresh: None,
            retry: None,
            expire: None,
            minimum_ttl: None,
            description: None,
            apex_ns: true,
            dry_run: false,
        };
        zone::create(&cx, &caller, &request).await.unwrap();
        let zone_name = ZoneName::parse("example.test").unwrap();
        let original = zone::get_by_name(&cx, &caller, &zone_name).await.unwrap();

        let kept = notify(
            &cx,
            &caller,
            NotifyTarget::Zone(&zone_name),
            NotifySerial::Keep,
        )
        .await
        .unwrap();
        assert!(!kept.message.contains("serial bumped"));
        assert_eq!(
            zone::get_by_name(&cx, &caller, &zone_name)
                .await
                .unwrap()
                .serial,
            original.serial
        );

        for target in [NotifyTarget::Zone(&zone_name), NotifyTarget::All] {
            let before = zone::get_by_name(&cx, &caller, &zone_name)
                .await
                .unwrap()
                .serial;
            let response = notify(&cx, &caller, target, NotifySerial::Bump)
                .await
                .unwrap();
            assert!(response.message.ends_with(" (serial bumped)"));
            assert!(
                zone::get_by_name(&cx, &caller, &zone_name)
                    .await
                    .unwrap()
                    .serial
                    .is_newer_than(before)
            );
        }
    }
}
