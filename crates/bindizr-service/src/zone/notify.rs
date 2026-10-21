//! Manual NOTIFY requests after authorization and optional zone serial increments.

use std::sync::Arc;

use bindizr_core::model::role_grant::Action;

use crate::{
    Context,
    authorization::Caller,
    error::ServiceError,
    notify::NotifyTarget,
    types::{MessageResponse, NotifySerial},
};

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
        NotifyTarget::Zone(name) if name == &cx.config().dns.catalog_zone_name => {
            caller.authorize_action(Action::ZoneUpdate)?;
            if serial == NotifySerial::Bump {
                log::info!("Skipping forced serial increment for virtual catalog zone");
            }
        }
        NotifyTarget::Zone(name) => {
            let zone = super::lookup_by_name(cx, name).await?;
            caller.authorize_zone_action(Action::ZoneUpdate, &zone)?;
            if serial == NotifySerial::Bump {
                super::force_increment_serial(cx, caller, name).await?;
                serial_bumped = true;
            }
        }
        NotifyTarget::All => {
            caller.authorize_action(Action::ZoneUpdate)?;
            if serial == NotifySerial::Bump {
                for zone in super::list(cx).await? {
                    super::force_increment_serial(cx, caller, &zone.name).await?;
                    serial_bumped = true;
                }
            }
        }
    }

    crate::notify::send_notify(cx, target).await?;

    let scope = match target {
        NotifyTarget::Zone(zone_name) => format!("zone: {}", zone_name),
        NotifyTarget::All => "all zones".to_string(),
    };
    let suffix = if serial_bumped {
        " (serial bumped)"
    } else {
        ""
    };

    Ok(MessageResponse {
        message: format!("NOTIFY sent successfully for {}{}", scope, suffix),
    })
}

#[cfg(test)]
mod tests {
    use bindizr_core::{config::Config, metrics::Metrics};

    use super::*;

    /// Messages describe completed increments, including requests whose target has none.
    #[tokio::test]
    async fn notify_reports_only_serials_it_advanced() {
        let config: Config = serde_json::from_value(serde_json::json!({
            "database": { "sqlite": { "file_path": "sqlite::memory:" } },
        }))
        .unwrap();
        let db = bindizr_db::Db::connect(&config.database).await.unwrap();
        let (jobs, _rx) = tokio::sync::mpsc::unbounded_channel();
        let (period, _period_rx) = tokio::sync::watch::channel(0);
        let cx = Arc::new(Context::new(
            config,
            String::new(),
            db,
            Metrics::new().unwrap(),
            jobs,
            period,
        ));
        let caller = Caller::socket();

        let empty = notify(&cx, &caller, NotifyTarget::All, NotifySerial::Bump)
            .await
            .unwrap();
        assert_eq!(empty.message, "NOTIFY sent successfully for all zones");

        let (catalog, _) = crate::zone::refresh_catalog(&cx).await.unwrap();
        let response = notify(
            &cx,
            &caller,
            NotifyTarget::Zone(&catalog.name),
            NotifySerial::Bump,
        )
        .await
        .unwrap();
        assert_eq!(
            response.message,
            format!("NOTIFY sent successfully for zone: {}", catalog.name)
        );
        assert_eq!(
            crate::zone::refresh_catalog(&cx).await.unwrap().0.serial,
            catalog.serial
        );

        let request = serde_json::from_value(serde_json::json!({
            "name": "example.test", "mname": "ns.example.test", "rname": "hostmaster@example.test",
        }))
        .unwrap();
        crate::zone::create(&cx, &caller, &request).await.unwrap();
        let name = crate::zone::normalize_name("example.test").unwrap();
        let original = crate::zone::get_by_name(&cx, &caller, &name).await.unwrap();

        let kept = notify(&cx, &caller, NotifyTarget::Zone(&name), NotifySerial::Keep)
            .await
            .unwrap();
        assert!(!kept.message.contains("serial bumped"));
        assert_eq!(
            crate::zone::get_by_name(&cx, &caller, &name)
                .await
                .unwrap()
                .serial,
            original.serial
        );

        for target in [NotifyTarget::Zone(&name), NotifyTarget::All] {
            let before = crate::zone::get_by_name(&cx, &caller, &name)
                .await
                .unwrap()
                .serial;
            let response = notify(&cx, &caller, target, NotifySerial::Bump)
                .await
                .unwrap();
            assert!(response.message.ends_with(" (serial bumped)"));
            assert!(
                crate::zone::get_by_name(&cx, &caller, &name)
                    .await
                    .unwrap()
                    .serial
                    .is_newer_than(before)
            );
        }
    }
}
