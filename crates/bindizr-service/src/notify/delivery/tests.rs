use std::error::Error;

use bindizr_core::{
    config::Config,
    dns::{
        message::{Keepalive, OptRcode, ParsedQuery},
        query::ParseResponseError,
    },
    metrics::Metrics,
};
use bindizr_db::Db;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch},
};

use super::*;
use crate::{authorization::Caller, types::CreateSecondaryRequest};

/// A failed ACK remains typed for propagation while reports render the same error text.
#[tokio::test]
async fn zone_notify_preserves_failure_causes_and_completes_other_deliveries() {
    let mut config: Config = serde_json::from_str("{}").unwrap();
    config.database.sqlite.file_path = "sqlite::memory:".into();
    config.dns.notify.timeout_secs = 1;
    config.dns.notify.retries = 0;
    let db = Db::connect(&config.database).await.unwrap();
    let cx = Context::new(
        config,
        String::new(),
        db,
        Metrics::new().unwrap(),
        mpsc::unbounded_channel().0,
        watch::channel(0).0,
    );
    let mut servers = Vec::new();
    let mut failed_address = String::new();
    for (name, rcode) in [
        ("failed", OptRcode::SERVFAIL),
        ("accepted", OptRcode::NOERROR),
    ] {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap().to_string();
        if name == "failed" {
            failed_address = address.clone();
        }
        secondary::create(
            &cx,
            &Caller::socket(),
            &CreateSecondaryRequest {
                name: name.into(),
                address,
                notify_key_name: None,
            },
        )
        .await
        .unwrap();
        servers.push(tokio::spawn(async move {
            for _ in 0..2 {
                let mut buffer = [0; 4096];
                let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let query = ParsedQuery::parse(&buffer[..len], Keepalive::None).unwrap();
                let response = query
                    .build_signed_error_response(rcode, None, None)
                    .unwrap();
                socket.send_to(&response, peer).await.unwrap();
            }
        }));
    }

    let zone_name = ZoneName::parse("example.com").unwrap();
    let error = send_zone_notify(&cx, &zone_name).await.unwrap_err();
    let NotifyZoneError::Undelivered {
        zone_name: failed_zone,
        failures,
    } = &error
    else {
        panic!("unexpected NOTIFY failure: {error}");
    };
    assert_eq!(failed_zone, "example.com");
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].0, failed_address);
    assert!(matches!(
        &failures[0].1,
        NotifyDeliveryError::Send(SendNotifyError::Response(ParseResponseError::NotifyRcode(
            OptRcode::SERVFAIL
        )))
    ));
    assert!(matches!(
        failures[0]
            .1
            .source()
            .unwrap()
            .downcast_ref::<SendNotifyError>(),
        Some(SendNotifyError::Response(ParseResponseError::NotifyRcode(
            OptRcode::SERVFAIL
        )))
    ));
    let expected_message = failures[0].1.to_string();
    assert_eq!(
        error.to_string(),
        format!("NOTIFY failed for zone example.com ({failed_address}: {expected_message})")
    );

    let reports = send_notify_to_secondaries(&cx, &zone_name).await.unwrap();
    assert_eq!(reports.len(), 2);
    assert_eq!(
        reports
            .iter()
            .filter(|report| report.error.is_none())
            .count(),
        1
    );
    assert_eq!(
        reports
            .iter()
            .find(|report| report.address == failed_address)
            .unwrap()
            .error
            .as_deref(),
        Some(expected_message.as_str())
    );
    for server in servers {
        server.await.unwrap();
    }
}

/// Signing-key preparation keeps its service and underlying storage cause.
#[test]
fn delivery_key_failure_preserves_service_source() {
    let error = NotifyDeliveryError::Key(ServiceError::internal_with_source(
        "failed to read NOTIFY key",
        std::io::Error::from_raw_os_error(5),
    ));
    let service = error
        .source()
        .unwrap()
        .downcast_ref::<ServiceError>()
        .unwrap();
    assert_eq!(
        service
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(5),
    );
    assert_eq!(error.to_string(), "failed to read NOTIFY key");
}
