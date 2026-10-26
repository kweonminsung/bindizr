use std::str::FromStr;

use bindizr_core::config::Config;
use bindizr_core::dns::message::{Name, Opcode, OptRcode};
use bindizr_core::dns::{message, query};
use bindizr_core::metrics::Metrics;
use bindizr_service::authorization::Caller;
use bindizr_service::{Context, secondary, zone};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::time;

use super::*;
use crate::dns::{tcp, tls, udp};
use crate::shutdown::Shutdown;

/// Build real service state with unsigned UPDATE and synchronous NOTIFY enabled.
async fn context() -> Arc<Context> {
    let mut config: Config = serde_json::from_str("{}").unwrap();
    config.database.sqlite.file_path = "sqlite::memory:".into();
    config.dns.nsupdate.tsig_required = false;
    config.dns.notify.batch_ms = 0;
    config.dns.notify.timeout_secs = 3;
    config.dns.notify.retries = 0;

    let db = bindizr_db::Db::connect(&config.database).await.unwrap();

    Arc::new(Context::new(
        config,
        String::new(),
        db,
        Metrics::new().unwrap(),
        mpsc::unbounded_channel().0,
        watch::channel(0).0,
    ))
}

/// Stopping a listener waits for a committed UPDATE's NOTIFY before ending its request task.
#[tokio::test]
async fn listeners_finish_in_flight_updates_before_shutdown_returns() {
    for tcp in [false, true] {
        let cx = context().await;

        let caller = Caller::socket();
        let request = serde_json::from_str(
            r#"{"name":"example.com","mname":"ns1.example.com","rname":"admin@example.com"}"#,
        )
        .unwrap();

        zone::create(&cx, &caller, &request).await.unwrap();
        let secondary_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = serde_json::from_value(serde_json::json!({
            "name": "ack-gate",
            "address": secondary_socket.local_addr().unwrap().to_string(),
        }))
        .unwrap();

        secondary::create(&cx, &caller, &request).await.unwrap();

        let dns_cx = Arc::new(DnsContext::new(cx.clone()));
        let shutdown = Shutdown::new();
        let stop = shutdown.waiter();
        let mut tcp_client = None;
        let mut udp_client = None;

        let mut server = if tcp {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            tcp_client = Some(
                TcpStream::connect(listener.local_addr().unwrap())
                    .await
                    .unwrap(),
            );

            tokio::spawn(async move { tcp::run_tcp_server(dns_cx, listener, stop).await.unwrap() })
        } else {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = socket.local_addr().unwrap();

            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client.connect(address).await.unwrap();

            udp_client = Some(client);
            let socket = udp::UdpSocket::new(socket).unwrap();

            tokio::spawn(udp::run_udp_server(dns_cx, socket, stop))
        };

        let (_, question) = query::build_question(
            Opcode::UPDATE,
            false,
            false,
            &Name::<Vec<u8>>::from_str("example.com").unwrap(),
            Rtype::SOA,
            None,
        );
        let mut update = question.finish();
        update[8..10].copy_from_slice(&1u16.to_be_bytes());
        update.extend_from_slice(&[
            3, b'w', b'w', b'w', 0xc0, 12, // owner
            0, 1, 0, 1, // A, IN
            0, 0, 1, 44, // TTL 300
            0, 4, 192, 0, 2, 9,
        ]);

        if let Some(client) = &mut tcp_client {
            client
                .write_all(&message::encode_tcp_message(&update).unwrap())
                .await
                .unwrap();
        } else {
            udp_client.as_ref().unwrap().send(&update).await.unwrap();
        }

        let mut notify = [0; 4096];

        let (len, peer) = time::timeout(
            Duration::from_secs(2),
            secondary_socket.recv_from(&mut notify),
        )
        .await
        .unwrap()
        .unwrap();

        shutdown.trigger();

        assert!(
            time::timeout(Duration::from_millis(50), &mut server)
                .await
                .is_err()
        );
        let response = message::ParsedQuery::parse(&notify[..len], Keepalive::None)
            .unwrap()
            .build_signed_error_response(OptRcode::NOERROR, None, None)
            .unwrap();

        secondary_socket.send_to(&response, peer).await.unwrap();
        let response = if let Some(client) = &mut tcp_client {
            let len = time::timeout(Duration::from_secs(2), client.read_u16())
                .await
                .unwrap()
                .unwrap();
            let mut response = vec![0; usize::from(len)];

            client.read_exact(&mut response).await.unwrap();

            response
        } else {
            let mut response = vec![0; 4096];

            let len = time::timeout(
                Duration::from_secs(2),
                udp_client.as_ref().unwrap().recv(&mut response),
            )
            .await
            .unwrap()
            .unwrap();
            response.truncate(len);

            response
        };

        assert_eq!(response[3] & 15, 0, "tcp={tcp}");

        time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        let records = bindizr_service::record::list_by_filter_with_zone(
            &cx,
            &caller,
            bindizr_service::types::RecordFilter {
                zone_name: Some("example.com".into()),
                name: Some("www".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(records.items.len(), 1);
    }
}

/// Shutdown closes idle TCP sessions and cancels a TLS handshake that has received no bytes.
#[tokio::test]
async fn listeners_stop_idle_connections_without_waiting_for_protocol_timeouts() {
    for tls in [false, true] {
        let cx = context().await;
        let dns_cx = Arc::new(DnsContext::new(cx));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();

        let shutdown = Shutdown::new();
        let stop = shutdown.waiter();
        let server_cx = dns_cx.clone();

        let server = tokio::spawn(async move {
            if tls {
                let config = rustls::ServerConfig::builder_with_protocol_versions(&[
                    &rustls::version::TLS13,
                ])
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));

                tls::run_tls_server(server_cx, listener, Arc::new(config), stop)
                    .await
                    .unwrap();
            } else {
                tcp::run_tcp_server(server_cx, listener, stop)
                    .await
                    .unwrap();
            }
        });
        time::timeout(Duration::from_secs(2), async {
            while Arc::strong_count(&dns_cx) < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        shutdown.trigger();

        time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();

        let mut byte = [0];

        assert_eq!(client.read(&mut byte).await.unwrap(), 0, "tls={tls}");
    }
}
