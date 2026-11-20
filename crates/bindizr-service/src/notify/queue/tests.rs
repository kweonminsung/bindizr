use bindizr_core::config::Config;
use bindizr_core::dns::message::{Keepalive, OptRcode, ParsedQuery};
use bindizr_core::metrics::Metrics;
use bindizr_db::Db;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task;

use super::*;
use crate::authorization::Caller;
use crate::types::{CreateSecondaryRequest, CreateZoneRequest};
use crate::{secondary, zone};

/// Build real service state before pausing time; catalog deadlines need no DB reads.
async fn context(batch_ms: u64) -> Arc<Context> {
    let mut config: Config = serde_json::from_str("{}").unwrap();
    config.database.sqlite.file_path = "sqlite::memory:".to_string();
    config.dns.notify.batch_ms = batch_ms;
    config.dns.notify.timeout_secs = 3;
    config.dns.notify.retries = 0;

    let db = Db::connect(&config.database).await.unwrap();

    Arc::new(Context::new(
        config,
        String::new(),
        db,
        Metrics::new().unwrap(),
        mpsc::unbounded_channel().0,
        mpsc::channel(1).0,
        watch::channel(0).0,
    ))
}

/// Verify that a worker collects later writes while the first NOTIFY waits for an ACK.
#[tokio::test]
async fn worker_sends_later_zone_before_silent_secondary_times_out() {
    let cx = context(10).await;
    // Only a served zone is announced; created first, so no secondary hears its creation.
    zone::create(
        &cx,
        &Caller::socket(),
        &CreateZoneRequest {
            name: "second.example".to_string(),
            mname: "ns.example.com".to_string(),
            rname: "hostmaster@example.com".to_string(),
            default_ttl: None,
            serial: None,
            refresh: None,
            retry: None,
            expire: None,
            minimum_ttl: None,
            description: None,
            apex_ns: true,
            dry_run: false,
        },
    )
    .await
    .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    secondary::create(
        &cx,
        &Caller::socket(),
        &CreateSecondaryRequest {
            name: "silent".to_string(),
            address: socket.local_addr().unwrap().to_string(),
            notify_key_name: None,
        },
    )
    .await
    .unwrap();

    let (jobs_tx, jobs) = mpsc::unbounded_channel();
    let worker = spawn(cx.clone(), jobs);
    let catalog_zone_name = cx.config().dns.catalog_zone_name.clone();
    jobs_tx
        .send(NotifyJob::new(NotifyTarget::Zone(&catalog_zone_name)))
        .unwrap();
    let mut buffer = [0; 4096];

    let (len, first_peer) = time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let first_request = buffer[..len].to_vec();
    let zone_name = ZoneName::parse("second.example").unwrap();
    jobs_tx
        .send(NotifyJob::new(NotifyTarget::Zone(&zone_name)))
        .unwrap();

    let (len, second_peer) = time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
        .await
        .expect("ACK wait must not block the next batch")
        .unwrap();
    let second_request = buffer[..len].to_vec();

    for (request, peer) in [(first_request, first_peer), (second_request, second_peer)] {
        let query = ParsedQuery::parse(&request, Keepalive::None).unwrap();

        socket
            .send_to(
                &query
                    .build_signed_error_response(OptRcode::NOERROR, None, None)
                    .unwrap(),
                peer,
            )
            .await
            .unwrap();
    }

    worker.stop().await.unwrap();
}

/// Verify that later writes coalesce without extending the first write's batching window.
#[tokio::test]
async fn batching_keeps_the_first_deadline_and_coalesces_writes() {
    let cx = context(1000).await;

    time::pause();
    let catalog_zone_name = cx.config().dns.catalog_zone_name.clone();
    let first = NotifyJob::new(NotifyTarget::Zone(&catalog_zone_name));
    let (jobs_tx, mut jobs) = mpsc::unbounded_channel();
    let (_stop_tx, mut stop) = watch::channel(false);

    let task = tokio::spawn(async move { collect_batch(&cx, &mut jobs, &mut stop, first).await });
    task::yield_now().await;
    time::advance(Duration::from_millis(600)).await;

    jobs_tx
        .send(NotifyJob::new(NotifyTarget::Zone(&catalog_zone_name)))
        .unwrap();

    task::yield_now().await;
    time::advance(Duration::from_millis(399)).await;

    assert!(
        !task.is_finished(),
        "the first job's 1s batching window must remain open at 999ms"
    );

    time::advance(Duration::from_millis(1)).await;
    let batch = task.await.unwrap();

    assert_eq!(batch.zones, HashSet::from([catalog_zone_name]));
}

/// Verify that backlogged jobs retain their original age and that the catalog uses its
/// served REFRESH.
#[tokio::test]
async fn batching_bounds_catalog_delay_and_does_not_restart_expired_windows() {
    let cx = context(7_200_000).await;

    time::pause();
    let catalog_zone_name = cx.config().dns.catalog_zone_name.clone();
    let first = NotifyJob::new(NotifyTarget::Zone(&catalog_zone_name));

    let deadline = lookup_batch_deadline(&cx, &first).await;

    assert_eq!(
        deadline - first.enqueued_at,
        Duration::from_secs(u64::from(CATALOG_SOA_REFRESH.as_secs())),
        "the catalog's served SOA REFRESH must cap the configured 2h batching window"
    );

    time::advance(Duration::from_secs(3601)).await;

    let started = Instant::now();
    let (_jobs_tx, mut jobs) = mpsc::unbounded_channel();
    let (_stop_tx, mut stop) = watch::channel(false);

    let batch = collect_batch(&cx, &mut jobs, &mut stop, first).await;

    assert_eq!(
        Instant::now(),
        started,
        "an expired batching window must flush without starting a new wait"
    );
    assert_eq!(batch.zones.len(), 1);
}

/// Verify that a shorter delay advances a pending deadline and that shutdown flushes
/// without waiting.
#[tokio::test]
async fn batching_shortens_deadlines_and_flushes_on_shutdown() {
    let cx = context(10000).await;

    time::pause();
    let catalog_zone_name = cx.config().dns.catalog_zone_name.clone();
    let first = NotifyJob::new(NotifyTarget::Zone(&catalog_zone_name));
    let (jobs_tx, mut jobs) = mpsc::unbounded_channel();
    let (stop_tx, mut stop) = watch::channel(false);
    let worker_cx = cx.clone();

    let task =
        tokio::spawn(async move { collect_batch(&worker_cx, &mut jobs, &mut stop, first).await });
    task::yield_now().await;
    time::advance(Duration::from_millis(500)).await;

    let mut config = (*cx.config()).clone();
    config.dns.notify.batch_ms = 100;
    cx.set_config(config);
    jobs_tx
        .send(NotifyJob::new(NotifyTarget::Zone(&catalog_zone_name)))
        .unwrap();

    task::yield_now().await;
    time::advance(Duration::from_millis(100)).await;

    assert_eq!(task.await.unwrap().zones.len(), 1);

    let started = Instant::now();
    let first = NotifyJob::new(NotifyTarget::Zone(&catalog_zone_name));
    let (jobs_tx, mut jobs) = mpsc::unbounded_channel();
    jobs_tx.send(NotifyJob::new(NotifyTarget::All)).unwrap();
    let mut stop = stop_tx.subscribe();
    stop_tx.send(true).unwrap();

    let batch = collect_batch(&cx, &mut jobs, &mut stop, first).await;

    assert!(batch.all_zones);
    assert_eq!(
        Instant::now(),
        started,
        "shutdown must flush queued jobs without waiting for their batching deadline"
    );
}
