use bindizr_core::{config::Config, metrics::Metrics};
use bindizr_db::Db;
use tokio::{
    sync::mpsc,
    time::{advance, pause},
};

use super::*;

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
        watch::channel(0).0,
    ))
}

/// A worker must collect later writes while the first NOTIFY waits for an ACK.
#[tokio::test]
async fn worker_sends_later_zone_before_silent_secondary_times_out() {
    use crate::{authorization::Caller, secondary, types::CreateSecondaryRequest};

    let cx = context(10).await;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    secondary::create(
        &cx,
        &Caller::socket(),
        &CreateSecondaryRequest {
            name: "silent".into(),
            address: socket.local_addr().unwrap().to_string(),
            notify_key_name: None,
        },
    )
    .await
    .unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let worker = spawn(cx.clone(), rx);
    let first = cx.config().dns.catalog_zone_name.clone();
    tx.send(NotifyJob::new(NotifyTarget::Zone(&first))).unwrap();
    let mut buf = [0; 4096];
    let (len, first_peer) =
        tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
    let first_request = buf[..len].to_vec();
    let second = ZoneName::parse("second.example").unwrap();
    tx.send(NotifyJob::new(NotifyTarget::Zone(&second)))
        .unwrap();
    let (len, second_peer) =
        tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buf))
            .await
            .expect("ACK wait must not block the next batch")
            .unwrap();
    let second_request = buf[..len].to_vec();
    for (request, peer) in [(first_request, first_peer), (second_request, second_peer)] {
        let query = bindizr_core::dns::message::ParsedQuery::parse(
            &request,
            bindizr_core::dns::message::Keepalive::None,
        )
        .unwrap();
        socket
            .send_to(
                &query
                    .build_signed_error_response(
                        bindizr_core::dns::message::Rcode::NOERROR.into(),
                        None,
                        None,
                    )
                    .unwrap(),
                peer,
            )
            .await
            .unwrap();
    }
    worker.stop().await.unwrap();
}

/// Later writes coalesce without extending the first write's batching window.
#[tokio::test]
async fn batching_keeps_the_first_deadline_and_coalesces_writes() {
    let cx = context(1000).await;
    pause();
    let name = cx.config().dns.catalog_zone_name.clone();
    let first = NotifyJob::new(NotifyTarget::Zone(&name));
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (_stop_tx, mut stop) = watch::channel(false);
    let task = tokio::spawn(async move { collect_batch(&cx, &mut rx, &mut stop, first).await });
    tokio::task::yield_now().await;
    advance(Duration::from_millis(600)).await;
    tx.send(NotifyJob::new(NotifyTarget::Zone(&name))).unwrap();
    tokio::task::yield_now().await;
    advance(Duration::from_millis(399)).await;
    assert!(!task.is_finished());
    advance(Duration::from_millis(1)).await;
    let batch = task.await.unwrap();
    assert_eq!(batch.zones, HashSet::from([name]));
}

/// Backlogged jobs retain their original age, and the catalog uses its served REFRESH.
#[tokio::test]
async fn batching_bounds_catalog_delay_and_does_not_restart_expired_windows() {
    let cx = context(7_200_000).await;
    pause();
    let name = cx.config().dns.catalog_zone_name.clone();
    let first = NotifyJob::new(NotifyTarget::Zone(&name));
    let deadline = read_batch_deadline(&cx, &first).await;
    assert_eq!(
        deadline - first.enqueued_at,
        Duration::from_secs(u64::from(CATALOG_SOA_REFRESH.as_secs()))
    );
    advance(Duration::from_secs(3601)).await;
    let started = Instant::now();
    let (_tx, mut rx) = mpsc::unbounded_channel();
    let (_stop_tx, mut stop) = watch::channel(false);
    let batch = collect_batch(&cx, &mut rx, &mut stop, first).await;
    assert_eq!(Instant::now(), started);
    assert_eq!(batch.zones.len(), 1);
}

/// A shorter delay advances a pending deadline; shutdown flushes without waiting.
#[tokio::test]
async fn batching_shortens_deadlines_and_flushes_on_shutdown() {
    let cx = context(10_000).await;
    pause();
    let name = cx.config().dns.catalog_zone_name.clone();
    let first = NotifyJob::new(NotifyTarget::Zone(&name));
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (stop_tx, mut stop) = watch::channel(false);
    let worker_cx = cx.clone();
    let task =
        tokio::spawn(async move { collect_batch(&worker_cx, &mut rx, &mut stop, first).await });
    tokio::task::yield_now().await;
    advance(Duration::from_millis(500)).await;
    let mut config = (*cx.config()).clone();
    config.dns.notify.batch_ms = 100;
    cx.set_config(config);
    tx.send(NotifyJob::new(NotifyTarget::Zone(&name))).unwrap();
    tokio::task::yield_now().await;
    advance(Duration::from_millis(100)).await;
    assert_eq!(task.await.unwrap().zones.len(), 1);

    let started = Instant::now();
    let first = NotifyJob::new(NotifyTarget::Zone(&name));
    let (tx, mut rx) = mpsc::unbounded_channel();
    tx.send(NotifyJob::new(NotifyTarget::All)).unwrap();
    let mut stop = stop_tx.subscribe();
    stop_tx.send(true).unwrap();
    let batch = collect_batch(&cx, &mut rx, &mut stop, first).await;
    assert!(batch.all_zones);
    assert_eq!(Instant::now(), started);
}
