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
