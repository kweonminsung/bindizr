use std::time::Duration;

use bindizr_core::config::Config;
use bindizr_core::metrics::Metrics;
use bindizr_db::Db;
use tokio::sync::mpsc;

use super::*;

/// Build real service state and its reload channel over a disposable SQLite database.
async fn context(period: u64) -> (Arc<Context>, watch::Receiver<u64>) {
    let mut config: Config = serde_json::from_str("{}").unwrap();
    config.database.sqlite.file_path = "sqlite::memory:".into();
    config.dns.scheduler_interval_secs = period;

    let db = Db::connect(&config.database).await.unwrap();

    let (period_tx, period_rx) = watch::channel(period);
    let cx = Arc::new(Context::new(
        config,
        String::new(),
        db,
        Metrics::new().unwrap(),
        mpsc::unbounded_channel().0,
        period_tx,
    ));

    (cx, period_rx)
}

/// A disabled scheduler stops even while the context keeps its reload sender alive.
#[tokio::test]
async fn stop_joins_disabled_worker_without_starting_a_pass() {
    let (cx, period_rx) = context(0).await;
    let worker = spawn(cx.clone(), period_rx);

    tokio::time::timeout(Duration::from_secs(2), worker.stop())
        .await
        .unwrap()
        .unwrap();

    assert!(
        cx.metrics()
            .encode()
            .contains("bindizr_dnssec_scheduler_runs_total{result=\"ok\"} 0")
    );
}

/// Shutdown waits for the current database pass and skips ticks accumulated during that pass.
#[tokio::test]
async fn stop_finishes_the_in_flight_pass_and_prevents_another() {
    let (cx, period_rx) = context(1).await;

    // Occupy every connection so the pass cannot finish its first query until released.
    let mut held = Vec::new();

    for _ in 0..cx.db().stats().max {
        held.push(cx.db().begin_read().await.unwrap());
    }

    let worker = spawn(cx.clone(), period_rx);

    tokio::time::timeout(Duration::from_secs(2), async {
        // The scheduler's additional Arc belongs to the spawned in-flight pass.
        while Arc::strong_count(&cx) < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let task = worker.stop();

    tokio::time::sleep(Duration::from_millis(1100)).await;

    assert!(!task.is_finished(), "shutdown must await the blocked pass");
    assert!(
        cx.metrics()
            .encode()
            .contains("bindizr_dnssec_scheduler_runs_total{result=\"ok\"} 0")
    );

    for tx in held {
        tx.rollback().await.unwrap();
    }

    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();

    assert!(
        cx.metrics()
            .encode()
            .contains("bindizr_dnssec_scheduler_runs_total{result=\"ok\"} 1")
    );
    assert!(
        cx.metrics()
            .encode()
            .contains("bindizr_dnssec_scheduler_runs_total{result=\"failed\"} 0")
    );
}
