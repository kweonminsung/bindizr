//! Retire zone history atomically under the zone lock.

use bindizr_core::model::zone::ZoneId;
use bindizr_db::LockLevel;
use chrono::{DateTime, Utc};

use crate::{Context, error::ServiceError, transaction};

/// Rows one prune removed from a zone's history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PruneSummary {
    pub(crate) journal_rows: u64,
    pub(crate) version_rows: u64,
}

/// Prune a zone's journal and versions before `cutoff` in one transaction under the zone lock.
/// The zone lock preserves serial consistency; pruning both tables avoids IXFR gaps.
pub(crate) async fn prune_by_zone_id(
    cx: &Context,
    zone_id: ZoneId,
    cutoff: DateTime<Utc>,
) -> Result<PruneSummary, ServiceError> {
    let mut tx = transaction::begin_tx(cx, "failed to prune zone history").await?;
    let result: Result<_, ServiceError> = async {
        if bindizr_db::zone::get_tx(&mut tx, zone_id, LockLevel::Exclusive)
            .await?
            .is_none()
        {
            return Ok(PruneSummary {
                journal_rows: 0,
                version_rows: 0,
            });
        }

        let journal_rows =
            bindizr_db::zone_change::prune_by_zone_id_older_than_tx(&mut tx, zone_id, cutoff)
                .await?;
        let version_rows =
            bindizr_db::zone_version::prune_by_zone_id_older_than_tx(&mut tx, zone_id, cutoff)
                .await?;

        Ok::<_, ServiceError>(PruneSummary {
            journal_rows,
            version_rows,
        })
    }
    .await;

    transaction::finish_tx(tx, result, "failed to prune zone history").await
}
