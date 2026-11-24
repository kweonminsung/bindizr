use bindizr_core::dns::Serial;
use bindizr_core::model::secondary::SecondaryId;
use bindizr_service::types::{SecondaryResponse, SecondaryStatusResponse, ZoneStatusResponse};
use tabled::Tabled;

use crate::cli::output::display;

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct SecondaryRow {
    #[tabled(rename = "ID")]
    pub(crate) id: SecondaryId,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "ADDRESS")]
    pub(crate) address: String,
    #[tabled(rename = "ENABLED", display = "display::display_yes_no")]
    pub(crate) enabled: bool,
    #[tabled(rename = "NOTIFY-KEY")]
    pub(crate) notify_key_name: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&SecondaryResponse> for SecondaryRow {
    /// Build a CLI table row from the secondary response.
    fn from(secondary: &SecondaryResponse) -> Self {
        Self {
            id: secondary.id,
            name: secondary.name.clone(),
            address: secondary.address.clone(),
            enabled: secondary.enabled,
            notify_key_name: display::display_option(&secondary.notify_key_name),
            created_at: display::display_time(secondary.created_at),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct SecondaryStatusRow {
    #[tabled(rename = "ADDRESS")]
    pub(crate) address: String,
    #[tabled(rename = "STATUS")]
    pub(crate) status: String,
    #[tabled(rename = "VISIBLE-SERIAL")]
    pub(crate) visible_serial: String,
    #[tabled(rename = "LAG")]
    pub(crate) lag: String,
    #[tabled(rename = "LAST-TRANSFER")]
    pub(crate) last_transfer: String,
}

impl SecondaryStatusRow {
    /// Build one row per secondary, with the lag behind the zone serial that its
    /// `status` was classified against.
    pub(crate) fn rows_from_status(status: &ZoneStatusResponse) -> Vec<Self> {
        status
            .secondaries
            .iter()
            .map(|secondary| Self::from_secondary(secondary, status.serial))
            .collect()
    }

    /// Build a CLI table row from a secondary server's status.
    fn from_secondary(secondary: &SecondaryStatusResponse, zone_serial: Serial) -> Self {
        let detail = match secondary.error.as_deref() {
            Some(error) if secondary.is_unreachable() => {
                format!("{} ({error})", secondary.status)
            }
            _ => secondary.status.to_string(),
        };
        Self {
            address: secondary.address.clone(),
            status: detail,
            visible_serial: display::display_option(&secondary.visible_serial),
            lag: display::display_serial_lag(
                zone_serial,
                secondary.visible_serial,
                secondary.status,
            ),
            last_transfer: secondary.last_transfer.as_ref().map_or_else(
                || display::MISSING_CELL.to_string(),
                display::display_transfer,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use bindizr_service::types::SecondaryStatus::{Ahead, InSync, Lagging, Reachable, Unreachable};

    use super::*;

    /// Verify that serial lag is displayed using wraparound-aware secondary status.
    #[test]
    fn secondary_status_row_displays_serial_lag_across_wraparound() {
        for (zone_serial, visible_serial, status, lag) in [
            (10, Some(10), InSync, "0"),
            (11, Some(10), Lagging, "1"),
            (10, Some(11), Ahead, "-1"),
            (0, Some(u32::MAX), Lagging, "1"),
            (u32::MAX, Some(0), Ahead, "-1"),
            (0x7fff_ffff, Some(0), Lagging, "2147483647"),
            (0, Some(0x7fff_ffff), Ahead, "-2147483647"),
            (0, Some(0x8000_0000), Reachable, "-"),
            (0x8000_0000, Some(0), Reachable, "-"),
            (0, None, Unreachable, "-"),
        ] {
            let secondary = SecondaryStatusResponse {
                address: "127.0.0.1:53".to_string(),
                status,
                visible_serial: visible_serial.map(Serial::from),
                error: None,
                last_transfer: None,
            };
            let row = SecondaryStatusRow::from_secondary(&secondary, Serial::from(zone_serial));

            assert_eq!(
                row.lag, lag,
                "{zone_serial} vs {visible_serial:?}: {status}"
            );
        }
    }
}
