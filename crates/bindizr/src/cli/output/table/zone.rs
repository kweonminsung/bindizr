use bindizr_core::dns::{Serial, SoaInterval};
use bindizr_core::model::zone::ZoneId;
use bindizr_service::types::ZoneResponse;
use tabled::Tabled;

use crate::cli::output::display;

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct ZoneRow {
    #[tabled(rename = "ID", display = "display::display_option")]
    pub(crate) id: Option<ZoneId>,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "MNAME")]
    pub(crate) mname: String,
    #[tabled(rename = "RNAME")]
    pub(crate) rname: String,
    #[tabled(rename = "DEFAULT-TTL")]
    pub(crate) default_ttl: i64,
    #[tabled(rename = "SERIAL")]
    pub(crate) serial: Serial,
    #[tabled(rename = "REFRESH")]
    pub(crate) refresh: SoaInterval,
    #[tabled(rename = "RETRY")]
    pub(crate) retry: SoaInterval,
    #[tabled(rename = "EXPIRE")]
    pub(crate) expire: SoaInterval,
    #[tabled(rename = "MINIMUM-TTL")]
    pub(crate) minimum_ttl: i64,
    #[tabled(rename = "SERVED", display = "display::display_yes_no")]
    pub(crate) served: bool,
    #[tabled(rename = "DESCRIPTION")]
    pub(crate) description: String,
}

impl From<&ZoneResponse> for ZoneRow {
    /// Build a CLI table row from the zone response.
    fn from(zone: &ZoneResponse) -> Self {
        Self {
            id: zone.id,
            name: zone.name.clone(),
            mname: zone.mname.clone(),
            rname: zone.rname.clone(),
            default_ttl: i64::from(zone.default_ttl),
            serial: zone.serial,
            refresh: zone.refresh,
            retry: zone.retry,
            expire: zone.expire,
            minimum_ttl: i64::from(zone.minimum_ttl),
            served: zone.enabled,
            description: display::display_option(&zone.description),
        }
    }
}
