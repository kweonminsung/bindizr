//! What the request's caller may do, for a client deciding what to offer.

use bindizr_core::model::role_grant::Action;
use bindizr_db::zone::ZoneFilter;

use crate::{
    Context,
    authorization::Caller,
    error::ServiceError,
    types::{PermissionsResponse, PermittedActionsResponse, ZonePermissionsResponse},
};

/// The caller's actions across all zones and where zone grants add to them;
/// reading its own rights needs no grant.
pub async fn get(cx: &Context, caller: &Caller) -> Result<PermissionsResponse, ServiceError> {
    let Some(grants) = caller.grants() else {
        // Nothing bounds the caller, so all zones are covered whole.
        return Ok(PermissionsResponse {
            all_zones: PermittedActionsResponse {
                actions: Action::ALL.to_vec(),
                whole_zone: record_actions().collect(),
            },
            zones: Vec::new(),
        });
    };

    let all_zones = PermittedActionsResponse {
        actions: Action::ALL
            .into_iter()
            .filter(|&action| grants.permits_all_zones(action))
            .collect(),
        whole_zone: record_actions()
            .filter(|&action| grants.covers_all_whole_zones(action))
            .collect(),
    };
    let zones = bindizr_db::zone::list_by_filter(
        cx.db(),
        ZoneFilter {
            scope_role_id: caller.scope_role_id(),
            ..ZoneFilter::default()
        },
    )
    .await?;

    // Zones answering as `all_zones` are left out.
    let zones = zones
        .into_iter()
        .filter_map(|zone| {
            let actions: Vec<Action> = Action::ALL
                .into_iter()
                .filter(|&action| grants.permits(action, zone.id))
                .collect();
            let whole_zone: Vec<Action> = record_actions()
                .filter(|&action| grants.covers_whole_zone(action, zone.id))
                .collect();
            (actions != all_zones.actions || whole_zone != all_zones.whole_zone).then(|| {
                ZonePermissionsResponse {
                    zone_name: zone.name.to_string(),
                    actions,
                    whole_zone,
                }
            })
        })
        .collect();
    Ok(PermissionsResponse { all_zones, zones })
}

/// The actions a name or type limit can narrow.
fn record_actions() -> impl Iterator<Item = Action> {
    Action::ALL
        .into_iter()
        .filter(|action| action.is_record_action())
}
