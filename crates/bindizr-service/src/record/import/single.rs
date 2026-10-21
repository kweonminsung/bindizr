//! Read one import payload and select zone-file text or an AXFR source.

use bindizr_core::dns::{address::is_address_target, name::ZoneName};

use super::{
    ImportOptions, ImportSource, MissingZoneAction, apply_import, authorize_new_zone_import,
    import_transfer,
};
use crate::{
    Context,
    authorization::Caller,
    dns_client::axfr::AxfrClient,
    error::ServiceError,
    types::{ImportMode, ImportZoneRequest, ImportZoneResponse, Run},
};

/// Import zone-file or AXFR records by mode; any validation failure rejects the whole import.
/// Applying advances the serial once and sends one NOTIFY.
pub async fn import_zone(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    request: &ImportZoneRequest,
) -> Result<ImportZoneResponse, ServiceError> {
    let mode = request
        .mode
        .parse::<ImportMode>()
        .map_err(ServiceError::invalid_input)?;
    let options = ImportOptions {
        mode,
        run: Run::from_dry_run(request.dry_run),
        missing_zone_action: if request.create {
            MissingZoneAction::Create
        } else {
            MissingZoneAction::Reject
        },
    };

    // Checked before any fetch or parse: with `create` there is no zone yet,
    // and only an all-zones grant will reach the one made.
    if request.create {
        authorize_new_zone_import(caller, mode)?;
    }

    let source = match (&request.content, &request.from_server) {
        (Some(content), None) => ImportSource::Text(content),
        (None, Some(server)) => {
            let server = server.trim();

            if !is_address_target(server) {
                return Err(ServiceError::invalid_input(
                    "from_server must name one server as host[:port]",
                ));
            }

            let mut client = AxfrClient::new(server);

            return import_transfer(cx, caller, zone_name, &mut client, server, options).await;
        }
        (Some(_), Some(_)) => {
            return Err(ServiceError::invalid_input(
                "give either content or from_server, not both",
            ));
        }
        (None, None) => {
            return Err(ServiceError::invalid_input("give content or from_server"));
        }
    };

    apply_import(cx, caller, zone_name, source, options).await
}
