//! The transfer log: each transfer, refusal, or failure a client was answered,
//! kept across restarts and instances; reads require `log:read`.

use std::net::IpAddr;

use bindizr_core::config::SavedTransfers;
use bindizr_core::dns::Serial;
use bindizr_core::dns::message::OptRcode;
use bindizr_core::dns::name::ZoneName;
use bindizr_core::dns::tsig::TsigRcode;
use bindizr_core::model::role_grant::Action;
use bindizr_core::model::transfer::{
    TransferKind, TransferLog, TransferLogWithZone, TransferResult, TransferTransport,
};
use bindizr_core::model::zone::ZoneId;
use chrono::Utc;

use crate::authorization::Caller;
use crate::error::{ErrorCode, ServiceError};
use crate::types::{PaginatedResponse, TransferLogFilter, TransferLogResponse};
use crate::{Context, pagination, secondary, text, zone};

/// A transfer log classification carrying codes alone, never input values or diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferLogErrorCode {
    Dns(OptRcode),
    Tsig(TsigRcode),
    Service(ErrorCode),
    IoFailed,
    DnsEncodingFailed,
    TsigResponseEncodingFailed,
    PeerClosed,
    ConnectionSlotsClosed,
    WriteTimeout,
    IncompletePrefix,
    IncompleteMessage,
    IxfrVersionMissing,
    InvalidQuery,
    UpdateResponseEncodingFailed,
    TsigAuthenticationFailed,
}

impl TransferLogErrorCode {
    /// Return the stored code, preserving the DNS and TSIG response-code namespaces.
    pub fn to_text(self) -> String {
        match self {
            Self::Dns(rcode) => rcode.to_string(),
            Self::Tsig(rcode) => rcode.to_string(),
            Self::Service(code) => code.as_str().to_string(),
            Self::IoFailed => "IO_FAILED".to_string(),
            Self::DnsEncodingFailed => "DNS_ENCODING_FAILED".to_string(),
            Self::TsigResponseEncodingFailed => "TSIG_RESPONSE_ENCODING_FAILED".to_string(),
            Self::PeerClosed => "PEER_CLOSED".to_string(),
            Self::ConnectionSlotsClosed => "CONNECTION_SLOTS_CLOSED".to_string(),
            Self::WriteTimeout => "WRITE_TIMEOUT".to_string(),
            Self::IncompletePrefix => "INCOMPLETE_PREFIX".to_string(),
            Self::IncompleteMessage => "INCOMPLETE_MESSAGE".to_string(),
            Self::IxfrVersionMissing => "IXFR_VERSION_MISSING".to_string(),
            Self::InvalidQuery => "INVALID_QUERY".to_string(),
            Self::UpdateResponseEncodingFailed => "UPDATE_RESPONSE_ENCODING_FAILED".to_string(),
            Self::TsigAuthenticationFailed => "TSIG_AUTHENTICATION_FAILED".to_string(),
        }
    }
}

/// Save a transfer answered for `zone_id` up to `serial`. A failure to
/// save is logged; the transfer already went out. An IXFR answered with the
/// SOA alone, its client already current, moved nothing and is not saved.
pub async fn save_ok(
    cx: &Context,
    client_ip: IpAddr,
    zone_id: ZoneId,
    kind: TransferKind,
    transport: TransferTransport,
    incremental: bool,
    serial: Serial,
) {
    // `transfer_log.save = "unserved"` keeps refusals and failures alone.
    if cx.config().transfer_log.save != SavedTransfers::All {
        return;
    }

    let saved = bindizr_db::transfer_log::create(
        cx.db(),
        TransferLog {
            client_addr: client_ip.to_string(),
            zone_id,
            kind,
            result: TransferResult::Ok,
            transport,
            incremental,
            serial: Some(serial),
            served_at: Utc::now(),
            error: None,
        },
    )
    .await;

    if let Err(error) = saved {
        log::warn!("Failed to save a transfer: {error}");
    }
}

/// Save a refusal's fixed error code for the zone `zone_name` names.
pub async fn save_refused(
    cx: &Context,
    client_ip: IpAddr,
    zone_name: &str,
    kind: TransferKind,
    transport: TransferTransport,
    error_code: TransferLogErrorCode,
) {
    save_unserved(
        cx,
        client_ip,
        zone_name,
        kind,
        transport,
        TransferResult::Refused,
        error_code,
    )
    .await;
}

/// Save a transfer of the zone `zone_name` names that was allowed and
/// then broke off, keeping its fixed error code without client diagnostics.
pub async fn save_failed(
    cx: &Context,
    client_ip: IpAddr,
    zone_name: &str,
    kind: TransferKind,
    transport: TransferTransport,
    error_code: TransferLogErrorCode,
) {
    save_unserved(
        cx,
        client_ip,
        zone_name,
        kind,
        transport,
        TransferResult::Failed,
        error_code,
    )
    .await;
}

/// Save a refusal or failure for the zone `zone_name` names; a zone
/// Bindizr does not have leaves no row, and a failure to save is logged.
async fn save_unserved(
    cx: &Context,
    client_ip: IpAddr,
    zone_name: &str,
    kind: TransferKind,
    transport: TransferTransport,
    result: TransferResult,
    error_code: TransferLogErrorCode,
) {
    if cx.config().transfer_log.save == SavedTransfers::None {
        return;
    }

    let Ok(zone_name) = ZoneName::parse(zone_name) else {
        return;
    };

    let zone = match bindizr_db::zone::get_by_name(cx.db(), &zone_name).await {
        Ok(Some(zone)) => zone,
        Ok(None) => return,
        Err(error) => {
            log::warn!("Failed to save a transfer of {zone_name}: {error}");
            return;
        }
    };
    let saved = bindizr_db::transfer_log::create(
        cx.db(),
        TransferLog {
            client_addr: client_ip.to_string(),
            zone_id: zone.id,
            kind,
            result,
            transport,
            incremental: false,
            serial: None,
            served_at: Utc::now(),
            error: Some(error_code.to_text()),
        },
    )
    .await;

    if let Err(error) = saved {
        log::warn!("Failed to save a transfer of {zone_name}: {error}");
    }
}

/// List the transfer log rows `filter` selects, newest first. Count and page
/// are plain statements; drift between the two is accepted.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    filter: &TransferLogFilter,
) -> Result<PaginatedResponse<TransferLogResponse>, ServiceError> {
    caller.authorize_action(Action::LogRead)?;

    let secondary_name = filter.secondary_name.as_deref();
    let mut filter = normalize_filter(filter)?;

    // A secondary selects the addresses it resolves to, which key its rows;
    // with an address too, that address only when the secondary resolves to it.
    if let Some(secondary_name) = secondary_name {
        let secondary = secondary::lookup_by_name(cx, secondary_name).await?;
        let secondary_addrs = secondary::resolve_ips(cx, &secondary)
            .await
            .into_iter()
            .map(|ip| ip.to_string());

        filter.client_addrs = Some(match filter.client_addrs {
            Some(client_addrs) => secondary_addrs
                .filter(|addr| client_addrs.contains(addr))
                .collect(),
            None => secondary_addrs.collect(),
        });
    }

    let total = bindizr_db::transfer_log::count_by_filter(cx.db(), &filter).await?;
    let logs = bindizr_db::transfer_log::list_by_filter_with_zone(cx.db(), &filter).await?;

    Ok(pagination::build_paginated_response(
        logs.iter().map(TransferLogResponse::from).collect(),
        filter.limit,
        filter.offset,
        total,
    ))
}

/// Parse the listing's zone, result, address and order, and bound its page.
fn normalize_filter(
    filter: &TransferLogFilter,
) -> Result<bindizr_db::transfer_log::TransferLogFilter, ServiceError> {
    let zone_name = filter
        .zone_name
        .as_deref()
        .map(zone::normalize_name)
        .transpose()?;
    let result = text::parse_optional::<TransferResult>(filter.result.as_deref())?;
    let address = text::normalize_ip_address(filter.address.as_deref())?;

    pagination::validate_time_window(filter.since, filter.until)?;

    // Newest first is the log's natural order, whatever the field.
    let defaults = bindizr_db::transfer_log::TransferLogFilter::default();
    let sort = pagination::parse_setting(filter.sort.as_deref(), defaults.sort)?;
    let order = pagination::parse_setting(filter.order.as_deref(), defaults.order)?;
    pagination::validate_page_limit(filter.limit)?;

    Ok(bindizr_db::transfer_log::TransferLogFilter {
        client_addrs: address.map(|address| vec![address.to_string()]),
        zone_name,
        result,
        since: filter.since,
        until: filter.until,
        sort,
        order,
        limit: filter.limit,
        offset: filter.offset,
    })
}

/// List the latest transfer of each zone answered to any of `client_ips`,
/// one row per zone, by the order `find_by_clients_and_zone_name` reads.
pub(crate) async fn list_latest_by_clients(
    cx: &Context,
    client_ips: &[IpAddr],
) -> Result<Vec<TransferLogWithZone>, ServiceError> {
    let client_addrs: Vec<String> = client_ips.iter().map(IpAddr::to_string).collect();

    Ok(
        bindizr_db::transfer_log::list_by_client_addrs_with_zone_latest_per_zone(
            cx.db(),
            &client_addrs,
        )
        .await?,
    )
}

/// Find the latest transfer of `zone_name` answered to any of `client_ips`.
pub(crate) async fn find_by_clients_and_zone_name(
    cx: &Context,
    client_ips: &[IpAddr],
    zone_name: &ZoneName,
) -> Result<Option<TransferLogWithZone>, ServiceError> {
    let filter = bindizr_db::transfer_log::TransferLogFilter {
        client_addrs: Some(client_ips.iter().map(IpAddr::to_string).collect()),
        zone_name: Some(zone_name.clone()),
        limit: Some(1),
        ..Default::default()
    };

    Ok(
        bindizr_db::transfer_log::list_by_filter_with_zone(cx.db(), &filter)
            .await?
            .into_iter()
            .next(),
    )
}

#[cfg(test)]
mod tests;
