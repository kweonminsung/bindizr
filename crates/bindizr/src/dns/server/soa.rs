//! Serves SOA queries over TCP, TLS, and UDP, used by secondaries to poll the
//! primary's serial, and a UDP IXFR, which the SOA alone answers.

use std::net::{IpAddr, SocketAddr};

use bindizr_core::dns::message::{DnsMessageBuilder, OptRcode, ParsedQuery, QueryMetadata, Rtype};
use bindizr_core::dns::tsig::{RequestSignature, TransferSigner};
use bindizr_core::dns::{Serial, query, tsig};
use bindizr_core::metrics::{SoaResult, XfrResult};
use bindizr_core::model::transfer::{TransferKind, TransferTransport};
use bindizr_service::authorization::Caller;
use bindizr_service::types::ZoneView;
use bindizr_service::zone;
use bindizr_service::zone::TransferAccess;

use crate::dns::error::DnsError;
use crate::dns::server::auth::{QueryIdentity, QueryRefusal};
use crate::dns::server::{DnsContext, auth};
use crate::dns::stream::ResponseWriter;
use crate::dns::udp::{ReplyTarget, UdpSocket};

/// What the packet builder actually answered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SoaOutcome {
    Answered(Serial),
    Truncated,
    Refused,
    NotAuth,
    Failed,
}

impl SoaOutcome {
    /// Report whether the poll received the zone's serial.
    fn to_soa_result(self) -> SoaResult {
        match self {
            Self::Answered(_) => SoaResult::Ok,
            Self::Truncated => SoaResult::Truncated,
            Self::Refused => SoaResult::Refused,
            Self::NotAuth => SoaResult::NotAuth,
            Self::Failed => SoaResult::Failed,
        }
    }

    /// A current or newer client only needs the SOA (RFC 1995, Section 2).
    fn to_ixfr_result(self, client_serial: Option<Serial>) -> XfrResult {
        match self {
            Self::Answered(serial)
                if client_serial
                    .is_some_and(|client| client == serial || client.is_newer_than(serial)) =>
            {
                XfrResult::Ok
            }
            Self::Answered(_) | Self::Truncated => XfrResult::Truncated,
            Self::Refused => XfrResult::Refused,
            Self::NotAuth => XfrResult::NotAuth,
            Self::Failed => XfrResult::Failed,
        }
    }
}

/// Answer an SOA query over TCP or TLS. Count the outcome after sending.
pub(crate) async fn handle_stream_soa(
    dns_cx: &DnsContext,
    writer: &ResponseWriter,
    client_addr: SocketAddr,
    query: &ParsedQuery,
    query_data: &[u8],
) -> Result<(), DnsError> {
    let cx = dns_cx.daemon();

    let (response, outcome) = handle_soa_request(
        dns_cx,
        client_addr.ip(),
        query,
        query_data,
        writer.transport(),
    )
    .await
    .inspect_err(|_| cx.metrics().track_soa(SoaResult::Failed))?;
    writer
        .write_message(&response)
        .await
        .inspect_err(|_| cx.metrics().track_soa(SoaResult::Failed))?;

    cx.metrics().track_soa(outcome.to_soa_result());

    Ok(())
}

/// Answer an SOA query over UDP. Count the outcome after sending.
pub(crate) async fn handle_udp_soa(
    dns_cx: &DnsContext,
    socket: &UdpSocket,
    target: ReplyTarget,
    query: &ParsedQuery,
    query_data: &[u8],
) -> Result<(), DnsError> {
    let cx = dns_cx.daemon();

    let (response, outcome) = handle_soa_request(
        dns_cx,
        target.client_addr.ip(),
        query,
        query_data,
        TransferTransport::Udp,
    )
    .await
    .inspect_err(|_| cx.metrics().track_soa(SoaResult::Failed))?;
    socket
        .send_to(&response, target, query.response_limit())
        .await
        .inspect_err(|_| cx.metrics().track_soa(SoaResult::Failed))?;

    cx.metrics().track_soa(outcome.to_soa_result());

    Ok(())
}

/// Answer a UDP IXFR with the zone's SOA. Count TCP retries separately from
/// complete answers for current clients. Like UDP AXFR, omit transfer-log rows.
pub(crate) async fn handle_udp_ixfr(
    dns_cx: &DnsContext,
    socket: &UdpSocket,
    target: ReplyTarget,
    query: &ParsedQuery,
    query_data: &[u8],
) -> Result<(), DnsError> {
    let cx = dns_cx.daemon();

    let (response, outcome) = handle_soa_request(
        dns_cx,
        target.client_addr.ip(),
        query,
        query_data,
        TransferTransport::Udp,
    )
    .await
    .inspect_err(|_| {
        cx.metrics().track_xfr(
            TransferKind::Ixfr,
            TransferTransport::Udp,
            XfrResult::Failed,
        );
    })?;
    socket
        .send_to(&response, target, query.response_limit())
        .await
        .inspect_err(|_| {
            cx.metrics().track_xfr(
                TransferKind::Ixfr,
                TransferTransport::Udp,
                XfrResult::Failed,
            );
        })?;

    cx.metrics().track_xfr(
        TransferKind::Ixfr,
        TransferTransport::Udp,
        outcome.to_ixfr_result(query.client_serial),
    );

    Ok(())
}

/// Return whether the client is `bindizr doctor` probing over the wire,
/// reaching a concrete `listen_addr` from it.
fn is_self_probe(dns_cx: &DnsContext, client_ip: IpAddr) -> bool {
    client_ip.is_loopback() || client_ip == dns_cx.daemon().config().dns.listen_addr.to_canonical()
}

/// Build an SOA response under the transfer gate for polling secondaries.
/// The query carries the response budget, including its transport.
async fn handle_soa_request(
    dns_cx: &DnsContext,
    client_ip: IpAddr,
    query: &ParsedQuery,
    query_data: &[u8],
    transport: TransferTransport,
) -> Result<(Vec<u8>, SoaOutcome), DnsError> {
    let cx = dns_cx.daemon();
    let zone_name_str = query.zone_name.as_str();

    // A UDP IXFR is a transfer; a SOA query is not.
    let identity = if query.qtype == Rtype::IXFR {
        auth::admit_transfer(dns_cx, client_ip, query_data, transport).await
    } else {
        authenticate_soa(dns_cx, client_ip, query_data, transport).await
    };
    let mut identity = match identity {
        Ok(identity) => identity,
        Err(refusal) => {
            let outcome = if refusal.is_failure() {
                SoaOutcome::Failed
            } else {
                SoaOutcome::Refused
            };
            log::warn!(
                "Refused {} query for {zone_name_str:?} from {client_ip}: {refusal}",
                query.qtype
            );

            return match refusal.into_response(&QueryMetadata::from(query), query_data) {
                Ok(response) => Ok((response, outcome)),
                Err(DnsError::TsigResponse(error)) => {
                    log::warn!("Failed to encode {} TSIG refusal: {error}", query.qtype);
                    Ok((
                        query.build_signed_error_response(OptRcode::SERVFAIL, None, None)?,
                        SoaOutcome::Failed,
                    ))
                }
                Err(error) => Err(error),
            };
        }
    };

    log::info!(
        "{} query for zone {zone_name_str:?} from {client_ip}",
        query.qtype
    );

    // The question is echoed as asked: SOA, or a UDP IXFR answered by it.
    let build = |signer: Option<TransferSigner>| {
        let mut builder = DnsMessageBuilder::new(query);

        if let Some(signer) = signer {
            builder = builder.sign_with(signer);
        }

        builder
    };

    if cx.config().dns.is_catalog_zone(zone_name_str) {
        log::info!(
            "{} query for catalog zone: {}",
            query.qtype,
            cx.config().dns.catalog_zone_name
        );

        let access = match zone::refresh_catalog_content(cx, &identity.caller).await {
            Ok(access) => access,
            Err(error) => {
                log::error!(
                    "Failed to load catalog content for {} query for {zone_name_str:?} from {client_ip}: {error:?}",
                    query.qtype
                );
                return Ok((
                    query.build_signed_error_response(
                        OptRcode::SERVFAIL,
                        None,
                        identity.signer.as_mut(),
                    )?,
                    SoaOutcome::Failed,
                ));
            }
        };
        let (catalog_zone, _) = match access {
            Ok(content) => content,
            Err(refusal) => {
                log::warn!(
                    "Refused {} query for {zone_name_str:?} from {client_ip}: {refusal}",
                    query.qtype
                );
                return QueryRefusal::refused(refusal.to_string(), identity.signer)
                    .into_response(&QueryMetadata::from(query), query_data)
                    .map(|response| (response, SoaOutcome::Refused));
            }
        };
        let mut builder = build(identity.signer);
        builder.add_catalog_soa(&catalog_zone)?;

        return build_soa_answer(builder, catalog_zone.serial);
    }

    // A name the zone type refuses is answered NOTAUTH like a missing zone.
    let view = ZoneView::from_signed(query.qtype == Rtype::SOA && query.edns.dnssec_ok());

    let access = match zone::normalize_name(zone_name_str) {
        Ok(zone_name) => {
            match zone::authorize_soa_content_by_name(cx, &identity.caller, &zone_name, view).await
            {
                Ok(access) => access,
                Err(error) => {
                    log::error!(
                        "Failed to load SOA content for {} query for {zone_name_str:?} from {client_ip}: {error:?}",
                        query.qtype
                    );
                    return Ok((
                        query.build_signed_error_response(
                            OptRcode::SERVFAIL,
                            None,
                            identity.signer.as_mut(),
                        )?,
                        SoaOutcome::Failed,
                    ));
                }
            }
        }
        Err(_) => TransferAccess::NotAuth,
    };
    let (zone, signatures) = match access {
        TransferAccess::Granted(content) => content,
        TransferAccess::NotAuth => {
            return QueryRefusal::not_auth(
                format!("not authoritative for zone: {zone_name_str}"),
                identity.signer,
            )
            .into_response(&QueryMetadata::from(query), query_data)
            .map(|response| (response, SoaOutcome::NotAuth));
        }
        TransferAccess::Refused(refusal) => {
            log::warn!(
                "Refused {} query for {zone_name_str:?} from {client_ip}: {refusal}",
                query.qtype
            );
            return QueryRefusal::refused(refusal.to_string(), identity.signer)
                .into_response(&QueryMetadata::from(query), query_data)
                .map(|response| (response, SoaOutcome::Refused));
        }
    };

    log::info!("SOA response: zone {zone_name_str} serial={}", zone.serial);

    let mut builder = build(identity.signer);
    builder.add_soa(&zone, zone.serial)?;

    for signature in &signatures {
        builder.add_dnssec_record(signature, &zone.name)?;
    }

    build_soa_answer(builder, zone.serial)
}

/// Encode the answer and classify the packet after applying its UDP limit.
fn build_soa_answer(
    builder: DnsMessageBuilder,
    serial: Serial,
) -> Result<(Vec<u8>, SoaOutcome), DnsError> {
    let response = builder.build()?;
    let outcome = if query::is_truncated(&response) {
        SoaOutcome::Truncated
    } else {
        SoaOutcome::Answered(serial)
    };

    Ok((response, outcome))
}

/// Authenticate an SOA query. `bindizr doctor`'s own probe carries no key and
/// is not a secondary, so it passes ahead of both gates.
async fn authenticate_soa(
    dns_cx: &DnsContext,
    client_ip: IpAddr,
    query_data: &[u8],
    transport: TransferTransport,
) -> Result<QueryIdentity, QueryRefusal> {
    // Only an unsigned probe skips the gate: a request that reached for a key
    // is held to it wherever it came from, or a wrong secret would pass.
    if is_self_probe(dns_cx, client_ip)
        && tsig::request_signature(query_data) == RequestSignature::Absent
    {
        return Ok(QueryIdentity {
            caller: Caller::unsigned_dns(),
            signer: None,
        });
    }

    auth::authenticate_query(dns_cx, client_ip, query_data, transport).await
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bindizr_core::dns::Ttl;
    use bindizr_core::dns::message::{Keepalive, Opcode};
    use bindizr_core::dns::name::WireName;
    use bindizr_core::dns::record::SoaRecordValue;

    use super::*;

    /// Verify that only an SOA that fits its UDP response budget delivers a serial.
    #[test]
    fn soa_metric_uses_the_encoded_answer() {
        let serial = Serial::from(42);
        let name = WireName::from_str("example.com.").unwrap();
        let (_, question) =
            query::build_question(Opcode::QUERY, false, false, &name, Rtype::SOA, None);
        let query = ParsedQuery::parse(&question.finish(), Keepalive::None).unwrap();
        let label = "a".repeat(60);
        let long_name = format!("{label}.{label}.{label}.{label}.");

        for (target, expected) in [
            ("ns.example.com.", SoaResult::Ok),
            (long_name.as_str(), SoaResult::Truncated),
        ] {
            let soa = SoaRecordValue {
                mname: target,
                rname: target,
                serial,
                refresh: 3600,
                retry: 600,
                expire: 86400,
                minimum: Ttl::from_secs(60),
            };
            let mut builder = DnsMessageBuilder::new(&query);
            builder
                .add_raw_rdata(
                    name.clone(),
                    Rtype::SOA,
                    Ttl::from_secs(60),
                    soa.to_rdata().unwrap(),
                )
                .unwrap();
            let (response, outcome) = build_soa_answer(builder, serial).unwrap();

            assert_eq!(outcome.to_soa_result(), expected);
            assert_eq!(
                query::extract_soa_serial(query.query_id, &name, &response).ok(),
                (expected == SoaResult::Ok).then_some(serial)
            );
        }
    }

    /// Verify that a complete SOA for an equal or newer UDP IXFR client ends the transfer.
    #[test]
    fn udp_ixfr_metric_counts_only_incomplete_answers_as_truncated() {
        let current = Serial::from(42);
        let outcome = SoaOutcome::Answered(current);
        for (client_serial, expected) in [
            (Some(current), XfrResult::Ok),
            (Some(Serial::from(43)), XfrResult::Ok),
            (Some(Serial::from(41)), XfrResult::Truncated),
            (Some(Serial::from(42 + 0x8000_0000)), XfrResult::Truncated),
            (None, XfrResult::Truncated),
        ] {
            assert_eq!(outcome.to_ixfr_result(client_serial), expected);
        }
        assert_eq!(
            SoaOutcome::Truncated.to_ixfr_result(Some(current)),
            XfrResult::Truncated
        );
    }
}
