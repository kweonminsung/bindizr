//! Framed queries on an established TCP or TLS connection.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bindizr_core::dns::message::{
    self, Class, ExtendedErrorCode, Keepalive, Opcode, OptRcode, Rtype,
};
use tokio::{task::JoinSet, time::timeout};

use super::{
    error::DnsError,
    server::{self, DnsContext},
    stream::{DnsStream, ResponseWriter},
    wire,
};

/// Bound concurrent queries on one connection.
const MAX_QUERIES_IN_FLIGHT: usize = 16;

/// Read DNS queries on one connection until the client is done or idle,
/// serving them concurrently (RFC 7766, Section 6.2.1.1; RFC 9103, Section 6).
pub(crate) async fn serve_connection(
    dns_cx: Arc<DnsContext>,
    stream: DnsStream,
    client_addr: SocketAddr,
) -> Result<(), DnsError> {
    let transport = stream.transport();
    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(writer);
    let idle_timeout = dns_cx.daemon().config().dns.tcp_idle_timeout();
    let mut pending = Vec::new();
    let mut in_flight = JoinSet::new();

    let outcome = loop {
        // A connection with a query in flight is not idle (RFC 7766, Section
        // 6.2.3); the cancel-safe read may be interrupted by a query finishing.
        let busy = !in_flight.is_empty();
        let read = async {
            let read = wire::read_tcp_message(&mut reader, &mut pending);
            if busy {
                read.await
            } else {
                match timeout(idle_timeout, read).await {
                    Ok(result) => result,
                    Err(_) => {
                        log::info!(
                            "Closing idle DNS {} connection from {} after {:?}",
                            transport,
                            client_addr,
                            idle_timeout
                        );
                        Err(DnsError::PeerClosed)
                    }
                }
            }
        };
        let result = tokio::select! {
            biased;
            () = writer.failed() => break Err(DnsError::PeerClosed),
            Some(_) = in_flight.join_next(), if busy => continue,
            result = read => result,
        };
        let query_data = match result {
            Ok(query_data) => query_data,
            Err(DnsError::PeerClosed) => break Ok(()),
            Err(error) => {
                writer.fail();
                break Err(error);
            }
        };

        if in_flight.len() >= MAX_QUERIES_IN_FLIGHT {
            tokio::select! {
                biased;
                () = writer.failed() => break Err(DnsError::PeerClosed),
                _ = in_flight.join_next() => {},
            }
        }
        let dns_cx = dns_cx.clone();
        let writer = writer.clone();
        in_flight.spawn(async move {
            dispatch_query(&dns_cx, &writer, client_addr, &query_data, idle_timeout).await;
        });
    };

    // Clean FIN keeps replies open (RFC 9293, Section 3.6.1); failures cancel transfers.
    // Finish UPDATE and NOTIFY without replies after failure (RFC 7766, Section 6.2.4).
    while in_flight.join_next().await.is_some() {}

    // A TLS peer is owed close_notify ahead of the FIN; a plain socket closes.
    if outcome.is_ok()
        && let Err(e) = writer.shutdown().await
    {
        log::debug!(
            "Closing DNS {} connection from {}: {}",
            transport,
            client_addr,
            e
        );
    }
    outcome
}

/// Route a framed DNS query to its transfer, update, or SOA handler.
async fn dispatch_query(
    dns_cx: &DnsContext,
    writer: &ResponseWriter,
    client_addr: SocketAddr,
    query_data: &[u8],
    idle_timeout: Duration,
) {
    let transport = writer.transport();
    if message::is_response(query_data) {
        log::warn!("Ignoring a DNS {} response from {}", transport, client_addr);
        return;
    }

    // nsupdate parses its own message and TSIG; other queries share this parse.
    if server::nsupdate::is_nsupdate(query_data) {
        if let Err(error) =
            server::nsupdate::handle_tcp_nsupdate(dns_cx, writer, query_data, client_addr).await
        {
            log::error!(
                "NSUPDATE {} handler failed for {}: {}",
                transport,
                client_addr,
                error
            );
        }
        return;
    }

    let query = match message::ParsedQuery::parse(query_data, Keepalive::IdleTimeout(idle_timeout))
    {
        Ok(query) => query,
        Err(e) => {
            log::warn!(
                "Failed to parse DNS {} query from {}: {}",
                transport,
                client_addr,
                e
            );
            if let Some(response) = e.to_response()
                && let Err(error) = writer.write_message(&response).await
            {
                log::error!(
                    "Failed to answer malformed DNS {} query from {}: {}",
                    transport,
                    client_addr,
                    error
                );
            }
            return;
        }
    };

    // Each refusal below is answered under the query's key when it has one.
    let refusal = if let Some(rcode) = query.format_error() {
        log::info!(
            "Refusing DNS {} query format from {}: {}",
            transport,
            client_addr,
            rcode
        );
        Some((rcode, None))
    } else if query.qclass != Class::IN {
        // RFC 5936, Section 2.2.2 echoes the class asked; only IN is served.
        log::info!(
            "Refusing DNS {} class {} from {}",
            transport,
            query.qclass,
            client_addr
        );
        Some((
            OptRcode::NOTAUTH,
            Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
        ))
    } else if query.opcode != Opcode::QUERY {
        log::info!(
            "Refusing DNS {} opcode {:?} from {}",
            transport,
            query.opcode,
            client_addr
        );
        Some((OptRcode::NOTIMP, Some(ExtendedErrorCode::NOT_SUPPORTED)))
    } else if query.qtype != Rtype::SOA && !server::is_xfr_query_type(query.qtype) {
        // bindizr answers secondaries, not resolvers; over TLS the refusal
        // names its reason (RFC 9103, Section 7.8).
        log::info!(
            "Refusing out-of-scope DNS {} query from {} (qtype={:?})",
            transport,
            client_addr,
            query.qtype
        );
        Some((OptRcode::REFUSED, Some(ExtendedErrorCode::NOT_SUPPORTED)))
    } else {
        None
    };

    let result = async {
        if let Some((rcode, ede)) = refusal {
            let response = server::refuse_query(dns_cx, &query, query_data, rcode, ede).await?;
            writer.write_message(&response).await
        } else if query.qtype == Rtype::SOA {
            server::soa::handle_tcp_soa(dns_cx, writer, client_addr, &query, query_data).await
        } else {
            server::handle_tcp_xfr(dns_cx, writer, client_addr, &query, query_data).await
        }
    }
    .await;
    if let Err(error) = result {
        log::error!(
            "DNS {} query from {} failed (opcode={:?} qtype={:?} qclass={}): {}",
            transport,
            client_addr,
            query.opcode,
            query.qtype,
            query.qclass,
            error
        );
    }
}
