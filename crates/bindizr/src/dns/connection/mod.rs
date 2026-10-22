//! Framed queries on an established TCP or TLS connection.

use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

use bindizr_core::dns::message::{self, Keepalive, Rtype};
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
    stop: impl Future<Output = ()>,
) -> Result<(), DnsError> {
    let transport = stream.transport();
    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(writer);
    let idle_timeout = dns_cx.daemon().config().dns.tcp_idle_timeout();
    let mut pending = Vec::new();
    let mut in_flight = JoinSet::new();
    let mut transfers = JoinSet::new();
    let mut stopping = false;
    tokio::pin!(stop);

    let outcome = loop {
        // A connection with a query in flight is not idle (RFC 7766, Section
        // 6.2.3); the cancel-safe read may be interrupted by a query finishing.
        let busy = !in_flight.is_empty() || !transfers.is_empty();

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
            () = &mut stop => {
                stopping = true;
                break Ok(());
            }

            () = writer.failed() => break Err(DnsError::PeerClosed),

            Some(_) = in_flight.join_next(), if !in_flight.is_empty() => continue,

            Some(_) = transfers.join_next(), if !transfers.is_empty() => continue,

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

        if in_flight.len() + transfers.len() >= MAX_QUERIES_IN_FLIGHT {
            tokio::select! {
                biased;
                () = &mut stop => {
                    stopping = true;
                    break Ok(());
                }

                () = writer.failed() => break Err(DnsError::PeerClosed),

                Some(_) = in_flight.join_next(), if !in_flight.is_empty() => {},

                Some(_) = transfers.join_next(), if !transfers.is_empty() => {},
            }
        }

        // Separate retryable transfers from requests that must finish during shutdown.
        let transfer =
            message::ParsedQuery::parse(&query_data, Keepalive::IdleTimeout(idle_timeout))
                .is_ok_and(|query| {
                    query.opcode == message::Opcode::QUERY
                        && matches!(query.qtype, Rtype::AXFR | Rtype::IXFR)
                });
        let dns_cx = dns_cx.clone();
        let writer = writer.clone();

        let answer = async move {
            dispatch_query(&dns_cx, &writer, client_addr, &query_data, idle_timeout).await;
        };

        if transfer {
            transfers.spawn(answer);
        } else {
            in_flight.spawn(answer);
        }
    };

    // Clean FIN keeps replies open (RFC 9293, Section 3.6.1); failures cancel transfers.
    // Finish UPDATE and NOTIFY without replies after failure (RFC 7766, Section 6.2.4).
    if stopping && !transfers.is_empty() {
        // Fail the writer before cancellation can leave a partial frame.
        writer.fail();
        transfers.abort_all();
    }

    while in_flight.join_next().await.is_some() {}

    while transfers.join_next().await.is_some() {}

    // A TLS peer is owed close_notify ahead of the FIN; a plain socket closes.
    if outcome.is_ok()
        && let Err(error) = writer.shutdown().await
    {
        log::debug!(
            "Closing DNS {} connection from {}: {}",
            transport,
            client_addr,
            error
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

    let keepalive = Keepalive::IdleTimeout(idle_timeout);

    match server::refuse_unsupported_opcode(dns_cx, query_data, keepalive, transport).await {
        Ok(Some((response, _))) => {
            if let Err(error) = writer.write_message(&response).await {
                log::error!(
                    "Failed to refuse DNS {} opcode from {}: {}",
                    transport,
                    client_addr,
                    error
                );
            }

            return;
        }
        Ok(None) => {}
        Err(error) => {
            log::error!(
                "Failed to refuse DNS {} opcode from {}: {}",
                transport,
                client_addr,
                error
            );
            return;
        }
    }

    let query = match message::ParsedQuery::parse(query_data, keepalive) {
        Ok(query) => query,
        Err(error) => {
            log::warn!(
                "Failed to parse DNS {} query from {}: {}",
                transport,
                client_addr,
                error
            );

            if let Some(metadata) = error.query_metadata() {
                let result = async {
                    let rcode = metadata
                        .format_error()
                        .unwrap_or(message::OptRcode::FORMERR);
                    let response =
                        server::refuse_query(dns_cx, metadata, query_data, rcode, None).await?;
                    writer.write_message(&response).await
                }
                .await;

                if let Err(error) = result {
                    log::error!(
                        "Failed to answer malformed DNS {} query from {}: {}",
                        transport,
                        client_addr,
                        error
                    );
                }
            }

            return;
        }
    };

    let result = async {
        if let Some((rcode, ede)) = server::query_refusal(&query, transport, client_addr) {
            let response = server::refuse_query(
                dns_cx,
                &message::QueryMetadata::from(&query),
                query_data,
                rcode,
                ede,
            )
            .await?;

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

#[cfg(test)]
mod tests;
