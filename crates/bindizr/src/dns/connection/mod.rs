//! Framed queries on an established TCP or TLS connection.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bindizr_core::dns::message::{Keepalive, Opcode, ParsedQuery, QueryMetadata};
use bindizr_core::dns::{DnsTransport, message};
use bindizr_core::model::transfer::TransferKind;
use tokio::task::{JoinError, JoinSet};
use tokio::time;

use crate::dns::error::DnsError;
use crate::dns::server::{DnsContext, QueryDispatch, nsupdate, soa};
use crate::dns::stream::{DnsStream, ResponseWriter};
use crate::dns::{server, wire};

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
                match time::timeout(idle_timeout, read).await {
                    Ok(result) => result,
                    Err(_) => {
                        log::info!(
                            "Closing idle DNS {transport} connection from {client_addr} after {idle_timeout:?}"
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

            Some(result) = in_flight.join_next(), if !in_flight.is_empty() => {
                log_query_task_failure(transport, client_addr, result);
                continue;
            }

            Some(result) = transfers.join_next(), if !transfers.is_empty() => {
                log_query_task_failure(transport, client_addr, result);
                continue;
            }

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

                Some(result) = in_flight.join_next(), if !in_flight.is_empty() => {
                    log_query_task_failure(transport, client_addr, result);
                }

                Some(result) = transfers.join_next(), if !transfers.is_empty() => {
                    log_query_task_failure(transport, client_addr, result);
                }
            }
        }

        // Separate retryable transfers from requests that must finish during shutdown.
        let transfer = ParsedQuery::parse(&query_data, Keepalive::IdleTimeout(idle_timeout))
            .is_ok_and(|query| {
                query.opcode == Opcode::QUERY && TransferKind::try_from(query.qtype).is_ok()
            });
        let dns_cx = dns_cx.clone();
        let writer = writer.clone();

        let task = async move {
            handle_stream_query(&dns_cx, &writer, client_addr, &query_data, idle_timeout).await;
        };

        if transfer {
            transfers.spawn(task);
        } else {
            in_flight.spawn(task);
        }
    };

    // Clean FIN keeps replies open (RFC 9293, Section 3.6.1); failures cancel transfers.
    // Finish UPDATE and NOTIFY without replies after failure (RFC 7766, Section 6.2.4).
    if stopping && !transfers.is_empty() {
        // Fail the writer before cancellation can leave a partial frame.
        writer.fail();
        transfers.abort_all();
    }

    while let Some(result) = in_flight.join_next().await {
        log_query_task_failure(transport, client_addr, result);
    }

    while let Some(result) = transfers.join_next().await {
        log_query_task_failure(transport, client_addr, result);
    }

    // A TLS peer is owed close_notify ahead of the FIN; a plain socket closes.
    if outcome.is_ok()
        && let Err(error) = writer.shutdown().await
    {
        log::debug!("Closing DNS {transport} connection from {client_addr}: {error}");
    }

    outcome
}

/// Log failed query tasks. Cancelling transfers during shutdown is expected.
fn log_query_task_failure(
    transport: DnsTransport,
    client_addr: SocketAddr,
    result: Result<(), JoinError>,
) {
    if let Err(error) = result
        && !error.is_cancelled()
    {
        log::warn!("DNS {transport} query task failed for {client_addr}: {error}");
    }
}

/// Route a framed DNS query to its transfer, update, or SOA handler.
async fn handle_stream_query(
    dns_cx: &DnsContext,
    writer: &ResponseWriter,
    client_addr: SocketAddr,
    query_data: &[u8],
    idle_timeout: Duration,
) {
    let transport = writer.transport();

    if message::is_response(query_data) {
        log::warn!("Ignoring a DNS {transport} response from {client_addr}");
        return;
    }

    let keepalive = Keepalive::IdleTimeout(idle_timeout);

    match server::refuse_unsupported_opcode(dns_cx, query_data, keepalive, transport).await {
        Ok(Some((response, _))) => {
            match writer.write_message(&response).await {
                Ok(()) | Err(DnsError::PeerClosed) => {}
                Err(error) => {
                    log::warn!(
                        "Failed to refuse DNS {transport} opcode from {client_addr}: {error}"
                    );
                }
            }

            return;
        }
        Ok(None) => {}
        Err(error) => {
            log::error!("Failed to refuse DNS {transport} opcode from {client_addr}: {error}");
            return;
        }
    }

    // nsupdate parses its own message and TSIG; other queries share this parse.
    if nsupdate::is_nsupdate(query_data) {
        // Server faults are logged inside the handler; what reaches here is the
        // client's side of the exchange.
        match nsupdate::handle_tcp_nsupdate(dns_cx, writer, client_addr, query_data).await {
            Ok(()) | Err(DnsError::PeerClosed) => {}
            Err(error) => {
                log::warn!("NSUPDATE {transport} handler failed for {client_addr}: {error}");
            }
        }

        return;
    }

    let query = match ParsedQuery::parse(query_data, keepalive) {
        Ok(query) => query,
        Err(error) => {
            log::warn!("Failed to parse DNS {transport} query from {client_addr}: {error}");

            if let (Some(metadata), Some(rcode)) = (error.query_metadata(), error.format_error()) {
                let result = async {
                    let response =
                        server::refuse_query(dns_cx, metadata, query_data, rcode, None).await?;
                    writer.write_message(&response).await
                }
                .await;

                if let Err(error) = result {
                    log::error!(
                        "Failed to answer malformed DNS {transport} query from {client_addr}: {error}"
                    );
                }
            }

            return;
        }
    };

    let result = match server::classify_query(client_addr, &query, transport) {
        QueryDispatch::Refuse { rcode, ede } => {
            async {
                let response = server::refuse_query(
                    dns_cx,
                    &QueryMetadata::from(&query),
                    query_data,
                    rcode,
                    ede,
                )
                .await?;

                writer.write_message(&response).await
            }
            .await
        }
        QueryDispatch::Transfer(kind) => {
            server::handle_stream_xfr(dns_cx, writer, client_addr, &query, query_data, kind).await
        }
        QueryDispatch::Soa => {
            soa::handle_stream_soa(dns_cx, writer, client_addr, &query, query_data).await
        }
    };

    // A handler logs a server fault with its cause where it answers; this adds
    // where the query came from, as the UDP dispatcher does. A peer that went
    // away is not a failure of the query.
    match result {
        Ok(()) | Err(DnsError::PeerClosed) => {}
        Err(error) => log::warn!(
            "DNS {transport} query from {client_addr} failed (opcode={:?} qtype={:?} qclass={}): {error}",
            query.opcode,
            query.qtype,
            query.qclass
        ),
    }
}

#[cfg(test)]
mod tests;
