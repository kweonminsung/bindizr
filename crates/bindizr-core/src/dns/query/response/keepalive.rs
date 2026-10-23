//! Decode the TCP keepalive timeout carried by a DNS response.

use std::time::Duration;

use domain::base::{Message, opt::keepalive::TcpKeepalive};

use super::ParseResponseError;
use crate::dns::message::Edns;

/// Read the server's idle timeout, in 100 ms units (RFC 7828, Sections 3.1 and 3.2.2).
pub fn extract_tcp_keepalive_timeout(
    response: &[u8],
) -> Result<Option<Duration>, ParseResponseError> {
    let message = Message::from_octets(response)
        .map_err(|error| ParseResponseError::Malformed(Box::new(error)))?;

    if Edns::from_message(&message) == Edns::Malformed {
        return Err(ParseResponseError::MalformedEdns);
    }

    let Some(opt) = message.opt() else {
        return Ok(None);
    };
    let mut options = opt.opt().iter::<TcpKeepalive>();
    let Some(keepalive) = options.next() else {
        return Ok(None);
    };
    let timeout = keepalive
        .map_err(|_| ParseResponseError::MalformedEdns)?
        .timeout()
        .ok_or(ParseResponseError::MalformedEdns)?;

    if options.next().is_some() {
        return Err(ParseResponseError::MalformedEdns);
    }

    Ok(Some(Duration::from(timeout)))
}
