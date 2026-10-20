//! Multiplex NOTIFY transactions on one connected socket per active target.

use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    future::pending,
    net::SocketAddr,
    sync::{Arc, Weak},
    time::Duration,
};

use bindizr_core::dns::{
    message::{Keepalive, Name, OptRcode, ParsedQuery, ResponseLimit},
    query::{
        ParseResponseError, build_notify_query, matches_response_to_request,
        validate_notify_response,
    },
    tsig::{ResponseVerifier, TsigSigningKey, sign_request, verify_response},
};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, Semaphore, mpsc, oneshot},
    time::{Instant, sleep_until},
};

use super::{ExchangeMessageError, SendNotifyError};

/// Bound database/key/address preparation, never the time spent waiting for ACKs.
const CONCURRENT_PREPARATIONS: usize = 16;

/// A daemon's active NOTIFY target sockets; idle sockets have no strong owner.
#[derive(Debug)]
pub(crate) struct NotifyClient {
    targets: Mutex<HashMap<SocketAddr, Weak<TargetSocket>>>,
    pub(super) preparations: Semaphore,
}

impl Default for NotifyClient {
    /// Create an empty target pool with bounded preparation concurrency.
    fn default() -> Self {
        Self {
            targets: Mutex::new(HashMap::new()),
            preparations: Semaphore::new(CONCURRENT_PREPARATIONS),
        }
    }
}

/// The sender keeps its socket task alive until its last transaction completes.
#[derive(Debug)]
struct TargetSocket {
    jobs: mpsc::UnboundedSender<PendingNotify>,
    ids: Mutex<HashSet<u16>>,
}

impl TargetSocket {
    /// Reserve an unpredictable ID, never reusing one on this socket.
    async fn reserve_id(&self) -> Option<u16> {
        let mut ids = self.ids.lock().await;
        if ids.len() > usize::from(u16::MAX) {
            return None;
        }
        loop {
            let id = rand::random();
            if ids.insert(id) {
                return Some(id);
            }
        }
    }
}

/// One immutable datagram, its verifier, and the timer for its current attempt.
#[derive(Debug)]
struct PendingNotify {
    request: Vec<u8>,
    limit: ResponseLimit,
    verifier: Option<ResponseVerifier>,
    timeout: Duration,
    retries_left: u32,
    deadline: Instant,
    waiting: bool,
    sent: bool,
    qname: Name<Vec<u8>>,
    reply: oneshot::Sender<Result<(), SendNotifyError>>,
}

impl NotifyClient {
    /// Get a target socket and reserve an ID before the request is signed.
    async fn reserve(
        &self,
        address: SocketAddr,
    ) -> Result<(Arc<TargetSocket>, u16), ExchangeMessageError> {
        let mut targets = self.targets.lock().await;
        targets.retain(|_, target| target.strong_count() != 0);
        if let Some(target) = targets.get(&address).and_then(Weak::upgrade)
            && !target.jobs.is_closed()
            && let Some(id) = target.reserve_id().await
        {
            return Ok((target, id));
        }
        let socket = UdpSocket::bind(if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        socket.connect(address).await?;
        let (jobs, rx) = mpsc::unbounded_channel();
        let target = Arc::new(TargetSocket {
            jobs,
            ids: Mutex::new(HashSet::new()),
        });
        let id = target
            .reserve_id()
            .await
            .expect("a new socket has unused IDs");
        targets.insert(address, Arc::downgrade(&target));
        tokio::spawn(serve(address, socket, rx));
        Ok((target, id))
    }

    /// Send and authenticate a NOTIFY, retrying the same bytes/socket only on silence.
    pub(super) async fn start(
        &self,
        qname: &Name<Vec<u8>>,
        address: SocketAddr,
        timeout: Duration,
        retries: u32,
        key: Option<&TsigSigningKey>,
    ) -> Result<NotifyExchange, SendNotifyError> {
        let (target, id) = self.reserve(address).await?;
        let (_, mut builder) = build_notify_query(qname, key);
        builder.header_mut().set_id(id);
        let verifier = key
            .map(|key| sign_request(&mut builder, key.clone()))
            .transpose()?;
        let wire = builder.finish();
        let limit = ParsedQuery::parse(&wire, Keepalive::None)
            .map_err(ExchangeMessageError::from)?
            .response_limit();
        let (reply, response) = oneshot::channel();
        let request = PendingNotify {
            request: wire,
            limit,
            verifier,
            timeout,
            retries_left: retries,
            qname: qname.clone(),
            deadline: Instant::now() + timeout,
            waiting: false,
            sent: false,
            reply,
        };
        target
            .jobs
            .send(request)
            .map_err(|_| SendNotifyError::DispatcherClosed)?;
        Ok(NotifyExchange { target, response })
    }
}

/// A transaction keeps its shared socket alive until its caller finishes or cancels.
#[derive(Debug)]
pub(super) struct NotifyExchange {
    target: Arc<TargetSocket>,
    response: oneshot::Receiver<Result<(), SendNotifyError>>,
}

impl NotifyExchange {
    /// Wait for the matching authenticated reply or the final transport error.
    pub(super) async fn wait(self) -> Result<(), SendNotifyError> {
        let result = self
            .response
            .await
            .map_err(|_| SendNotifyError::DispatcherClosed)?;
        drop(self.target);
        result
    }
}

/// Run all outstanding transactions for a connected peer without per-zone tasks.
async fn serve(
    address: SocketAddr,
    socket: UdpSocket,
    mut rx: mpsc::UnboundedReceiver<PendingNotify>,
) {
    let mut requests: HashMap<u16, PendingNotify> = HashMap::new();
    let mut timers = BTreeSet::new();
    let mut ready = VecDeque::new();
    let mut accepting = true;
    let mut buffer = [0; super::super::UDP_RESPONSE_BUF];
    loop {
        // A cancelled caller no longer needs retries.
        requests.retain(|id, request| {
            if request.reply.is_closed() {
                timers.remove(&(request.deadline, *id));
                false
            } else {
                true
            }
        });
        while ready.front().is_some_and(|id| !requests.contains_key(id)) {
            ready.pop_front();
        }
        if !accepting && requests.is_empty() {
            break;
        }
        let deadline = timers.first().map(|(time, _)| *time);
        tokio::select! {
            job = rx.recv(), if accepting => match job {
                Some(request) => {
                    let id = u16::from_be_bytes([request.request[0], request.request[1]]);
                    timers.insert((request.deadline, id));
                    requests.insert(id, request);
                    ready.push_back(id);
                }
                None => accepting = false,
            },
            () = async { match deadline { Some(deadline) => sleep_until(deadline).await, None => pending().await } } => {
                let (_, id) = timers.pop_first().expect("a timer woke this branch");
                let request = requests.get_mut(&id).expect("timers belong to live requests");
                if request.waiting && request.retries_left > 0 {
                    request.retries_left -= 1;
                    request.waiting = false;
                    request.deadline = Instant::now() + request.timeout;
                    timers.insert((request.deadline, id));
                    ready.push_back(id);
                    log::info!("Retransmitting NOTIFY to {} after {:?} of silence", address, request.timeout);
                } else {
                    let request = requests.remove(&id).unwrap();
                    let error = if request.waiting {
                        ExchangeMessageError::ResponseTimedOut { what: "NOTIFY", server: address }
                    } else { ExchangeMessageError::SendTimedOut { what: "NOTIFY" } };
                    let _ = request.reply.send(Err(error.into()));
                }
            },
            result = socket.writable(), if !ready.is_empty() => {
                if let Err(error) = result { fail_requests(&mut requests, error); break; }
                let id = *ready.front().unwrap();
                let request = requests.get_mut(&id).unwrap();
                match socket.try_send(&request.request) {
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {},
                    Err(error) => { fail_requests(&mut requests, error); break; }
                    Ok(sent) => {
                        ready.pop_front();
                        timers.remove(&(request.deadline, id));
                        if sent != request.request.len() {
                            let request = requests.remove(&id).unwrap();
                            let _ = request.reply.send(Err(ExchangeMessageError::IncompleteSend {
                                what: "NOTIFY", server: address, sent, len: request.request.len(),
                            }.into()));
                        } else {
                            request.waiting = true;
                            request.sent = true;
                            request.deadline = Instant::now() + request.timeout;
                            timers.insert((request.deadline, id));
                        }
                    }
                }
            },
            result = socket.recv(&mut buffer), if !requests.is_empty() => {
                let received = match result { Ok(len) => len, Err(error) => { fail_requests(&mut requests, error); break; } };
                let response = &buffer[..received];
                if response.len() < 2 { continue; }
                let id = u16::from_be_bytes([response[0], response[1]]);
                let Some(request) = requests.get(&id) else { continue; };
                if request.limit.validate_len(received).is_err() || !request.sent || !matches_response_to_request(&request.request, response) { continue; }
                let verified = request.verifier.as_ref().map(|verifier| verify_response(verifier, response)).transpose();
                if let Err(error) = &verified
                    && !error.is_authenticated()
                {
                    log::warn!("Ignoring an unauthenticated NOTIFY response from {}: {}", address, error);
                    continue;
                }
                let request = requests.remove(&id).unwrap();
                timers.remove(&(request.deadline, id));
                let result = verified.map_err(SendNotifyError::Verify).and_then(|_| {
                    match validate_notify_response(id, &request.qname, response) {
                        // RFC 1996, Section 3.12: a validated NOTIMP completes the transaction.
                        Err(ParseResponseError::NotifyRcode(OptRcode::NOTIMP)) => {
                            log::warn!("Server {} does not support NOTIFY; transaction complete", address);
                            Ok(())
                        }
                        result => result.map_err(SendNotifyError::Response),
                    }
                });
                let _ = request.reply.send(result);
            },
        }
    }
}

/// A connected-socket ICMP/I/O error ends every outstanding exchange to that peer.
fn fail_requests(requests: &mut HashMap<u16, PendingNotify>, error: std::io::Error) {
    for (_, request) in requests.drain() {
        let error = std::io::Error::new(error.kind(), error.to_string());
        let _ = request
            .reply
            .send(Err(ExchangeMessageError::Io(error).into()));
    }
}

#[cfg(test)]
mod tests;
