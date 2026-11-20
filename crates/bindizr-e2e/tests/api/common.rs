//! Helpers the API scenarios share: a zone created under the caller's own
//! name, the grant a role needs to change records, and a fake secondary that
//! records NOTIFY signatures and signs its replies (RFC 1996). The fake's SOA
//! replies use [`SERVED_SERIAL`] so probes see it as reachable and behind.

use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;

use domain::base::iana::{Class, Opcode, Rcode, Rtype};
use domain::base::{Message, MessageBuilder, Name, Serial, Ttl};
use domain::rdata::Soa;
use domain::rdata::tsig::Time48;
use domain::tsig::{Key, ServerTransaction};
use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;
use crate::common::dns::tsig::SigningKey;

/// Every record action, the grant a test role needs to read and change a zone's records.
pub(crate) const RECORD_ACTIONS: &str = "record:read,record:create,record:update,record:delete";

impl TestApp {
    /// Create a zone under the name given, for tests whose subject is what a
    /// grant or a key may reach rather than the zone itself.
    pub(crate) async fn create_named_zone(&self, zone_name: &str) {
        let (status, _) = self
            .send_request(
                Method::POST,
                "/zones",
                Some(json!({
                    "name": zone_name,
                    "mname": format!("ns1.{zone_name}"),
                    "rname": "admin@example.com",
                    "default_ttl": 3600
                })),
            )
            .await;

        assert_eq!(status, StatusCode::CREATED);
    }
}

/// The serial the fake answers every SOA query with.
pub(crate) const SERVED_SERIAL: u32 = 1;

/// One NOTIFY as the fake secondary saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReceivedNotify {
    pub(crate) zone_name: String,
    /// The request carried a TSIG record.
    pub(crate) signed: bool,
    /// The TSIG verified under the fake's key; a signature under another key
    /// is answered with the TSIG error instead.
    pub(crate) verified: bool,
}

/// A UDP secondary on an ephemeral port that answers NOTIFY and SOA queries.
#[derive(Debug)]
pub(crate) struct FakeSecondary {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<ReceivedNotify>>>,
}

impl FakeSecondary {
    /// Start on an ephemeral port; with `key`, a signed NOTIFY is verified
    /// under it and answered signed.
    pub(crate) fn start(key: Option<&SigningKey>) -> Self {
        use domain::base::ToName;

        let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("failed to bind the fake secondary");
        let addr = socket
            .local_addr()
            .expect("failed to read the fake secondary's port");
        let key: Option<Arc<Key>> =
            key.map(|key| Arc::new(key.to_tsig_key().expect("the notify key converts")));
        let received: Arc<Mutex<Vec<ReceivedNotify>>> = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&received);

        thread::spawn(move || {
            let mut buffer = [0; 4096];

            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buffer) else {
                    return;
                };
                let Ok(mut query) = Message::from_octets(buffer[..len].to_vec()) else {
                    continue;
                };
                let Ok(question) = query.sole_question() else {
                    continue;
                };
                let qname = question.qname().to_name::<Vec<u8>>();
                let zone_name = qname.to_string();

                // A probe: answer the SOA with the fixed serial.
                if query.header().opcode() == Opcode::QUERY {
                    let mut answer = MessageBuilder::new_vec()
                        .start_answer(&query, Rcode::NOERROR)
                        .expect("start the answer");
                    answer.header_mut().set_aa(true);

                    if question.qtype() == Rtype::SOA {
                        let mname = Name::<Vec<u8>>::root_vec();
                        answer
                            .push((
                                &qname,
                                Class::IN,
                                Ttl::from_secs(60),
                                Soa::new(
                                    mname.clone(),
                                    mname,
                                    Serial::from(SERVED_SERIAL),
                                    Ttl::from_secs(60),
                                    Ttl::from_secs(60),
                                    Ttl::from_secs(60),
                                    Ttl::from_secs(60),
                                ),
                            ))
                            .expect("push the SOA");
                    }

                    let _ = socket.send_to(&answer.finish(), peer);

                    continue;
                }

                let signed = query.additional().is_ok_and(|section| {
                    section
                        .flatten()
                        .any(|record| record.rtype() == Rtype::TSIG)
                });

                // With a key, the signature decides the answer.
                let mut signer = None;

                if let Some(key) = &key {
                    match ServerTransaction::request(key, &mut query, Time48::now()) {
                        Ok(context) => signer = context,
                        Err(error) => {
                            seen.lock().expect("received lock").push(ReceivedNotify {
                                zone_name,
                                signed,
                                verified: false,
                            });

                            if let Ok(response) =
                                error.build_message(&query, MessageBuilder::new_vec())
                            {
                                let _ = socket.send_to(&response.finish(), peer);
                            }

                            continue;
                        }
                    }
                }

                seen.lock().expect("received lock").push(ReceivedNotify {
                    zone_name,
                    signed,
                    verified: signer.is_some(),
                });

                let mut answer = MessageBuilder::new_vec()
                    .start_answer(&query, Rcode::NOERROR)
                    .expect("start the answer")
                    .additional();

                if let Some(signer) = signer {
                    signer
                        .answer(&mut answer, Time48::now())
                        .expect("sign the answer");
                }

                let _ = socket.send_to(&answer.finish(), peer);
            }
        });

        Self { addr, received }
    }

    /// Return the `host:port` to register the fake as a secondary under.
    pub(crate) fn addr(&self) -> String {
        self.addr.to_string()
    }

    /// Return every NOTIFY received so far, in order.
    pub(crate) fn received(&self) -> Vec<ReceivedNotify> {
        self.received.lock().expect("received lock").clone()
    }
}
