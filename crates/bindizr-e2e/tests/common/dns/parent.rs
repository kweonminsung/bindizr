//! A stand-in for a parent zone's nameserver: answers every DS question
//! authoritatively with the records it is told to serve, whatever the child.

use std::{
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread,
};

use domain::{
    base::{
        Message, MessageBuilder, Rtype, ToName, Ttl,
        iana::{Class, DigestAlgorithm, Rcode, SecurityAlgorithm},
    },
    rdata::Ds,
};

pub(crate) struct FakeParent {
    addr: SocketAddr,
    /// `(key tag, TTL)` of each DS record served.
    ds: Arc<Mutex<Vec<(u16, u32)>>>,
}

impl FakeParent {
    /// Start on an ephemeral port, serving no DS records yet.
    pub(crate) fn start() -> Self {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("failed to bind the fake parent");
        let addr = socket
            .local_addr()
            .expect("failed to read the fake parent's port");
        let ds: Arc<Mutex<Vec<(u16, u32)>>> = Arc::new(Mutex::new(Vec::new()));
        let served = Arc::clone(&ds);

        thread::spawn(move || {
            let mut buf = [0_u8; 4096];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf) else {
                    return;
                };
                let Ok(query) = Message::from_octets(&buf[..len]) else {
                    continue;
                };
                let Ok(question) = query.sole_question() else {
                    continue;
                };
                let qname = question.qname().to_name::<Vec<u8>>();
                let mut answer = MessageBuilder::new_vec()
                    .start_answer(&query, Rcode::NOERROR)
                    .expect("start the answer");
                answer.header_mut().set_aa(true);
                if question.qtype() == Rtype::DS {
                    for (key_tag, ttl) in served.lock().expect("ds lock").iter() {
                        answer
                            .push((
                                &qname,
                                Class::IN,
                                Ttl::from_secs(*ttl),
                                Ds::new(
                                    *key_tag,
                                    SecurityAlgorithm::ECDSAP256SHA256,
                                    DigestAlgorithm::SHA256,
                                    vec![0xab; 32],
                                )
                                .expect("build the DS record"),
                            ))
                            .expect("push the DS record");
                    }
                }
                let _ = socket.send_to(&answer.finish(), peer);
            }
        });

        Self { addr, ds }
    }

    /// The `host:port` entry to give bindizr as the zone's parent address.
    pub(crate) fn addr(&self) -> String {
        self.addr.to_string()
    }

    /// Replace the DS records served: `(key tag, TTL)` pairs.
    pub(crate) fn set_ds(&self, records: Vec<(u16, u32)>) {
        *self.ds.lock().expect("ds lock") = records;
    }
}
