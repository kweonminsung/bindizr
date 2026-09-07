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
use serde_json::Value;

/// A DS record for the fake parent to serve.
#[derive(Clone, Debug)]
pub(crate) struct ServedDs {
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: Vec<u8>,
    ttl: u32,
}

impl ServedDs {
    /// The DS of key `key_tag` as a status payload's `ds_records` lists it.
    pub(crate) fn from_status(dnssec: &Value, key_tag: u16, ttl: u32) -> Self {
        let record = dnssec["ds_records"]
            .as_array()
            .expect("status carries ds_records")
            .iter()
            .find(|record| record["key_tag"] == key_tag)
            .unwrap_or_else(|| panic!("no DS for key tag {key_tag} in {dnssec}"));
        let digest = record["digest"].as_str().expect("DS digest is hex");
        Self {
            key_tag,
            algorithm: record["algorithm"].as_u64().expect("DS algorithm") as u8,
            digest_type: record["digest_type"].as_u64().expect("DS digest type") as u8,
            digest: (0..digest.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&digest[i..i + 2], 16).expect("hex digest"))
                .collect(),
            ttl,
        }
    }

    /// The same DS with a digest of no key: another key sharing the tag.
    pub(crate) fn with_wrong_digest(mut self) -> Self {
        self.digest = vec![0xab; self.digest.len()];
        self
    }
}

pub(crate) struct FakeParent {
    addr: SocketAddr,
    ds: Arc<Mutex<Vec<ServedDs>>>,
}

impl FakeParent {
    /// Start on an ephemeral port, serving no DS records yet.
    pub(crate) fn start() -> Self {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("failed to bind the fake parent");
        let addr = socket
            .local_addr()
            .expect("failed to read the fake parent's port");
        let ds: Arc<Mutex<Vec<ServedDs>>> = Arc::new(Mutex::new(Vec::new()));
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
                    for record in served.lock().expect("ds lock").iter() {
                        answer
                            .push((
                                &qname,
                                Class::IN,
                                Ttl::from_secs(record.ttl),
                                Ds::new(
                                    record.key_tag,
                                    SecurityAlgorithm::from_int(record.algorithm),
                                    DigestAlgorithm::from_int(record.digest_type),
                                    record.digest.clone(),
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

    /// Replace the DS records served.
    pub(crate) fn set_ds(&self, records: Vec<ServedDs>) {
        *self.ds.lock().expect("ds lock") = records;
    }
}
