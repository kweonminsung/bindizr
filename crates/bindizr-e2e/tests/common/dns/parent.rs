//! A stand-in for a parent zone's nameserver: answers every DS question
//! authoritatively with the records it is told to serve, whatever the child.

use std::{
    net::{SocketAddr, UdpSocket},
    str::FromStr,
    sync::{Arc, Mutex},
    thread,
};

use base64::Engine;
use domain::{
    base::{
        Message, MessageBuilder, Name, Rtype, Serial, ToName, Ttl,
        iana::{Class, DigestAlgorithm, Rcode, SecurityAlgorithm},
    },
    rdata::{Ds, Soa},
};
use serde_json::Value;
use sha1::{Digest, Sha1};

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

    /// The SHA-1 DS of key `key_tag`, digested from the status payload's
    /// DNSKEY since bindizr renders none: what a parent digesting the
    /// DNSKEY itself may register.
    pub(crate) fn sha1_from_status(
        dnssec: &Value,
        zone_name: &str,
        key_tag: u16,
        ttl: u32,
    ) -> Self {
        let dnskey = dnssec["keys"]
            .as_array()
            .expect("status carries keys")
            .iter()
            .find(|key| key["key_tag"] == key_tag)
            .unwrap_or_else(|| panic!("no key with tag {key_tag} in {dnssec}"))["dnskey"]
            .as_str()
            .expect("DNSKEY presentation");
        let fields: Vec<&str> = dnskey.split(' ').collect();
        let flags: u16 = fields[0].parse().expect("DNSKEY flags");
        let algorithm: u8 = fields[2].parse().expect("DNSKEY algorithm");
        let mut rdata = flags.to_be_bytes().to_vec();
        rdata.extend_from_slice(&[3, algorithm]);
        rdata.extend(
            base64::engine::general_purpose::STANDARD
                .decode(fields[3])
                .expect("DNSKEY public key is base64"),
        );
        // RFC 4034, Section 5.1.4: the digest covers the wire owner name,
        // then the DNSKEY RDATA.
        let apex = Name::<Vec<u8>>::from_str(zone_name).expect("zone name");
        let mut hasher = Sha1::new();
        hasher.update(apex.as_slice());
        hasher.update(&rdata);
        Self {
            key_tag,
            algorithm,
            digest_type: 1,
            digest: hasher.finalize().to_vec(),
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
                let mut served_any = false;
                if question.qtype() == Rtype::DS {
                    for record in served.lock().expect("ds lock").iter() {
                        served_any = true;
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
                let mut authority = answer.authority();
                if !served_any {
                    // A negative answer needs the parent's SOA (RFC 2308, Section 2).
                    let parent = qname
                        .parent()
                        .map(|parent| parent.to_name::<Vec<u8>>())
                        .unwrap_or_else(Name::root_vec);
                    authority
                        .push((
                            &parent,
                            Class::IN,
                            Ttl::from_secs(60),
                            Soa::new(
                                parent.clone(),
                                parent.clone(),
                                Serial(1),
                                Ttl::from_secs(60),
                                Ttl::from_secs(60),
                                Ttl::from_secs(60),
                                Ttl::from_secs(60),
                            ),
                        ))
                        .expect("push the parent SOA");
                }
                let _ = socket.send_to(&authority.finish(), peer);
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
