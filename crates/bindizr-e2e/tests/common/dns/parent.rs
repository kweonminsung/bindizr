//! Authoritative parent DS responder with configurable records and metadata.

use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;

use base64::Engine;
use domain::base::iana::{Class, DigestAlgorithm, OptRcode, SecurityAlgorithm};
use domain::base::{Message, MessageBuilder, Name, Rtype, Serial, ToName, Ttl};
use domain::rdata::{Ds, Soa};
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};
use serde_json::Value;

/// A DS record for the fake parent to serve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DsRecord {
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: Vec<u8>,
    ttl: u32,
}

impl DsRecord {
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

    /// Compute a parent's SHA-1 DS from the status DNSKEY; status does not render SHA-1.
    pub(crate) fn sha1_from_status(
        dnssec: &Value,
        zone_name: &str,
        key_tag: u16,
        ttl: u32,
    ) -> Self {
        use std::str::FromStr;

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
        let mut hasher = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        hasher.update(apex.as_slice());
        hasher.update(&rdata);

        Self {
            key_tag,
            algorithm,
            digest_type: 1,
            digest: hasher.finish().as_ref().to_vec(),
            ttl,
        }
    }

    /// The same DS with a digest of no key: another key sharing the tag.
    pub(crate) fn with_wrong_digest(mut self) -> Self {
        self.digest = vec![0xab; self.digest.len()];
        self
    }

    /// Relabel the digest type to test unsupported digests.
    pub(crate) fn with_digest_type(mut self, digest_type: u8) -> Self {
        self.digest_type = digest_type;
        self
    }
}

/// The records and response metadata the fake parent serves.
#[derive(Debug)]
struct ParentResponse {
    records: Vec<DsRecord>,
    rcode: OptRcode,
    class: Class,
}

/// A loopback parent serving configurable DS records and metadata.
#[derive(Debug)]
pub(crate) struct FakeParent {
    addr: SocketAddr,
    response: Arc<Mutex<ParentResponse>>,
}

impl FakeParent {
    /// Start on an ephemeral port, serving no DS records yet.
    pub(crate) fn start() -> Self {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("failed to bind the fake parent");
        let addr = socket
            .local_addr()
            .expect("failed to read the fake parent's port");
        let response = Arc::new(Mutex::new(ParentResponse {
            records: Vec::new(),
            rcode: OptRcode::NOERROR,
            class: Class::IN,
        }));
        let served = Arc::clone(&response);

        thread::spawn(move || {
            let mut buffer = [0_u8; 4096];

            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buffer) else {
                    return;
                };
                let Ok(query) = Message::from_octets(&buffer[..len]) else {
                    continue;
                };
                let Ok(question) = query.sole_question() else {
                    continue;
                };
                let qname = question.qname().to_name::<Vec<u8>>();
                let response = served.lock().expect("parent response lock");
                let mut answer = MessageBuilder::new_vec()
                    .start_answer(&query, response.rcode.rcode())
                    .expect("start the answer");
                answer.header_mut().set_aa(true);
                let mut served_any = false;

                if question.qtype() == Rtype::DS {
                    for record in &response.records {
                        served_any = true;
                        answer
                            .push((
                                &qname,
                                response.class,
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
                            response.class,
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

                let mut additional = authority.additional();

                if let Some(opt) = query.opt() {
                    additional
                        .opt(|answer| {
                            answer.set_udp_payload_size(opt.udp_payload_size());
                            answer.set_rcode(response.rcode);
                            Ok(())
                        })
                        .expect("push response OPT");
                }

                let _ = socket.send_to(&additional.finish(), peer);
            }
        });

        Self { addr, response }
    }

    /// Return the parent address for zone configuration.
    pub(crate) fn addr(&self) -> String {
        self.addr.to_string()
    }

    /// Replace the DS records served.
    pub(crate) fn set_ds(&self, records: Vec<DsRecord>) {
        self.response.lock().expect("parent response lock").records = records;
    }

    /// Set response RCODE and record class, retaining DS records.
    pub(crate) fn set_response(&self, rcode: OptRcode, class: Class) {
        let mut response = self.response.lock().expect("parent response lock");
        response.rcode = rcode;
        response.class = class;
    }
}
