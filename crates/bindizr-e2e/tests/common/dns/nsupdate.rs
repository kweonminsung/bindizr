//! Building and sending RFC 2136 UPDATE messages, so the nsupdate path can be
//! driven without the BIND tools on the host.

use std::{net::UdpSocket, str::FromStr, time::Duration};

use base64::Engine;
use domain::{
    base::{
        Message, MessageBuilder, Name, Record, Rtype, Ttl, UnknownRecordData,
        iana::{Class, Opcode, Rcode},
        message_builder::AdditionalBuilder,
    },
    rdata::{A, tsig::Time48},
    tsig::{Algorithm, ClientTransaction, Key, KeyName},
};

use crate::common::{TestApp, dns::parse_name};

/// The key an update is signed with, as `tsig-key get` reports it.
pub(crate) struct SigningKey {
    pub(crate) name: String,
    pub(crate) secret: String,
}

impl SigningKey {
    /// Convert into the TSIG key `domain` signs and verifies with.
    pub(crate) fn to_tsig_key(&self) -> Result<Key, String> {
        let secret = base64::engine::general_purpose::STANDARD
            .decode(&self.secret)
            .map_err(|e| format!("TSIG secret is not base64: {e}"))?;
        let key_name = KeyName::from_str(&self.name).map_err(|e| e.to_string())?;
        Key::new(Algorithm::Sha256, &secret, key_name, None, None).map_err(|e| e.to_string())
    }
}

/// One record of an update section, in the class that gives it its meaning
/// (RFC 2136, Section 2.5).
pub(crate) enum UpdateRecord {
    /// CLASS IN: add this address record.
    AddA {
        name: String,
        ttl: u32,
        addr: String,
    },
    /// CLASS ANY: delete the record set.
    DeleteRecordSet { name: String, rtype: Rtype },
    /// CLASS NONE: delete just this address record.
    DeleteA { name: String, addr: String },
}

/// One prerequisite (RFC 2136, Section 2.4).
pub(crate) enum PrereqRecord {
    /// CLASS ANY, TYPE ANY: the owner name must exist.
    NameInUse { name: String },
    /// CLASS NONE, TYPE ANY: the owner name must not exist.
    NameNotInUse { name: String },
    /// CLASS IN, TTL 0: with the others of its name, these A values must be
    /// exactly the zone's (RFC 2136, Section 3.2.3).
    AEquals { name: String, addr: String },
}

/// Send an unsigned UPDATE for `zone` and return the response RCODE.
pub(crate) fn send_update(
    port: u16,
    zone: &str,
    prerequisites: &[PrereqRecord],
    updates: &[UpdateRecord],
) -> Result<Rcode, String> {
    send(port, zone, prerequisites, updates, None)
}

/// Send an UPDATE signed with `key`, as a real nsupdate client would.
pub(crate) fn send_signed_update(
    port: u16,
    zone: &str,
    prerequisites: &[PrereqRecord],
    updates: &[UpdateRecord],
    key: &SigningKey,
) -> Result<Rcode, String> {
    send(port, zone, prerequisites, updates, Some(key))
}

/// Send a dynamic update with optional TSIG and return the response code.
fn send(
    port: u16,
    zone: &str,
    prerequisites: &[PrereqRecord],
    updates: &[UpdateRecord],
    key: Option<&SigningKey>,
) -> Result<Rcode, String> {
    let query_id = (std::process::id() as u16)
        .wrapping_add(port)
        .wrapping_add(1);
    let mut builder = build_update(query_id, zone, prerequisites, updates)?;
    if let Some(key) = key {
        sign(&mut builder, key)?;
    }
    let message = builder.finish();

    let socket = UdpSocket::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    socket
        .send_to(&message, ("127.0.0.1", port))
        .map_err(|e| e.to_string())?;

    let mut response = [0_u8; 1500];
    let (len, _) = socket.recv_from(&mut response).map_err(|e| e.to_string())?;

    let message = Message::from_octets(&response[..len]).map_err(|e| e.to_string())?;
    if message.header().id() != query_id {
        return Err("UPDATE response id mismatch".to_string());
    }
    Ok(message.header().rcode())
}

/// An UPDATE message reuses the standard sections: the zone is the question,
/// the prerequisites are the answer, the updates are the authority
/// (RFC 2136, Section 2.1).
fn build_update(
    query_id: u16,
    zone: &str,
    prerequisites: &[PrereqRecord],
    updates: &[UpdateRecord],
) -> Result<AdditionalBuilder<Vec<u8>>, String> {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(query_id);
    builder.header_mut().set_opcode(Opcode::UPDATE);

    let mut question = builder.question();
    question
        .push((&parse_name(zone)?, Rtype::SOA, Class::IN))
        .map_err(|e| e.to_string())?;

    let mut answer = question.answer();
    for prerequisite in prerequisites {
        match prerequisite {
            PrereqRecord::NameInUse { name: owner } => answer
                .push(empty_record(owner, Rtype::ANY, Class::ANY)?)
                .map_err(|e| e.to_string())?,
            PrereqRecord::NameNotInUse { name: owner } => answer
                .push(empty_record(owner, Rtype::ANY, Class::NONE)?)
                .map_err(|e| e.to_string())?,
            PrereqRecord::AEquals { name: owner, addr } => {
                let data = A::from_str(addr).map_err(|e| e.to_string())?;
                answer
                    .push(Record::new(parse_name(owner)?, Class::IN, Ttl::ZERO, data))
                    .map_err(|e| e.to_string())?;
            }
        }
    }

    let mut authority = answer.authority();
    for update in updates {
        match update {
            UpdateRecord::AddA {
                name: owner,
                ttl,
                addr,
            } => {
                let data = A::from_str(addr).map_err(|e| e.to_string())?;
                authority
                    .push(Record::new(
                        parse_name(owner)?,
                        Class::IN,
                        Ttl::from_secs(*ttl),
                        data,
                    ))
                    .map_err(|e| e.to_string())?;
            }
            UpdateRecord::DeleteRecordSet { name: owner, rtype } => authority
                .push(empty_record(owner, *rtype, Class::ANY)?)
                .map_err(|e| e.to_string())?,
            UpdateRecord::DeleteA { name: owner, addr } => {
                let data = A::from_str(addr).map_err(|e| e.to_string())?;
                authority
                    .push(Record::new(
                        parse_name(owner)?,
                        Class::NONE,
                        Ttl::ZERO,
                        data,
                    ))
                    .map_err(|e| e.to_string())?;
            }
        }
    }

    // The TSIG, when there is one, goes in the additional section.
    Ok(authority.additional())
}

/// A record carrying no rdata, built from an rtype the builder need not know.
type EmptyRecord = Record<Name<Vec<u8>>, UnknownRecordData<Vec<u8>>>;

/// A record with empty rdata and TTL 0 — the shape every delete-record-set and
/// name-existence entry takes.
fn empty_record(owner: &str, rtype: Rtype, class: Class) -> Result<EmptyRecord, String> {
    let data = UnknownRecordData::from_octets(rtype, Vec::new()).map_err(|e| e.to_string())?;
    Ok(Record::new(parse_name(owner)?, class, Ttl::ZERO, data))
}

/// Append the request TSIG, the way `domain`'s client transaction does it.
fn sign(builder: &mut AdditionalBuilder<Vec<u8>>, key: &SigningKey) -> Result<(), String> {
    ClientTransaction::request(key.to_tsig_key()?, builder, Time48::now())
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Create a TSIG key through the CLI and read back the secret it printed,
/// global when asked so it reaches every zone without a grant.
pub(crate) async fn create_tsig_key(app: &TestApp, name: &str, global: bool) -> SigningKey {
    let mut args = vec!["tsig-key", "create", name];
    if global {
        args.push("--global");
    }
    app.run_cli_success(&args).await;
    let fetched = app
        .run_cli_success(&["tsig-key", "get", name, "--output", "json"])
        .await;
    let fetched: serde_json::Value =
        serde_json::from_str(&fetched).expect("tsig-key get did not print JSON");
    SigningKey {
        name: name.to_string(),
        secret: fetched["secret"]
            .as_str()
            .expect("tsig-key get prints the secret")
            .to_string(),
    }
}
