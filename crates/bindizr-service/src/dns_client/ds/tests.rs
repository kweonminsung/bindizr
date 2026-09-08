use std::{net::SocketAddr, sync::Arc, time::Duration};

use bindizr_core::dns::{name::ZoneName, query::DsRr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

use super::*;

const TIMEOUT: Duration = Duration::from_secs(2);
const FLAG_AA: u16 = 0x0400;
const FLAG_TC: u16 = 0x0200;
const RCODE_NXDOMAIN: u16 = 3;
const RTYPE_NS: u16 = 2;
const RTYPE_DS: u16 = 43;
const RTYPE_SOA: u16 = 6;

/// What a fake server answers to every question: DS records at the qname,
/// the same but truncated over UDP so only TCP carries them, NXDOMAIN, or
/// nothing at all.
#[derive(Clone)]
enum Answer {
    Ds { aa: bool, records: Vec<(u16, u32)> },
    DsTruncatedOverUdp { records: Vec<(u16, u32)> },
    Nxdomain,
    Silence,
}

fn encode_name(name: &str, buf: &mut Vec<u8>) {
    for label in name.split('.').filter(|label| !label.is_empty()) {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
}

/// The question's name in presentation form and the offset just past the
/// question section (the EDNS OPT record follows it in our queries).
fn decode_question(query: &[u8]) -> (String, usize) {
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let len = query[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        labels.push(String::from_utf8_lossy(&query[pos..pos + len]).into_owned());
        pos += len;
    }
    (labels.join("."), pos + 4)
}

/// A response echoing the query's id and question, with `flags` (QR is
/// always set) and `rcode`, whose answer section holds `answers` and whose
/// authority section holds `authority`.
fn build_response(
    query: &[u8],
    flags: u16,
    rcode: u16,
    answers: &[Vec<u8>],
    authority: &[Vec<u8>],
) -> Vec<u8> {
    let (_, question_end) = decode_question(query);
    let mut buf = Vec::new();
    buf.extend_from_slice(&query[0..2]);
    buf.extend_from_slice(&(0x8000 | flags | rcode).to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    buf.extend_from_slice(&(authority.len() as u16).to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&query[12..question_end]);
    for rr in answers.iter().chain(authority) {
        buf.extend_from_slice(rr);
    }
    buf
}

/// The SOA of the queried name's parent zone, as a negative answer's
/// authority section carries it.
fn parent_soa_rr(query: &[u8]) -> Vec<u8> {
    let (qname, _) = decode_question(query);
    let parent = qname.split_once('.').map_or("", |(_, rest)| rest);
    let mut rr = Vec::new();
    encode_name(parent, &mut rr);
    rr.extend_from_slice(&RTYPE_SOA.to_be_bytes());
    rr.extend_from_slice(&1u16.to_be_bytes());
    rr.extend_from_slice(&3600u32.to_be_bytes());
    let mut rdata = Vec::new();
    encode_name("ns.parent.example", &mut rdata);
    encode_name("hostmaster.parent.example", &mut rdata);
    for field in [1u32, 3600, 600, 86400, 300] {
        rdata.extend_from_slice(&field.to_be_bytes());
    }
    rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    rr.extend_from_slice(&rdata);
    rr
}

/// One answer RR owned by the question name (a pointer to offset 12).
fn build_rr(rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut buf = vec![0xC0, 0x0C];
    buf.extend_from_slice(&rtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&ttl.to_be_bytes());
    buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    buf.extend_from_slice(rdata);
    buf
}

fn ds_rr(key_tag: u16, ttl: u32) -> Vec<u8> {
    let mut rdata = key_tag.to_be_bytes().to_vec();
    rdata.extend_from_slice(&[13, 2]);
    rdata.extend_from_slice(&[0xab; 32]);
    build_rr(RTYPE_DS, ttl, &rdata)
}

/// The record `ds_rr` serves for `key_tag`, as the probe parses it.
fn parsed_ds_rr(key_tag: u16) -> DsRr {
    let mut rdata = key_tag.to_be_bytes().to_vec();
    rdata.extend_from_slice(&[13, 2]);
    rdata.extend_from_slice(&[0xab; 32]);
    DsRr { key_tag, rdata }
}

fn ns_rr(nsdname: &str) -> Vec<u8> {
    let mut rdata = Vec::new();
    encode_name(nsdname, &mut rdata);
    build_rr(RTYPE_NS, 3600, &rdata)
}

/// The whole answer to `query`, as TCP always carries it.
fn build_full_response(query: &[u8], answer: &Answer) -> Option<Vec<u8>> {
    let authority = [parent_soa_rr(query)];
    match answer {
        Answer::Silence => None,
        Answer::Nxdomain => Some(build_response(
            query,
            FLAG_AA,
            RCODE_NXDOMAIN,
            &[],
            &authority,
        )),
        Answer::Ds { aa, records } => {
            let answers: Vec<Vec<u8>> = records
                .iter()
                .map(|(key_tag, ttl)| ds_rr(*key_tag, *ttl))
                .collect();
            Some(build_response(
                query,
                if *aa { FLAG_AA } else { 0 },
                0,
                &answers,
                &authority,
            ))
        }
        Answer::DsTruncatedOverUdp { records } => {
            let answers: Vec<Vec<u8>> = records
                .iter()
                .map(|(key_tag, ttl)| ds_rr(*key_tag, *ttl))
                .collect();
            Some(build_response(query, FLAG_AA, 0, &answers, &authority))
        }
    }
}

/// A server answering every question with `answer` over UDP and TCP on one
/// port, until dropped.
async fn fake_server(answer: Answer) -> SocketAddr {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();
    let udp_answer = answer.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let query = &buf[..len];
            let response = match &udp_answer {
                Answer::DsTruncatedOverUdp { .. } => {
                    build_response(query, FLAG_AA | FLAG_TC, 0, &[], &[])
                }
                other => match build_full_response(query, other) {
                    Some(response) => response,
                    None => continue,
                },
            };
            let _ = socket.send_to(&response, peer).await;
        }
    });
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut prefix = [0u8; 2];
            if stream.read_exact(&mut prefix).await.is_err() {
                continue;
            }
            let mut query = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
            if stream.read_exact(&mut query).await.is_err() {
                continue;
            }
            let Some(response) = build_full_response(&query, &answer) else {
                continue;
            };
            let mut frame = (response.len() as u16).to_be_bytes().to_vec();
            frame.extend_from_slice(&response);
            let _ = stream.write_all(&frame).await;
        }
    });
    addr
}

/// A resolver whose NS answers depend on the qname: `example.com` and `com`
/// are zone apexes, every other name is NODATA.
async fn fake_resolver() -> SocketAddr {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let query = &buf[..len];
            let (qname, _) = decode_question(query);
            let names: &[&str] = match qname.as_str() {
                "example.com" => &["ns1.example.com", "ns2.example.com"],
                "com" => &["a.gtld-servers.net"],
                _ => &[],
            };
            let answers: Vec<Vec<u8>> = names.iter().map(|ns| ns_rr(ns)).collect();
            let _ = socket
                .send_to(&build_response(query, 0, 0, &answers, &[]), peer)
                .await;
        }
    });
    addr
}

fn zone_name(value: &str) -> ZoneName {
    ZoneName::parse(value).unwrap()
}

fn servers(addrs: &[SocketAddr]) -> Vec<(String, Vec<SocketAddr>)> {
    addrs
        .iter()
        .map(|addr| (addr.to_string(), vec![*addr]))
        .collect()
}

#[test]
fn parse_resolv_conf_reads_nameserver_lines() {
    let contents = "# generated\nsearch example.com\nnameserver 192.0.2.53 # primary\n\
                    nameserver 2001:db8::53\nnameserver fe80::1%en0\noptions ndots:1\n";
    assert_eq!(
        parse_resolv_conf(contents),
        vec![
            "192.0.2.53:53".parse::<SocketAddr>().unwrap(),
            "[2001:db8::53]:53".parse::<SocketAddr>().unwrap(),
        ]
    );
}

#[tokio::test]
async fn query_ds_reports_each_server_apart() {
    let a = fake_server(Answer::Ds {
        aa: true,
        records: vec![(34217, 3600)],
    })
    .await;
    let b = fake_server(Answer::Ds {
        aa: true,
        records: vec![(34217, 3600), (2371, 86400)],
    })
    .await;

    let answers = query_ds(&zone_name("example.com"), &servers(&[a, b]), TIMEOUT)
        .await
        .unwrap();
    assert_eq!(
        answers,
        vec![
            Some(DsRrset {
                records: vec![parsed_ds_rr(34217)],
                ttl: 3600,
            }),
            Some(DsRrset {
                records: vec![parsed_ds_rr(2371), parsed_ds_rr(34217)],
                ttl: 3600,
            }),
        ]
    );
}

#[tokio::test]
async fn query_ds_retries_a_truncated_answer_over_tcp() {
    let server = fake_server(Answer::DsTruncatedOverUdp {
        records: vec![(34217, 3600)],
    })
    .await;

    let answers = query_ds(&zone_name("example.com"), &servers(&[server]), TIMEOUT)
        .await
        .unwrap();
    assert_eq!(
        answers,
        vec![Some(DsRrset {
            records: vec![parsed_ds_rr(34217)],
            ttl: 3600,
        })]
    );
}

#[tokio::test]
async fn query_ds_reports_absence_per_server() {
    let absent = fake_server(Answer::Ds {
        aa: true,
        records: vec![],
    })
    .await;
    let nxdomain = fake_server(Answer::Nxdomain).await;
    let present = fake_server(Answer::Ds {
        aa: true,
        records: vec![(1, 300)],
    })
    .await;

    let answers = query_ds(
        &zone_name("example.com"),
        &servers(&[absent, nxdomain]),
        TIMEOUT,
    )
    .await
    .unwrap();
    assert_eq!(answers, vec![None, None]);

    // A lagging server still serving the DS stays visible to the caller.
    let answers = query_ds(
        &zone_name("example.com"),
        &servers(&[absent, present]),
        TIMEOUT,
    )
    .await
    .unwrap();
    assert_eq!(
        answers
            .iter()
            .map(|a| a.as_ref().map(DsRrset::key_tags))
            .collect::<Vec<_>>(),
        vec![None, Some(vec![1])]
    );
}

#[tokio::test]
async fn query_ds_fails_when_a_server_is_silent_or_not_authoritative() {
    let absent = fake_server(Answer::Ds {
        aa: true,
        records: vec![],
    })
    .await;
    let silent = fake_server(Answer::Silence).await;
    let err = query_ds(
        &zone_name("example.com"),
        &servers(&[absent, silent]),
        Duration::from_millis(200),
    )
    .await
    .unwrap_err();
    assert!(err.contains(&silent.to_string()), "{err}");
    assert!(err.contains("timeout"), "{err}");

    let cache = fake_server(Answer::Ds {
        aa: false,
        records: vec![],
    })
    .await;
    let err = query_ds(&zone_name("example.com"), &servers(&[cache]), TIMEOUT)
        .await
        .unwrap_err();
    assert!(err.contains("not authoritative"), "{err}");
}

#[tokio::test]
async fn query_ds_falls_through_to_the_next_address_of_a_server() {
    let silent = fake_server(Answer::Silence).await;
    let present = fake_server(Answer::Ds {
        aa: true,
        records: vec![(7, 60)],
    })
    .await;
    let servers = vec![("ns1.parent.example".to_string(), vec![silent, present])];
    let answers = query_ds(
        &zone_name("example.com"),
        &servers,
        Duration::from_millis(200),
    )
    .await
    .unwrap();
    assert_eq!(
        answers
            .iter()
            .map(|a| a.as_ref().map(DsRrset::key_tags))
            .collect::<Vec<_>>(),
        vec![Some(vec![7])]
    );
}

#[tokio::test]
async fn discover_parent_finds_the_closest_enclosing_zone() {
    let resolver = fake_resolver().await;

    // `child.example.com` is no zone apex, so the walk passes it and stops
    // at `example.com`.
    let (parent, nameservers) =
        discover_parent(&zone_name("sub.child.example.com"), &[resolver], TIMEOUT)
            .await
            .unwrap();
    assert_eq!(parent, "example.com");
    assert_eq!(nameservers, vec!["ns1.example.com.", "ns2.example.com."]);

    let (parent, nameservers) = discover_parent(&zone_name("example.com"), &[resolver], TIMEOUT)
        .await
        .unwrap();
    assert_eq!(parent, "com");
    assert_eq!(nameservers, vec!["a.gtld-servers.net."]);
}

#[tokio::test]
async fn discover_parent_tries_the_next_resolver_when_one_is_silent() {
    let silent = fake_server(Answer::Silence).await;
    let resolver = fake_resolver().await;

    let (parent, _) = discover_parent(
        &zone_name("example.com"),
        &[silent, resolver],
        Duration::from_millis(200),
    )
    .await
    .unwrap();
    assert_eq!(parent, "com");

    let err = discover_parent(
        &zone_name("example.com"),
        &[silent],
        Duration::from_millis(200),
    )
    .await
    .unwrap_err();
    assert!(err.contains("timeout"), "{err}");
}

#[tokio::test]
async fn discover_parent_fails_when_no_ancestor_has_nameservers() {
    let resolver = fake_server(Answer::Nxdomain).await;
    let err = discover_parent(&zone_name("example.org"), &[resolver], TIMEOUT)
        .await
        .unwrap_err();
    assert!(err.contains("no parent zone found"), "{err}");
}

#[tokio::test]
async fn resolve_parent_ns_addrs_rejects_an_unresolvable_entry() {
    let err = resolve_parent_ns_addrs("127.0.0.1:5353,nx.invalid", TIMEOUT)
        .await
        .unwrap_err();
    assert!(err.contains("nx.invalid"), "{err}");

    let servers = resolve_parent_ns_addrs("127.0.0.1:5353, 192.0.2.1", TIMEOUT)
        .await
        .unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[1].0, "192.0.2.1");
    assert_eq!(
        servers[1].1,
        vec!["192.0.2.1:53".parse::<SocketAddr>().unwrap()]
    );
}
