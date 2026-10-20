use std::time::Duration;

use bindizr_core::dns::{
    message::Class,
    name::encode_name,
    record::{Rdata, SoaRecordValue},
};
use tokio::net::TcpListener;

use super::*;

/// Finish an outstanding transfer, then honor zero and expired keepalive timeouts.
#[tokio::test]
async fn fetch_zone_honors_keepalive_timeouts() {
    for (timeout, final_timeout, idle, expected_reuse) in [
        (None, None, 0, true),
        (Some(20u16), None, 0, true),
        (Some(1), None, 150, false),
        (Some(0), None, 0, false),
        (Some(0), Some(20), 0, false),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (idle_closed, idle_observed) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut reused = false;
            let mut idle_closed = Some(idle_closed);
            for transfer in 0..2 {
                let query = if transfer == 0 {
                    crate::dns_client::read_tcp_message(&mut stream)
                        .await
                        .unwrap()
                } else if idle != 0 {
                    assert!(
                        tokio::time::timeout(
                            Duration::from_secs(1),
                            crate::dns_client::read_tcp_message(&mut stream)
                        )
                        .await
                        .unwrap()
                        .is_err()
                    );
                    idle_closed.take().unwrap().send(()).unwrap();
                    stream = listener.accept().await.unwrap().0;
                    crate::dns_client::read_tcp_message(&mut stream)
                        .await
                        .unwrap()
                } else {
                    tokio::select! {
                        query = crate::dns_client::read_tcp_message(&mut stream) => match query {
                            Ok(query) => { reused = true; query },
                            Err(_) => {
                                let (next, _) = listener.accept().await.unwrap();
                                stream = next;
                                crate::dns_client::read_tcp_message(&mut stream).await.unwrap()
                            }
                        },
                        accepted = listener.accept() => {
                            stream = accepted.unwrap().0;
                            crate::dns_client::read_tcp_message(&mut stream).await.unwrap()
                        }
                    }
                };
                let question_end = 12 + encode_name("example.com.").unwrap().len() + 4;
                let soa = SoaRecordValue {
                    mname: "ns.example.com.",
                    rname: "admin.example.com.",
                    serial: 1,
                    refresh: 1,
                    retry: 1,
                    expire: 1,
                    minimum: 1,
                }
                .to_rdata()
                .unwrap();
                for keepalive in [timeout, final_timeout] {
                    let mut response = query[..question_end].to_vec();
                    response[2..4].copy_from_slice(&0x8400u16.to_be_bytes());
                    response[6..8].copy_from_slice(&1u16.to_be_bytes());
                    response[10..12].copy_from_slice(&1u16.to_be_bytes());
                    response.extend_from_slice(&encode_name("example.com.").unwrap());
                    response.extend_from_slice(&[0, 6, 0, 1, 0, 0, 1, 44]);
                    response.extend_from_slice(&(soa.as_bytes().len() as u16).to_be_bytes());
                    response.extend_from_slice(soa.as_bytes());
                    response.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0]);
                    response.extend_from_slice(
                        &(if keepalive.is_some() { 6u16 } else { 0 }).to_be_bytes(),
                    );
                    if let Some(timeout) = keepalive {
                        response.extend_from_slice(&[0, 11, 0, 2]);
                        response.extend_from_slice(&timeout.to_be_bytes());
                    }
                    stream
                        .write_all(&encode_tcp_message(&response).unwrap())
                        .await
                        .unwrap();
                }
            }
            reused
        });
        let mut client = AxfrClient::new(&addr.to_string());
        let zone = ZoneName::parse("example.com").unwrap();
        assert_eq!(
            client
                .fetch_zone(&zone, &ImportConfig::default())
                .await
                .unwrap()
                .len(),
            2
        );
        if idle != 0 {
            idle_observed.await.unwrap();
        }
        assert_eq!(
            client
                .fetch_zone(&zone, &ImportConfig::default())
                .await
                .unwrap()
                .len(),
            2
        );
        let reused = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            reused, expected_reuse,
            "timeout={timeout:?}, final={final_timeout:?}, idle={idle}"
        );
    }
}

async fn fetch_transfer(
    opening: Rdata,
    closing: Rdata,
) -> Result<Vec<TransferRecord>, FetchZoneError> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let query = crate::dns_client::read_tcp_message(&mut stream)
            .await
            .unwrap();
        // The query carries an OPT; the reply copies its question alone:
        // the header, the name, then QTYPE and QCLASS.
        let question_end = 12 + encode_name("example.com.").unwrap().len() + 4;
        for (index, rdata) in [opening, closing].iter().enumerate() {
            let mut response = if index == 0 {
                query[..question_end].to_vec()
            } else {
                let mut header = query[..12].to_vec();
                header[4..6].copy_from_slice(&0u16.to_be_bytes());
                header
            };
            response[10..12].copy_from_slice(&0u16.to_be_bytes());
            response[2..4].copy_from_slice(&0x8400u16.to_be_bytes());
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&encode_name("example.com.").unwrap());
            response.extend_from_slice(&Rtype::SOA.to_int().to_be_bytes());
            response.extend_from_slice(&Class::IN.to_int().to_be_bytes());
            response.extend_from_slice(&300u32.to_be_bytes());
            response
                .extend_from_slice(&u16::try_from(rdata.as_bytes().len()).unwrap().to_be_bytes());
            response.extend_from_slice(rdata.as_bytes());
            stream
                .write_all(&encode_tcp_message(&response).unwrap())
                .await
                .unwrap();
        }
    });
    let qname = "example.com.".parse().unwrap();
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        fetch_zone_on_stream(&mut stream, &qname, 2),
    )
    .await
    .expect("AXFR did not complete");
    server.await.unwrap();
    result.map(|(records, _)| records)
}

#[tokio::test]
async fn fetch_zone_accepts_case_varied_closing_soa_and_preserves_rdata() {
    let opening = SoaRecordValue {
        mname: "NS1.Example.COM.",
        rname: "Hostmaster.Example.COM.",
        serial: 42,
        refresh: 7200,
        retry: 3600,
        expire: 604800,
        minimum: 300,
    };
    for (mname, rname) in [
        ("ns1.example.com.", opening.rname),
        (opening.mname, "hostmaster.example.com."),
        ("ns1.example.com.", "hostmaster.example.com."),
    ] {
        let opening_rdata = opening.to_rdata().unwrap();
        let closing_rdata = SoaRecordValue {
            mname,
            rname,
            ..opening
        }
        .to_rdata()
        .unwrap();
        let records = fetch_transfer(opening_rdata.clone(), closing_rdata.clone())
            .await
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].rdata, opening_rdata);
        assert_eq!(records[1].rdata, closing_rdata);
    }
}

#[tokio::test]
async fn fetch_zone_rejects_changed_closing_soa() {
    let opening = SoaRecordValue {
        mname: "ns1.example.com.",
        rname: "hostmaster.example.com.",
        serial: 42,
        refresh: 7200,
        retry: 3600,
        expire: 604800,
        minimum: 300,
    };
    for closing in [
        SoaRecordValue {
            mname: "ns2.example.com.",
            ..opening
        },
        SoaRecordValue {
            rname: "other.example.com.",
            ..opening
        },
        SoaRecordValue {
            serial: 43,
            ..opening
        },
        SoaRecordValue {
            refresh: 7201,
            ..opening
        },
        SoaRecordValue {
            retry: 3601,
            ..opening
        },
        SoaRecordValue {
            expire: 604801,
            ..opening
        },
        SoaRecordValue {
            minimum: 301,
            ..opening
        },
    ] {
        let result = fetch_transfer(opening.to_rdata().unwrap(), closing.to_rdata().unwrap()).await;
        assert!(
            matches!(result, Err(FetchZoneError::ForeignClosingSoa)),
            "{closing:?}: {result:?}"
        );
    }
}
