use std::time::Duration;

use bindizr_core::dns::{
    message::Class,
    name::encode_name,
    record::{Rdata, SoaRecordValue},
};
use tokio::net::TcpListener;

use super::*;

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
        for (index, rdata) in [opening, closing].iter().enumerate() {
            let mut response = if index == 0 {
                query.clone()
            } else {
                let mut header = query[..12].to_vec();
                header[4..6].copy_from_slice(&0u16.to_be_bytes());
                header
            };
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
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        fetch_zone_from_address(addr, &qname, 2),
    )
    .await
    .expect("AXFR did not complete");
    server.await.unwrap();
    result
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
