//! Helpers shared by the DNS UPDATE scenarios.

use domain::base::Rtype;
use reqwest::{Method, StatusCode};

use crate::common::{TestApp, TestAppOptions};

/// Start a local daemon accepting unsigned DNS updates.
pub(crate) async fn unsigned_nsupdate_app() -> TestApp {
    TestApp::start_with_options(TestAppOptions {
        nsupdate_tsig_required: false,
        ..TestAppOptions::default()
    })
    .await
}

/// Read published RRsets with an independent zone-file parser.
pub(crate) async fn exported_record_sets(
    app: &TestApp,
    zone_name: &str,
) -> std::collections::BTreeMap<(String, Rtype), Vec<Vec<u8>>> {
    use domain::{
        base::rdata::ComposeRecordData,
        zonefile::inplace::{Entry, Zonefile},
    };

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/zones/{zone_name}/export?signed=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut file = Zonefile::new();
    file.extend_from_slice(body.as_str().unwrap().as_bytes());
    let mut sets = std::collections::BTreeMap::<_, Vec<_>>::new();
    while let Some(entry) = file.next_entry().unwrap() {
        if let Entry::Record(record) = entry {
            let name = format!("{}.", record.owner().to_string().trim_end_matches('.'));
            let mut rdata = Vec::new();
            let Ok(()) = record.data().compose_rdata(&mut rdata);
            sets.entry((name, record.rtype())).or_default().push(rdata);
        }
    }
    sets
}
