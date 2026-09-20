//! Helpers the API scenarios share: a zone created under the caller's own
//! name, for the grant and key tests that have to spell it.

use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

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
                    "default_ttl": 3600,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }
}
