//! TSIG keys and request signing shared by DNS tests.

use std::str::FromStr;

use base64::Engine;
use domain::{
    base::{Message, Rtype, message_builder::AdditionalBuilder},
    rdata::tsig::Time48,
    tsig::{Algorithm, ClientTransaction, Key, KeyName},
};

use crate::common::TestApp;

/// Request signing key returned by `tsig-key get`.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Whether the response carries a TSIG record.
pub(crate) fn is_signed(response: &Message<Vec<u8>>) -> Result<bool, String> {
    Ok(response
        .additional()
        .map_err(|e| e.to_string())?
        .any(|record| record.is_ok_and(|record| record.rtype() == Rtype::TSIG)))
}

/// Sign a request using a client transaction.
pub(crate) fn sign(
    builder: &mut AdditionalBuilder<Vec<u8>>,
    key: &SigningKey,
) -> Result<(), String> {
    ClientTransaction::request(key.to_tsig_key()?, builder, Time48::now())
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// The role a test TSIG key authenticates into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyRole {
    /// The built-in `admin` role, reaching all zones.
    Admin,
    /// A fresh role named after the key, holding no grants until the test adds them.
    Own,
}

/// Create a TSIG key through the CLI and read back the secret it printed.
pub(crate) async fn create_tsig_key(app: &TestApp, name: &str, role: KeyRole) -> SigningKey {
    let role = match role {
        KeyRole::Admin => "admin",
        KeyRole::Own => {
            app.run_cli_success(&["role", "create", name]).await;
            name
        }
    };
    app.run_cli_success(&["tsig-key", "create", name, "--role", role])
        .await;
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
