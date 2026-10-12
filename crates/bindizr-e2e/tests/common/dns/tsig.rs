//! TSIG keys and request signing shared by DNS tests.

use std::str::FromStr;

use base64::Engine;
use domain::{
    base::{Message, Rtype, ToName, message_builder::AdditionalBuilder},
    rdata::tsig::{Time48, Tsig},
    tsig::{Algorithm, ClientTransaction, Key, KeyName},
};
use ring::hmac;

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
        self.to_tsig_key_with_mac_len(Algorithm::Sha256.native_len())
    }

    /// Construct a client key that emits the requested MAC length.
    pub(crate) fn to_tsig_key_with_mac_len(&self, mac_len: usize) -> Result<Key, String> {
        let secret = base64::engine::general_purpose::STANDARD
            .decode(&self.secret)
            .map_err(|e| format!("TSIG secret is not base64: {e}"))?;
        let key_name = KeyName::from_str(&self.name).map_err(|e| e.to_string())?;
        Key::new(Algorithm::Sha256, &secret, key_name, None, Some(mac_len))
            .map_err(|e| e.to_string())
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

/// Verify a response MAC from its wire fields, including BADTIME Other Data.
pub(crate) fn verify_response_mac(
    request: &[u8],
    response: &Message<Vec<u8>>,
    key: &SigningKey,
) -> Result<(), String> {
    let request = Message::from_octets(request).map_err(|e| e.to_string())?;
    let request_tsig = request
        .additional()
        .map_err(|e| e.to_string())?
        .limit_to::<Tsig<_, _>>()
        .last()
        .ok_or("request has no TSIG")?
        .map_err(|e| e.to_string())?;
    let tsig = response
        .additional()
        .map_err(|e| e.to_string())?
        .limit_to::<Tsig<_, _>>()
        .last()
        .ok_or("response has no TSIG")?
        .map_err(|e| e.to_string())?;
    let expected_key = key.to_tsig_key()?;
    if !tsig.owner().name_eq(expected_key.name())
        || !tsig
            .data()
            .algorithm()
            .name_eq(&expected_key.algorithm().to_name())
    {
        return Err("response uses a different TSIG key or algorithm".to_string());
    }
    let mut records = response.additional().map_err(|e| e.to_string())?;
    let tsig_start = loop {
        let start = records.pos();
        let record = records
            .next()
            .ok_or("response has no TSIG")?
            .map_err(|e| e.to_string())?;
        if record.rtype() == Rtype::TSIG {
            break start;
        }
    };
    if records.next().is_some() {
        return Err("TSIG must be the last record".to_string());
    }
    let data = tsig.data();
    let mut unsigned = response.as_slice()[..tsig_start].to_vec();
    unsigned[..2].copy_from_slice(&data.original_id().to_be_bytes());
    unsigned[10..12].copy_from_slice(&(response.header_counts().arcount() - 1).to_be_bytes());
    let request_mac = request_tsig.data().mac();
    let mut digest = u16::try_from(request_mac.len())
        .map_err(|e| e.to_string())?
        .to_be_bytes()
        .to_vec();
    digest.extend_from_slice(request_mac);
    digest.extend_from_slice(&unsigned);
    tsig.owner().compose_canonical(&mut digest).unwrap();
    digest.extend_from_slice(&tsig.class().to_int().to_be_bytes());
    digest.extend_from_slice(&tsig.ttl().as_secs().to_be_bytes());
    data.algorithm().compose_canonical(&mut digest).unwrap();
    digest.extend_from_slice(&data.time_signed().into_octets());
    digest.extend_from_slice(&data.fudge().to_be_bytes());
    digest.extend_from_slice(&data.error().to_int().to_be_bytes());
    digest.extend_from_slice(
        &u16::try_from(data.other().len())
            .map_err(|e| e.to_string())?
            .to_be_bytes(),
    );
    digest.extend_from_slice(data.other());
    let secret = base64::engine::general_purpose::STANDARD
        .decode(&key.secret)
        .map_err(|e| e.to_string())?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, &secret);
    hmac::verify(&key, &digest, data.mac()).map_err(|_| "response MAC did not verify".to_string())
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
            app.run_cli_success(&["role", "create", name], None).await;
            name
        }
    };
    app.run_cli_success(&["tsig-key", "create", name, "--role", role], None)
        .await;
    let fetched = app
        .run_cli_success(&["tsig-key", "get", name, "--output", "json"], None)
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
