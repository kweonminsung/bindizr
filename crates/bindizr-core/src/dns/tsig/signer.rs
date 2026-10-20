//! Response signing and the MAC chain carried across transfer messages.

use domain::{
    base::{
        ToName,
        iana::{Class, TsigRcode},
        message_builder::{AdditionalBuilder, PushError},
        wire::Composer,
    },
    rdata::tsig::{Time48, Tsig},
    tsig::Key,
};
use ring::hmac;
use thiserror::Error;

use super::TsigSigningKey;

/// The response signature could not be appended to the DNS message.
#[derive(Debug, Error)]
#[error("failed to sign the response: {0}")]
pub struct SignResponseError(#[from] PushError);

/// The key and original request MAC needed to sign its response.
#[derive(Clone, Debug)]
pub struct ResponseSigner {
    pub(super) key: TsigSigningKey,
    pub(super) request_mac: Vec<u8>,
}

impl ResponseSigner {
    /// Sign one response with the suggested TSIG fudge (RFC 8945, Section 10).
    pub fn sign_response<T: Composer>(
        self,
        message: &mut AdditionalBuilder<T>,
        now: Time48,
    ) -> Result<(), SignResponseError> {
        self.sign_response_with_fudge(message, now, 300)
    }

    /// Sign one response with the caller's accepted clock tolerance.
    pub fn sign_response_with_fudge<T: Composer>(
        self,
        message: &mut AdditionalBuilder<T>,
        now: Time48,
        fudge: u16,
    ) -> Result<(), SignResponseError> {
        TransferSigner::from(self).sign_response_with_fudge(message, now, fudge)
    }

    /// The key whose name and algorithm the response carries.
    pub fn key(&self) -> &Key {
        self.key.as_ref()
    }
}

/// One transfer's key and previous MAC (RFC 8945, Section 5.3.1).
#[derive(Clone, Debug)]
pub struct TransferSigner {
    key: TsigSigningKey,
    previous_mac: Vec<u8>,
    first: bool,
}

impl From<ResponseSigner> for TransferSigner {
    /// Begin the response chain with the original request's MAC.
    fn from(signer: ResponseSigner) -> Self {
        Self {
            key: signer.key,
            previous_mac: signer.request_mac,
            first: true,
        }
    }
}

impl TransferSigner {
    /// Sign the next transfer message with the suggested TSIG fudge.
    pub fn sign_response<T: Composer>(
        &mut self,
        message: &mut AdditionalBuilder<T>,
        now: Time48,
    ) -> Result<(), SignResponseError> {
        self.sign_response_with_fudge(message, now, 300)
    }

    /// Advance the chain only after the signed record fits the builder.
    pub fn sign_response_with_fudge<T: Composer>(
        &mut self,
        message: &mut AdditionalBuilder<T>,
        now: Time48,
        fudge: u16,
    ) -> Result<(), SignResponseError> {
        let name = self.key.domain.name().to_canonical_name::<Vec<u8>>();
        let algorithm = self.key.domain.algorithm().to_name();
        let mut digest = hmac::Context::with_key(&self.key.hmac);
        digest.update(&(self.previous_mac.len() as u16).to_be_bytes());
        digest.update(&self.previous_mac);
        digest.update(message.as_slice());
        if self.first {
            digest.update(name.as_slice());
            digest.update(&Class::ANY.to_int().to_be_bytes());
            digest.update(&0u32.to_be_bytes());
            digest.update(algorithm.as_slice());
        }
        digest.update(&now.into_octets());
        digest.update(&fudge.to_be_bytes());
        if self.first {
            digest.update(&[0, 0, 0, 0]); // Error and Other Len.
        }
        let mac = digest.sign();
        message.push((
            &name,
            Class::ANY,
            0,
            Tsig::new(
                algorithm,
                now,
                fudge,
                mac.as_ref(),
                message.header().id(),
                TsigRcode::NOERROR,
                b"",
            )
            .expect("the HMAC and empty Other Data fit TSIG's u16 fields"),
        ))?;
        self.previous_mac = mac.as_ref().to_vec();
        self.first = false;
        Ok(())
    }

    /// The key used to size and identify the next signature.
    pub fn key(&self) -> &Key {
        self.key.as_ref()
    }
}
