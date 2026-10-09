//! The certificate a TLS listener presents: read from the configured PEM
//! pair at startup and re-read on reload, so a renewal needs no restart.

use std::sync::{Arc, PoisonError, RwLock};

use bindizr_core::config::{Config, TlsFiles};
use rustls::{
    crypto::ring,
    pki_types::{
        CertificateDer, PrivateKeyDer,
        pem::{self, PemObject},
    },
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use thiserror::Error;

/// Why the configured PEM pair presents no certificate.
#[derive(Debug, Error)]
pub(crate) enum LoadCertificateError {
    #[error("failed to read the certificate chain '{path}': {source}")]
    Certificate {
        path: String,
        #[source]
        source: pem::Error,
    },
    #[error("failed to read the private key '{path}': {source}")]
    PrivateKey {
        path: String,
        #[source]
        source: pem::Error,
    },
    #[error("the certificate '{cert_file}' and key '{key_file}' make no TLS server: {source}")]
    Pair {
        cert_file: String,
        key_file: String,
        #[source]
        source: rustls::Error,
    },
}

/// The certificate one listener presents, swapped in place when its pair is
/// re-read.
#[derive(Debug)]
pub(crate) struct TlsCertificate {
    certified: RwLock<Arc<CertifiedKey>>,
}

impl TlsCertificate {
    /// Read the pair the listener starts with.
    pub(crate) fn load(files: TlsFiles<'_>) -> Result<Arc<Self>, LoadCertificateError> {
        Ok(Arc::new(Self {
            certified: RwLock::new(Arc::new(load_certified_key(files)?)),
        }))
    }

    /// Present `next` from now on; `true` when the certificate changed.
    fn swap(&self, next: CertifiedKey) -> bool {
        let next = Arc::new(next);
        let mut current = self
            .certified
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let changed = current.cert != next.cert;
        *current = next;
        changed
    }
}

impl ResolvesServerCert for TlsCertificate {
    /// Present the current certificate to every handshake.
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(
            self.certified
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        )
    }
}

/// Read the PEM pair into the key a handshake signs with, checked against
/// its certificate.
fn load_certified_key(files: TlsFiles<'_>) -> Result<CertifiedKey, LoadCertificateError> {
    let certs = CertificateDer::pem_file_iter(files.cert_file)
        .and_then(|chain| chain.collect::<Result<Vec<_>, _>>())
        .map_err(|source| LoadCertificateError::Certificate {
            path: files.cert_file.to_string(),
            source,
        })?;
    let key = PrivateKeyDer::from_pem_file(files.key_file).map_err(|source| {
        LoadCertificateError::PrivateKey {
            path: files.key_file.to_string(),
            source,
        }
    })?;
    CertifiedKey::from_der(certs, key, &ring::default_provider()).map_err(|source| {
        LoadCertificateError::Pair {
            cert_file: files.cert_file.to_string(),
            key_file: files.key_file.to_string(),
            source,
        }
    })
}

/// The certificates the daemon's TLS listeners present.
#[derive(Debug, Clone)]
pub(crate) struct TlsCertificates {
    pub(crate) api: Option<Arc<TlsCertificate>>,
    pub(crate) dns: Option<Arc<TlsCertificate>>,
}

impl TlsCertificates {
    /// Read the pairs the configuration names.
    pub(crate) fn load(config: &Config) -> Result<Self, LoadCertificateError> {
        Ok(Self {
            api: config
                .api
                .tls
                .tls_files()
                .map(TlsCertificate::load)
                .transpose()?,
            dns: config
                .dns
                .tls
                .tls_files()
                .map(TlsCertificate::load)
                .transpose()?,
        })
    }

    /// Re-read the pairs, naming the listeners whose certificate changed.
    /// Both are read before either is presented, so one that fails leaves
    /// each listener as it was.
    pub(crate) fn reload(&self, config: &Config) -> Result<Vec<String>, LoadCertificateError> {
        let mut renewed = Vec::new();
        for (section, certificate, files) in [
            ("api.tls", &self.api, config.api.tls.tls_files()),
            ("dns.tls", &self.dns, config.dns.tls.tls_files()),
        ] {
            if let (Some(certificate), Some(files)) = (certificate, files) {
                renewed.push((section, certificate, load_certified_key(files)?));
            }
        }
        let mut changed = Vec::new();
        for (section, certificate, next) in renewed {
            if certificate.swap(next) {
                changed.push(format!("{section} certificate"));
            }
        }
        Ok(changed)
    }
}
