//! The TLS side of XoT (RFC 9103): the server configuration the listener
//! accepts with, built once at startup from the configured PEM pair.

use std::sync::Arc;

use bindizr_core::config::TlsFiles;
use rustls::{
    ServerConfig,
    pki_types::{
        CertificateDer, PrivateKeyDer,
        pem::{self, PemObject},
    },
};
use thiserror::Error;

/// Why the configured PEM pair made no TLS server.
#[derive(Debug, Error)]
pub(crate) enum LoadServerConfigError {
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
    #[error("the certificate and key make no TLS server: {0}")]
    Config(#[source] rustls::Error),
}

/// Read the PEM pair and build the server configuration the XoT listener
/// accepts every connection with.
pub(crate) fn load_server_config(
    files: TlsFiles<'_>,
) -> Result<Arc<ServerConfig>, LoadServerConfigError> {
    let certs = CertificateDer::pem_file_iter(files.cert_file)
        .and_then(|chain| chain.collect::<Result<Vec<_>, _>>())
        .map_err(|source| LoadServerConfigError::Certificate {
            path: files.cert_file.to_string(),
            source,
        })?;
    let key = PrivateKeyDer::from_pem_file(files.key_file).map_err(|source| {
        LoadServerConfigError::PrivateKey {
            path: files.key_file.to_string(),
            source,
        }
    })?;

    // RFC 9103, Section 7.2: XoT uses TLS 1.3 or later and nothing older.
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(LoadServerConfigError::Config)?;
    // RFC 9103, Section 7.1: the handshake selects "dot". Other tokens alone
    // fail here; a client naming none is closed by the listener instead.
    config.alpn_protocols = vec![b"dot".to_vec()];
    Ok(Arc::new(config))
}
