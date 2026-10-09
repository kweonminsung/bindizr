//! The TLS side of XoT (RFC 9103): the server configuration the listener
//! accepts with, presenting the certificate the daemon re-reads on reload.

use std::sync::Arc;

use rustls::ServerConfig;

use crate::tls::TlsCertificate;

/// Build the server configuration the XoT listener accepts every connection
/// with.
pub(crate) fn build_server_config(certificate: Arc<TlsCertificate>) -> Arc<ServerConfig> {
    // RFC 9103, Section 7.2: XoT uses TLS 1.3 or later and nothing older.
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_cert_resolver(certificate);
    // RFC 9103, Section 7.1: the handshake selects "dot". Other tokens alone
    // fail here; a client naming none is closed by the listener instead.
    config.alpn_protocols = vec![b"dot".to_vec()];
    Arc::new(config)
}
