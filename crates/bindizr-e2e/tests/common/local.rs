//! Local daemon startup with a temporary database and optional TLS, for the
//! API or the XoT listener, under one certificate generated for the run.

use std::{
    fs,
    io::Read,
    net::{TcpListener, UdpSocket},
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

use reqwest::{Client, StatusCode};
use rustls::pki_types::CertificateDer;

use super::{TestApp, TestAppOptions, TestRuntime, reserve_tcp_port, test_namespace};

impl TestApp {
    /// Start with non-default config; always the local runtime, because the
    /// compose stack's config is fixed.
    pub(crate) async fn start_with_options(options: TestAppOptions) -> Self {
        super::install_crypto_provider();
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let db_path = temp_dir.path().join("bindizr.sqlite");
        let config_path = temp_dir.path().join("bindizr.conf.toml");
        // One certificate serves both TLS listeners; none is written otherwise.
        let tls_cert =
            (options.tls || options.dns_tls).then(|| write_test_certificate(temp_dir.path()));
        let (scheme, client) = match (&tls_cert, options.tls) {
            (Some(cert), true) => ("https", tls_client(cert)),
            _ => ("http", Client::new()),
        };

        // A reserved port is released before the daemon binds it, so another
        // socket can take it in between; fresh ports and a retry cover that.
        let mut failures = Vec::new();
        for _ in 0..3 {
            let api_port = reserve_tcp_port();
            let dns_port = reserve_dns_port();
            let dns_tls_port = options.dns_tls.then(reserve_tcp_port);
            write_config(
                &config_path,
                api_port,
                dns_port,
                dns_tls_port,
                &db_path,
                &options,
            );

            let mut child = Command::new(env!("CARGO_BIN_EXE_bindizr-e2e-server"))
                .arg("start")
                .arg("-c")
                .arg(&config_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("failed to start bindizr binary");

            let base_url = format!("{scheme}://127.0.0.1:{api_port}");
            match wait_for_api(&client, &base_url, &mut child).await {
                Ok(()) => {
                    return Self {
                        runtime: TestRuntime::Local { temp_dir, child },
                        client,
                        base_url,
                        dns_port: Some(dns_port),
                        dns_tls_port,
                        tls_cert: tls_cert.clone(),
                        dns_secondary_ports: Vec::new(),
                        namespace: test_namespace(),
                        auth_token: None,
                    };
                }
                Err(failure) => failures.push(failure),
            }
        }

        panic!(
            "bindizr did not start:
{}",
            failures.join(
                "
---
"
            )
        );
    }
}

/// Find a local port available for both TCP and UDP DNS.
fn reserve_dns_port() -> u16 {
    for _ in 0..10 {
        let tcp =
            TcpListener::bind(("127.0.0.1", 0)).expect("failed to bind ephemeral DNS TCP port");
        let port = tcp
            .local_addr()
            .expect("failed to read ephemeral DNS TCP port")
            .port();

        if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }

    panic!("failed to reserve a DNS port available for both TCP and UDP");
}

/// A self-signed certificate for `127.0.0.1`, written beside the config as
/// `tls.crt`/`tls.key`; returns the certificate a client must trust to reach it.
fn write_test_certificate(dir: &Path) -> CertificateDer<'static> {
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("generate a test certificate");
    std::fs::write(dir.join("tls.crt"), certified.cert.pem()).expect("write tls.crt");
    std::fs::write(dir.join("tls.key"), certified.signing_key.serialize_pem())
        .expect("write tls.key");
    certified.cert.der().clone()
}

/// Build an HTTP client that trusts the test TLS certificate.
fn tls_client(cert: &CertificateDer<'static>) -> Client {
    Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_der(cert).expect("parse the test certificate"),
        )
        .build()
        .expect("build the TLS client")
}

/// Write a daemon configuration for the local test application.
fn write_config(
    config_path: &Path,
    api_port: u16,
    dns_port: u16,
    dns_tls_port: Option<u16>,
    db_path: &Path,
    options: &TestAppOptions,
) {
    // The certificate pair sits beside the config file.
    let dir = config_path
        .parent()
        .expect("config has a directory")
        .display();
    let config = format!(
        r#"
[api]
listen_addr = "127.0.0.1"
listen_port = {api_port}
authentication_required = {authentication_required}
external_dns_enabled = {external_dns_enabled}
openapi_enabled = {openapi_enabled}
{tls}

[database]
type = "sqlite"

[database.mysql]
url = ""

[database.sqlite]
file_path = "{}"

[database.postgresql]
url = ""

[dns]
listen_addr = "127.0.0.1"
listen_port = {dns_port}
{dns_tls}
{dns_transfer}

[dns.notify]
retries = 0
timeout_secs = 1

[dns.nsupdate]
tsig_required = {nsupdate_tsig_required}

[logging]
level = "error"
"#,
        db_path.display(),
        authentication_required = options.authentication_required,
        external_dns_enabled = options.external_dns_enabled,
        nsupdate_tsig_required = options.nsupdate_tsig_required,
        openapi_enabled = options.openapi_enabled,
        tls = match options.tls {
            true => {
                format!(
                    "\n[api.tls]\ncert_file = \"{dir}/tls.crt\"\nkey_file = \"{dir}/tls.key\"\n"
                )
            }
            false => String::new(),
        },
        dns_tls = match dns_tls_port {
            Some(port) => format!(
                "\n[dns.tls]\nlisten_port = {port}\ncert_file = \"{dir}/tls.crt\"\nkey_file = \"{dir}/tls.key\"\n"
            ),
            None => String::new(),
        },
        dns_transfer = match options.dns_transfer_require_tls {
            true => "\n[dns.transfer]\nrequire_tls = true\n",
            false => "",
        },
    );

    fs::write(config_path, config).expect("failed to write bindizr config");
}

/// Poll `/health` until the daemon answers; a failure carries the daemon's
/// stderr, the only place a daemon that dies before listening says why.
async fn wait_for_api(client: &Client, base_url: &str, child: &mut Child) -> Result<(), String> {
    // /health sits outside the auth layer, so readiness ignores
    // authentication_required.
    let health_url = format!("{base_url}/health");
    let mut attempts = 0;
    let failure = loop {
        if let Some(status) = child.try_wait().expect("failed to check child status") {
            break format!("bindizr exited before API was ready: {status}");
        }

        if let Ok(response) = client.get(&health_url).send().await
            && response.status() == StatusCode::OK
        {
            return Ok(());
        }

        attempts += 1;
        if attempts == 100 {
            let _ = child.kill();
            let _ = child.wait();
            break "bindizr API did not become ready".to_string();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    Err(format!("{failure}\n{stderr}"))
}

impl TestApp {
    /// Replace the run's certificate pair on disk, as a renewal does; returns
    /// the certificate a client trusts after `config reload`.
    pub(crate) fn renew_test_certificate(&self) -> CertificateDer<'static> {
        let TestRuntime::Local { temp_dir, .. } = &self.runtime else {
            panic!("the compose stack's certificate is fixed");
        };
        write_test_certificate(temp_dir.path())
    }
}

impl TestApp {
    /// Overwrite the run's private key with text no key parser reads, as a
    /// broken renewal does.
    pub(crate) fn corrupt_test_certificate(&self) {
        let TestRuntime::Local { temp_dir, .. } = &self.runtime else {
            panic!("the compose stack's certificate is fixed");
        };
        std::fs::write(temp_dir.path().join("tls.key"), "not a key").expect("write tls.key");
    }
}
