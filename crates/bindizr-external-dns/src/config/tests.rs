use std::iter;

use super::*;

/// Build the `Cli` a configuration test starts from, panicking on a parse failure.
fn to_cli(args: &[&str]) -> Cli {
    Cli::try_parse_from(iter::once("bindizr-external-dns").chain(args.iter().copied())).unwrap()
}

/// Verify that listener defaults to localhost only.
#[test]
fn listener_defaults_to_loopback() {
    let cli = to_cli(&["--bindizr-url", "http://bindizr:8000"]);
    assert_eq!(cli.listen_addr.to_string(), "127.0.0.1:8888");
    assert_eq!(cli.health_listen_addr.to_string(), "0.0.0.0:8080");
    // Below external-dns's 10s webhook write deadline, so a stalled
    // upstream still maps to a 502 the caller can receive.
    assert_eq!(cli.timeout_secs, 8);
}

/// Verify that configuration normalizes the base URL and requires an HTTP scheme.
#[test]
fn config_normalizes_url_and_requires_http_scheme() {
    let config = AdapterConfig::load(to_cli(&["--bindizr-url", "http://bindizr:8000/"])).unwrap();
    assert_eq!(config.bindizr_url.to_string(), "http://bindizr:8000");
    assert_eq!(
        config
            .bindizr_url
            .to_request_url("/external-dns/domains")
            .as_str(),
        "http://bindizr:8000/external-dns/domains"
    );
    assert!(config.token.is_none());

    assert!(AdapterConfig::load(to_cli(&["--bindizr-url", "bindizr:8000"])).is_err());
}

/// Verify that configuration rejects unusable base URLs and retains a valid prefix.
#[test]
fn config_rejects_unusable_base_urls() {
    for url in [
        "https://bad host",
        "http://",
        "http://bindizr:8000?tls=off",
        "http://bindizr:8000#api",
    ] {
        assert!(
            AdapterConfig::load(to_cli(&["--bindizr-url", url])).is_err(),
            "accepted '{url}'"
        );
    }

    let config = AdapterConfig::load(to_cli(&[
        "--bindizr-url",
        " http://bindizr:8000/api%2Fprefix// ",
    ]))
    .unwrap();

    assert_eq!(
        config
            .bindizr_url
            .to_request_url("/external-dns/domains")
            .as_str(),
        "http://bindizr:8000/api%2Fprefix/external-dns/domains"
    );
}

/// Verify that rejected URLs leave no raw input in either error formatter.
#[test]
fn config_url_errors_omit_sensitive_input() {
    for (url, expected) in [
        ("ftp://dummy-url-secret@bindizr", "must start with http"),
        ("http://dummy-url-secret@[invalid", "invalid IPv6 address"),
        (
            "http://dummy-user:dummy-url-secret@bindizr",
            "must not carry user information",
        ),
        (
            "http://@bindizr/dummy-url-secret",
            "must not carry user information",
        ),
        (
            "http://\t/@bindizr/dummy-url-secret",
            "must not carry user information",
        ),
        (
            "http://bindizr?token=dummy-url-secret",
            "must not carry a query or fragment",
        ),
        (
            "http://bindizr#dummy-url-secret",
            "must not carry a query or fragment",
        ),
    ] {
        let error = AdapterConfig::load(to_cli(&["--bindizr-url", url])).unwrap_err();
        assert!(matches!(error, LoadAdapterConfigError::Url(_)));
        assert!(error.to_string().contains(expected), "{error}");
        for diagnostic in [
            error.to_string(),
            format!("{error:?}"),
            format!("{:#?}", (&error,)),
        ] {
            assert!(!diagnostic.contains("dummy-url-secret"), "{diagnostic}");
            assert!(!diagnostic.contains("dummy-user"), "{diagnostic}");
        }
    }
}

/// Verify that Debug and the startup URL display omit configured secrets.
#[test]
fn config_diagnostics_omit_url_path_and_token() {
    let cli = to_cli(&[
        "--bindizr-url",
        "https://bindizr:8000/dummy-path-secret",
        "--token",
        "dummy-api-token",
    ]);
    let cli_debug = format!("{cli:?} {cli:#?}");
    let config = AdapterConfig::load(cli).unwrap();
    let diagnostics = format!("{cli_debug} {config:?} {config:#?} {}", config.bindizr_url);
    assert!(diagnostics.contains("https://bindizr:8000"));
    assert!(!diagnostics.contains("dummy-path-secret"));
    assert!(!diagnostics.contains("dummy-api-token"));
}

/// Verify that token file takes precedence and is trimmed.
#[test]
fn config_prefers_trimmed_token_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("token");
    fs::write(&path, "secret-token\n").unwrap();

    let config = AdapterConfig::load(to_cli(&[
        "--bindizr-url",
        "http://bindizr:8000",
        "--token",
        "inline-token",
        "--token-file",
        path.to_str().unwrap(),
    ]))
    .unwrap();

    assert_eq!(
        config.token.as_ref().map(RedactedString::as_str),
        Some("secret-token")
    );
}

/// Verify that missing token resolves to none.
#[test]
fn config_returns_no_token_when_unspecified() {
    let config = AdapterConfig::load(to_cli(&[
        "--bindizr-url",
        "http://bindizr:8000",
        "--token",
        "",
    ]))
    .unwrap();

    assert!(config.token.is_none());
}
