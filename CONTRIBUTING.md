# Contributing to Bindizr

Thanks for your interest in improving Bindizr! Help is welcome at any level —
whether you are new to Rust or to DNS, or have run BIND9 for twenty years.

No contribution is too small. Fixing a typo in the docs, sharpening an error
message, or reporting something that confused you all count.

## Ways to help

- **Report a bug** — [open an issue](https://github.com/kweonminsung/bindizr/issues/new/choose).
  The Bindizr version, database backend, and a few log lines
  (`level = "debug"` under `[logging]`) usually tell the whole story.
- **Suggest a feature** — open an issue and describe what you were trying to do.
- **Send a pull request** — small fixes can go straight to a PR. For anything
  larger, opening an issue first saves you from writing code twice.

## Getting started

You need Rust 1.94 or newer and the native build dependencies — a C compiler,
pkg-config, and the OpenSSL headers — listed per platform in
[Building from Source](https://kweonminsung.github.io/bindizr/deployment/source/).
The end-to-end tests use temporary SQLite databases and local processes by
default; Docker is needed only to run them against database and BIND9 containers
(`BINDIZR_E2E_VERIFY_DNS=true`) and for the benchmark suite.

```bash
$ git clone https://github.com/kweonminsung/bindizr.git
$ cd bindizr
$ cargo build -p bindizr
$ cargo test --workspace --all-features -- --test-threads=1
```

Tests share process-wide state, so they run single-threaded: `.cargo/config.toml`
sets `RUST_TEST_THREADS=1`, and the explicit `--test-threads=1` spells out the
same guarantee.

`cargo +nightly fmt` formats the code (the config uses nightly-only options), and
`cargo clippy --workspace` catches the rest.

## A few things worth knowing

- The three database backends — `mysql/`, `postgres/`, and `sqlite/` under
  `crates/bindizr-db/src/` — are duplicated on purpose: the SQL dialects
  differ, and keeping them separate keeps each readable.
- Bindizr targets clean installs only and does not support upgrading an
  existing deployment, so there is no migration code and no compatibility
  shims. Breaking schema changes are fine — change the definition in place.
- Every named function carries a one-sentence purpose comment, private helpers
  and tests included. Beyond that, comments are for *why* something is done,
  especially where a protocol or RFC is behind it.

## Pull requests

Branch off `develop` and open the pull request against it, and write commit
messages in the style already in the history
(`feat:`, `fix:`, `docs:`, …). A test for new behavior is appreciated. Everything
else is a conversation, not a checklist — reviews are here to help, not to gate.

## License

By contributing, you agree that your work is licensed under the
[Apache License 2.0](LICENSE), the same as the rest of the project.
