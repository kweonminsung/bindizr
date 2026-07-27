# Contributing to Bindizr

Thanks for your interest in improving Bindizr! Help is welcome at any level —
whether you are new to Rust or to DNS, or have run BIND9 for twenty years.

No contribution is too small. Fixing a typo in the docs, sharpening an error
message, or reporting something that confused you all count.

## Ways to help

- **Report a bug** — [open an issue](https://github.com/kweonminsung/bindizr/issues/new/choose).
  The Bindizr version, database backend, and a few log lines
  (`log_level = "debug"`) usually tell the whole story.
- **Suggest a feature** — open an issue and describe what you were trying to do.
- **Send a pull request** — small fixes can go straight to a PR. For anything
  larger, opening an issue first saves you from writing code twice.

## Getting started

You need Rust 1.85 or newer. Docker is only needed for the end-to-end tests and
the benchmark suite.

```bash
$ git clone https://github.com/kweonminsung/bindizr.git
$ cd bindizr
$ cargo build -p bindizr
$ cargo test --workspace --all-features -- --test-threads=1
```

Tests share process-wide state, so `--test-threads=1` is required — without it
they race and fail for reasons that have nothing to do with your change.

`cargo +nightly fmt` formats the code (the config uses nightly-only options), and
`cargo clippy --workspace` catches the rest.

## A few things worth knowing

- The three database backends under `crates/bindizr-db/src/repository/` are
  duplicated on purpose — the SQL dialects differ, and keeping them separate
  keeps each readable.
- Until the first stable release, Bindizr targets clean installs only, so there
  is no migration code and no compatibility shims. Breaking schema changes are
  fine for now — change the definition in place.
- Comments are for *why* something is done, especially where a protocol or RFC
  is behind it.

## Pull requests

Branch off `main`, and write commit messages in the style already in the history
(`feat:`, `fix:`, `docs:`, …). A test for new behavior is appreciated. Everything
else is a conversation, not a checklist — reviews are here to help, not to gate.

## License

By contributing, you agree that your work is licensed under the
[Apache License 2.0](LICENSE), the same as the rest of the project.
