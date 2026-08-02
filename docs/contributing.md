# Contributing

Help is welcome at any level — whether you are new to Rust or to DNS, or have
run BIND9 for twenty years. Fixing a typo, sharpening an error message, or
reporting something that confused you all count.

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

`cargo +nightly fmt` formats the code (the config uses nightly-only options),
and `cargo clippy --workspace` catches the rest.

## Editing these docs

The site is MkDocs Material, built from `docs/` in the main repository. With
[uv](https://docs.astral.sh/uv/) there is nothing to install or activate:

```bash
$ uv run --with-requirements docs/requirements.txt mkdocs serve
```

Or in a virtualenv, if you prefer:

```bash
$ pip install -r docs/requirements.txt
$ mkdocs serve
```

Use the pinned versions either way — CI builds with `--strict`, so a page that
renders against a different Material release can still fail the build.

Every page has an edit link in the top right that opens the corresponding file
on GitHub.

!!! note "`docs/openapi.yaml` is generated, not written"

    The API reference comes from the `#[utoipa::path]` annotations in
    `crates/bindizr/src/api/`. Change the annotations, then regenerate the spec
    from a debug build — never edit the YAML by hand.

## The rest

The full contributor guide — issue templates, pull-request conventions, and the
project rules a review will check against — lives in
[CONTRIBUTING.md](https://github.com/kweonminsung/bindizr/blob/main/CONTRIBUTING.md).
