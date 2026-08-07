# Changelog

## Unreleased

### Security

- upgraded `wasmtime` and `wasmtime-wasi` to the patched 46.0.2 release line
- made zizmor findings fail the security workflow instead of being suppressed
- pinned third-party GitHub Actions and the pgvector CI image by immutable digest
- consolidated cargo-audit policy into `.cargo/audit.toml`
- removed obsolete advisory exceptions and documented the remaining lockfile-only exception
- removed committed development database credentials from CI and Compose configuration

### Changed

- corrected repository badges and links for `BlueDot-IT/DemonClaw`
- updated the architecture specification to the implemented 1.0 runtime
- added idempotent GitHub Release publication for existing version tags

## 1.0.0 - 2026-04-20

Spec-complete release.

### Fixed

- memory optimizer maintenance no longer emits invalid REINDEX SQL during runtime
- runtime schema initialization now uses the non-macro SQLx migrator API
- release metadata updated for the 1.0.0 launch

### Validation

- `cargo test --all` passing
- `cargo fmt --all -- --check` passing
- `cargo clippy --all-targets --all-features -- -D warnings` passing
- `cargo audit` clean with the repository audit policy
- runtime smoke verified with `/healthz` and `POST /ingest`

## 0.1.0 - 2026-04-20

First stable release.

### Fixed

- memory optimizer maintenance no longer emits invalid REINDEX SQL during runtime
- runtime schema initialization now uses the non-macro SQLx migrator API
- release metadata updated for the 0.1.0 launch

### Validation

- `cargo test --all` passing
- runtime smoke verified with `/healthz` and `POST /ingest`

## 0.1.0-rc1 - 2026-04-13

Release candidate prepared for the first tagged release.

### Added

- centralized runtime configuration with environment overrides and an optional config file
- AgentLoop lifecycle events and structured evidence recording
- payload concurrency control
- interval scheduling and basic cron scheduling
- deterministic local SignalGate fallback for core directives
- end-to-end acceptance test coverage for payload-to-evidence flow
- release-facing README refresh

### Improved

- main runtime wiring and subsystem initialization
- integration test behavior in database-optional local environments
- documentation clarity around release state and feature coverage

### Validation

- `cargo test` passing
- CI configured for formatting, Clippy, and test runs with pgvector
