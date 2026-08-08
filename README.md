<p align="center">
  <img src="assets/banner_1600x400.png" alt="DemonClaw banner" width="100%" />
</p>

# DemonClaw

<p align="center">
  <a href="https://github.com/BlueDot-IT/DemonClaw/actions/workflows/ci.yml">
    <img src="https://github.com/BlueDot-IT/DemonClaw/actions/workflows/ci.yml/badge.svg" alt="CI" />
  </a>
  <a href="https://github.com/BlueDot-IT/DemonClaw/actions/workflows/security.yml">
    <img src="https://github.com/BlueDot-IT/DemonClaw/actions/workflows/security.yml/badge.svg" alt="Security" />
  </a>
  <a href="https://github.com/BlueDot-IT/DemonClaw/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT" />
  </a>
  <a href="https://www.rust-lang.org">
    <img src="https://img.shields.io/badge/rust-stable-orange.svg" alt="Rust" />
  </a>
  <a href="https://github.com/BlueDot-IT/DemonClaw/releases/tag/v1.1.0">
    <img src="https://img.shields.io/badge/release-v1.1.0-blue.svg" alt="Release v1.1.0" />
  </a>
</p>

DemonClaw is a Rust-native, security-focused agent runtime for controlled purple-team operations, defensive validation, and tamper-evident evidence collection.

It combines policy-gated orchestration, capability-scoped WASM execution, semantic routing, persistent PostgreSQL and pgvector memory, and explicit approval boundaries. It is not intended to be an unsupervised offensive platform.

## Release status

The current release is `v1.1.0`.

Implemented runtime surfaces include:

- SignalGate semantic routing with deterministic local fallback
- GhostMCP approval checks for sensitive actions
- WASM payload scanning and constrained execution
- PostgreSQL and pgvector semantic memory
- hash-linked Evidence Locker records
- interval and five-field cron scheduling
- active-defense command routing
- HTTP ingestion, JSON APIs, SSE events, and a server-rendered dashboard
- end-to-end acceptance coverage

## Architecture

The main subsystems are:

- `Channels`: REPL and HTTP ingestion, dashboard routes, JSON APIs, body limits, optional token authentication, rate limiting, and SSE delivery
- `AgentLoop`: intent routing, lifecycle state transitions, concurrency control, and evidence recording
- `SignalGate`: local and upstream intent classification
- `SecurityPolicy`: engagement, target, CIDR, domain, port, and tool-level controls
- `GhostMCP`: approval and secret-injection boundary
- `Payload Scanner`: pre-execution WASM validation
- `Sandbox`: Wasmtime-based execution with explicit HTTP and executable allowlists, fuel limits, and enforced epoch timeouts
- `MemoryManager`: PostgreSQL, pgvector, full-text retrieval, and maintenance
- `EvidenceLocker`: hash-linked audit records and chain verification
- `Scheduler`: interval and cron-driven envelope injection
- `Active Defense`: controlled scan, verification, and remediation workflows

See `SPEC.md` for the implemented architecture and security invariants. See `CONFIG.md` for runtime configuration.

## HTTP surfaces

The default listener is `127.0.0.1:3000`, and ingest authentication is enabled by default. Dashboard and read APIs still require an authenticated reverse proxy or another restricted deployment boundary when exposed remotely.

Stable operator API endpoints:

- `POST /api/v1/ingest`
- `GET /api/v1/status`
- `GET /api/v1/targets`
- `GET /api/v1/findings`
- `GET /api/v1/evidence`
- `GET /api/v1/evidence/verify`
- `GET /api/v1/policy`
- `GET /api/v1/events/stream`
- `GET /api/v1/memory/search?q=...`

`GET /healthz` and `/dashboard/*` are operational surfaces outside the versioned API. The older unversioned `/api/*` routes remain 1.1 compatibility aliases but new integrations should use `/api/v1/*`.

## Operator CLI

DemonClaw now exposes a supported operator CLI instead of requiring raw internal envelope commands:

```bash
demonclaw init
demonclaw migrate
demonclaw doctor
demonclaw target add web-01 --ssh admin@10.0.0.20 --tag production
demonclaw defend baseline web-01
demonclaw scan vuln web-01
demonclaw findings list
```

The daemon remains available with `demonclaw run`. CLI security operations submit authenticated commands to the local daemon after resolving the registered target.

## Installation

### Release bundle

Download the release archive for `linux-x86_64` or `linux-aarch64`, verify its adjacent SHA-256 file and GitHub provenance, extract it, then run:

```bash
sudo ./packaging/install.sh
```

Each release also publishes an SPDX JSON SBOM. GitHub provenance can be verified with:

```bash
gh attestation verify demonclaw-1.1.0-linux-x86_64.tar.gz -R BlueDot-IT/DemonClaw
```

The installer does not create secrets or start the service. Follow the printed steps to populate `/etc/demonclaw/demonclaw.env`, migrate, run `doctor`, and enable the service.

### Docker Compose

```bash
export POSTGRES_PASSWORD="$(openssl rand -hex 32)"
export DEMONCLAW_TOKEN="$(openssl rand -hex 32)"
docker compose up -d --build
docker compose exec demonclaw demonclaw doctor
```

The Compose deployment publishes both PostgreSQL and DemonClaw only on loopback. SSH keys are never mounted automatically; add an explicit read-only mount only when remote SSH targets require one.

See `SUPPORT.md`, `UPGRADING.md`, `SECURITY_MODEL.md`, and `docs/DEMO.md` before production deployment.

## Quick start

### 1. Start PostgreSQL and pgvector

Generate a development password in the current shell and start the database:

```bash
export POSTGRES_PASSWORD="$(openssl rand -hex 32)"
docker compose up -d
```

The compose file binds PostgreSQL to `127.0.0.1:5433` only.

### 2. Configure the runtime

```bash
export DATABASE_URL="postgres://postgres:${POSTGRES_PASSWORD}@127.0.0.1:5433/demonclaw"
export DEMONCLAW_INGEST_AUTH_ENABLED=1
export DEMONCLAW_TOKEN="$(openssl rand -hex 32)"
```

Provider credentials are optional unless the corresponding upstream feature is enabled:

```bash
export SIGNALGATE_API_KEY="<provider credential>"
export EMBEDDING_API_KEY="<provider credential>"
```

Do not commit `.env` files or credentials. `.env.example` contains names and safe defaults only.

### 3. Run DemonClaw

```bash
cargo run --locked -- run
```

### 4. Send an authenticated envelope

```bash
curl -s \
  -H 'content-type: application/json' \
  -H "x-demonclaw-token: ${DEMONCLAW_TOKEN}" \
  -d '{"content":"memory:compact"}' \
  http://127.0.0.1:3000/api/v1/ingest
```

## Testing

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all
cargo audit --file Cargo.lock
```

Database-backed tests use the pgvector service in CI. Local tests that require PostgreSQL need a reachable `DATABASE_URL`.

## Security policy

Security-sensitive operations are expected to pass through engagement checks, policy validation, GhostMCP approval, payload scanning, sandbox limits, and evidence recording.

The repository uses one canonical cargo-audit policy at `.cargo/audit.toml`. Every advisory exception must be documented in `SECURITY_EXCEPTIONS.md`.

Report vulnerabilities privately according to `.github/SECURITY.md`.

## Release and maintenance files

- `CHANGELOG.md`: release history
- `RELEASE_CHECKLIST.md`: release validation
- `SECURITY_EXCEPTIONS.md`: reviewed dependency-advisory exceptions
- `SECURITY_MODEL.md`: trust boundaries, guarantees, and explicit non-goals
- `SUPPORT.md`: production support and compatibility policy
- `UPGRADING.md`: forward-migration and rollback procedure
- `docs/DEMO.md`: reproducible operator demo
- `.github/workflows/release.yml`: native x86_64/arm64 release bundles and checksums

## License

DemonClaw is licensed under the MIT License. See `LICENSE`.

Built by BlueDot IT.
