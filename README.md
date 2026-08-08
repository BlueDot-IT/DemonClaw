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
  <a href="https://github.com/BlueDot-IT/DemonClaw/releases/tag/v1.0.0">
    <img src="https://img.shields.io/badge/release-v1.0.0-blue.svg" alt="Release v1.0.0" />
  </a>
</p>

DemonClaw is a Rust-native, security-focused agent runtime for controlled purple-team operations, defensive validation, and tamper-evident evidence collection.

It combines policy-gated orchestration, capability-scoped WASM execution, semantic routing, persistent PostgreSQL and pgvector memory, and explicit approval boundaries. It is not intended to be an unsupervised offensive platform.

## Release status

The current release is `v1.0.0`.

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

Key endpoints:

- `POST /ingest`
- `GET /healthz`
- `GET /dashboard/`
- `GET /api/status`
- `GET /api/evidence`
- `GET /api/evidence/verify`
- `GET /api/policy`
- `GET /api/events/stream`
- `GET /api/memory/search?q=...`

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
cargo run --locked
```

### 4. Send an authenticated envelope

```bash
curl -s \
  -H 'content-type: application/json' \
  -H "x-demonclaw-token: ${DEMONCLAW_TOKEN}" \
  -d '{"content":"memory:compact"}' \
  http://127.0.0.1:3000/ingest
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
- `.github/workflows/release.yml`: idempotent publication of existing version tags

## License

DemonClaw is licensed under the MIT License. See `LICENSE`.

Built by BlueDot IT.
