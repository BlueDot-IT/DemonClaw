# DemonClaw Specification, v1.0

This document describes the implemented DemonClaw 1.0 runtime on the `main` branch.

## 1. Purpose

DemonClaw is a Rust-native agent runtime for controlled purple-team operations and defensive validation. It is designed to:

- ingest envelopes from a local REPL or HTTP endpoint
- classify envelopes as queries, commands, payload requests, or unknown input
- enforce engagement and target policy before sensitive activity
- require explicit approval for protected actions
- scan and execute capability-scoped WASM payloads
- retain semantic memory in PostgreSQL and pgvector
- record lifecycle and execution evidence in a hash-linked chain
- expose operational status, evidence, policy, memory search, and live events to operators

DemonClaw is not designed as an unsupervised offensive platform. Deployment operators remain responsible for network isolation, identity controls, engagement authorization, and provider credentials.

## 2. Runtime components

### 2.1 Configuration

`src/config.rs` loads optional JSON configuration and then applies environment-variable overrides. Configuration covers the HTTP listener, ingest authentication, SignalGate, persistence, scheduling, logging, and runtime limits.

`src/security.rs` separately constructs the operational security policy from environment variables. The policy includes engagement requirements, CIDR and domain scope, blocked ports, private-address restrictions, and maximum tool level.

### 2.2 Channels

`src/channels/mod.rs` owns the input and operator-facing HTTP surfaces:

- asynchronous stdin REPL ingestion
- `POST /ingest`
- `GET /healthz`
- server-rendered dashboard pages
- JSON status, evidence, policy, and memory APIs
- SSE event delivery
- static asset serving

The channel layer applies a request-body limit, a fixed-window ingest rate limit, and optional constant-time token authentication for `POST /ingest`.

The dashboard and read-only JSON endpoints do not implement an application identity layer. Production deployments must place them behind an authenticated reverse proxy or a restricted network boundary.

### 2.3 SignalGate

`src/signalgate/mod.rs` classifies envelope content into:

- `Query`
- `Command`
- `AttackPayload`
- `Unknown`

Core directives use deterministic local rules. Other classifications can use an OpenAI-compatible upstream. Upstream URLs are validated, plaintext HTTP is disabled by default, and user forwarding supports `drop`, `hash`, or `passthrough` modes.

### 2.4 AgentLoop

`src/loop/mod.rs` is the central asynchronous orchestrator. For each envelope it:

1. records the received state
2. classifies the envelope
3. records the classification
4. routes the selected pipeline
5. enforces applicable policy and approval checks
6. records completion, denial, failure, or ignored state

A semaphore limits concurrent payload execution.

### 2.5 GhostMCP

`src/ghostmcp/mod.rs` is the approval and secret-injection boundary. Protected payload, verification, and remediation actions must receive GhostMCP authorization before execution.

Automatic approval is a development option and is disabled by default.

### 2.6 Payload scanner and sandbox

`src/scanner/mod.rs` validates WASM modules before execution. It inspects imports and rejects modules that violate the scanner policy.

`src/sandbox/mod.rs` executes accepted modules with Wasmtime and WASI. The sandbox applies manifest capabilities, fuel limits, and time limits. A payload is expected at:

`payloads/<name>/target/wasm32-wasip1/release/<name>.wasm`

Payload execution follows this sequence:

1. parse the `payload:<name>` directive
2. verify engagement context
3. obtain GhostMCP approval
4. acquire a concurrency slot
5. load the payload
6. scan the module
7. apply a capability manifest
8. execute in the sandbox
9. record the result in the evidence chain

### 2.7 Memory

`src/memory/mod.rs` manages PostgreSQL and pgvector persistence. It provides:

- schema migration
- semantic chunk insertion
- vector similarity search
- full-text fallback when embeddings are unavailable
- context retrieval
- periodic `ANALYZE` and `VACUUM ANALYZE` maintenance

Embedding generation is provided by `src/embeddings.rs`. The configured embedding dimension must match the database schema.

### 2.8 Evidence Locker

`src/evidence.rs` records structured events in a hash-linked chain. Each record contains the preceding hash and a hash derived from the event fields. Verification recomputes hashes and link relationships to detect broken links or modified records.

The chain is tamper-evident, not tamper-proof. Database access controls, backups, retention, and external anchoring remain deployment responsibilities.

### 2.9 Scheduler

`src/scheduler/mod.rs` injects envelopes from:

- a periodic heartbeat
- configured interval jobs
- basic five-field cron expressions supporting wildcards, lists, ranges, and steps

Scheduled envelopes enter the same AgentLoop and evidence lifecycle as interactive input.

### 2.10 Active defense

`src/active_defense/` implements controlled defensive scan, verification, and remediation command handling. Supported command families include:

- vulnerability and intrusion scans
- verification checks
- remediation planning
- approval-gated remediation application
- combined defensive workflows

Remote SSH targets require explicit allowlisting unless the development-only allow-any setting is enabled. Engagement and GhostMCP controls apply where required.

## 3. Envelope lifecycle

An `Envelope` contains an identifier, source, content, and receipt timestamp. Sources include REPL, HTTP, scheduler, and internal workflows.

The normal lifecycle is:

1. `Received`
2. `Classified`
3. `Running`
4. one of `Completed`, `Denied`, `Failed`, `Ignored`

Every transition is submitted to the Evidence Locker. Evidence failures are logged but do not currently stop the runtime pipeline.

## 4. Query pipeline

A query retrieves context through the MemoryManager. Vector retrieval is used when an embedding provider is available. Otherwise, PostgreSQL full-text search is used. The number of retrieved context chunks is recorded in the completed lifecycle event.

DemonClaw does not currently expose a separate answer-generation stage in the AgentLoop.

## 5. Command pipeline

The command pipeline handles internal directives such as `memory:compact` and active-defense commands. Unknown commands are recorded as ignored.

Security-sensitive command handlers are responsible for applying engagement, target, tool-level, approval, and evidence controls before sensitive operations.

## 6. HTTP security boundary

`POST /ingest` can require a token from a configurable header. The expected token is read from a named environment variable and compared in constant time.

The default configuration enables ingest authentication and requires a non-empty runtime token. Production deployments must explicitly enable it:

```text
DEMONCLAW_INGEST_AUTH_ENABLED=1
DEMONCLAW_TOKEN=<runtime secret>
```

The default listener is `127.0.0.1:3000`. Operators must restrict exposure when dashboard and read APIs are not protected by an upstream identity layer.

## 7. Security invariants

The implemented design intends to preserve these invariants:

1. Sensitive execution is not performed without applicable engagement context.
2. Targets and ports remain inside the configured operational scope.
3. Protected actions pass through GhostMCP approval.
4. Active-defense targets and tool levels are validated before command execution.
5. WASM modules are scanned before sandbox execution.
6. Payload HTTP destinations and executable names do not exceed explicit manifest allowlists.
7. Payload execution is bounded by concurrency, guest-input, fuel, and enforced epoch limits.
8. Lifecycle outcomes are serialized before insertion into the evidence chain, and chain forks are rejected.
9. Upstream LLM destinations satisfy configured URL restrictions.
10. Provider credentials and runtime secrets are supplied at runtime, not committed to the repository.
11. Dependency advisory exceptions are centralized and explicitly documented.

## 8. Persistence and migrations

SQLx migrations in `migrations/` create the pgvector memory schema. Evidence schema initialization is performed by the Evidence Locker.

Startup fails closed when PostgreSQL, pgvector migrations, or the Evidence Locker schema are unavailable. DemonClaw does not execute payloads as a database-failure fallback.

## 9. Build and verification

Required project checks are:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all
cargo audit --file Cargo.lock
```

CI runs these checks with a pinned pgvector container and pinned GitHub Actions dependencies. The security workflow runs cargo-audit and zizmor without suppressing findings.

## 10. Dependency policy

`Cargo.lock` is committed and CI uses `--locked`. The only cargo-audit policy file is `.cargo/audit.toml`.

Every ignored advisory must have a current, source-backed justification in `SECURITY_EXCEPTIONS.md`. An exception must be removed when it becomes reachable, when a patched dependency is available, or when the dependency graph no longer contains it.

## 11. Release process

Version history is maintained in `CHANGELOG.md`. Existing version tags are published through `.github/workflows/release.yml`. The release workflow is idempotent and does not recreate an existing GitHub Release.

The current release line is `v1.0.0`.

## 12. Acceptance criteria

A release candidate is acceptable only when:

- formatting, Clippy, and tests pass with the committed lockfile
- cargo-audit passes under the documented exception policy
- zizmor reports no unsuppressed workflow findings
- the pgvector-backed test environment starts successfully
- `/healthz` responds successfully
- authenticated ingestion works when enabled
- payload execution produces the expected lifecycle evidence
- evidence-chain verification succeeds on unmodified records
- release documentation matches the implemented runtime
