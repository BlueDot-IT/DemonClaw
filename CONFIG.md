# DemonClaw Configuration

DemonClaw loads an optional JSON file and then applies environment-variable overrides. The default JSON path is `demonclaw.json`; set `DEMONCLAW_CONFIG` to use another path.

Do not commit local configuration files or credentials. `.env`, `.env.*`, and `demonclaw.json` are ignored. `.env.example` contains variable names and safe defaults only.

## Core runtime

| Variable | Default | Description |
| --- | --- | --- |
| `DEMONCLAW_CONFIG` | `demonclaw.json` | Optional JSON configuration path |
| `DEMONCLAW_HTTP_BIND` | `0.0.0.0:3000` | HTTP listener address |
| `DATABASE_URL` | `postgres://localhost/demonclaw` | PostgreSQL connection string |
| `DEMONCLAW_EVENT_BUFFER` | `256` | Internal envelope channel capacity |
| `DEMONCLAW_MAX_CONCURRENT_PAYLOADS` | `4` | Maximum simultaneous payload executions |
| `DEMONCLAW_LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, or `error` |

The default HTTP bind exposes the listener on every interface. Use `127.0.0.1:3000`, an authenticated reverse proxy, or another restricted network boundary unless remote access is explicitly required.

## HTTP ingestion

| Variable | Default | Description |
| --- | --- | --- |
| `DEMONCLAW_INGEST_AUTH_ENABLED` | `false` | Require a token for `POST /ingest` |
| `DEMONCLAW_INGEST_AUTH_HEADER` | `x-demonclaw-token` | Header carrying the ingest token |
| `DEMONCLAW_INGEST_TOKEN_ENV` | `DEMONCLAW_TOKEN` | Name of the environment variable containing the expected token |
| `DEMONCLAW_MAX_BODY_BYTES` | `1000000` | Maximum request body size |

Production deployments should enable ingestion authentication. Dashboard and read-only JSON routes do not currently implement an application identity layer and must be protected by the deployment boundary.

Generate a runtime token without placing a literal value in a configuration file:

```bash
export DEMONCLAW_INGEST_AUTH_ENABLED=1
export DEMONCLAW_TOKEN="$(openssl rand -hex 32)"
```

## Security policy

| Variable | Default | Description |
| --- | --- | --- |
| `DEMONCLAW_REQUIRE_ENGAGEMENT` | `false` | Require engagement context for protected operations |
| `DEMONCLAW_ENGAGEMENT_ID` | unset | Current engagement identifier |
| `DEMONCLAW_ALLOW_PRIVATE_ONLY` | `true` | Restrict targets to private, loopback, and link-local addresses |
| `DEMONCLAW_ALLOWED_CIDRS` | unset | Comma-separated CIDR allowlist |
| `DEMONCLAW_BLOCKED_PORTS` | `22,2375,2376,3389` | Comma-separated blocked ports |
| `DEMONCLAW_ALLOWED_DOMAINS` | unset | Comma-separated domain allowlist |
| `DEMONCLAW_MAX_TOOL_LEVEL` | `intrusive` | Maximum level: `passive`, `active`, or `intrusive` |

For a new deployment, start with `DEMONCLAW_REQUIRE_ENGAGEMENT=1` and `DEMONCLAW_MAX_TOOL_LEVEL=passive`, then expand permissions deliberately.

## SignalGate

| Variable | Default | Description |
| --- | --- | --- |
| `SIGNALGATE_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible API base URL |
| `SIGNALGATE_API_KEY` | unset | Provider credential |
| `SIGNALGATE_MODEL` | `gpt-4o` | Classification model |
| `SIGNALGATE_UPSTREAM_ALLOW_HTTP` | `false` | Permit plaintext HTTP upstreams |
| `SIGNALGATE_UPSTREAM_ALLOWLIST` | unset | `provider=url1,url2;provider2=url3` |
| `SIGNALGATE_USER_FORWARD_MODE` | `hash` | `drop`, `hash`, or `passthrough` |
| `SIGNALGATE_USER_SALT` | unset | Salt used by hash forwarding mode |

Keep plaintext upstreams disabled outside an isolated development environment. Provider credentials must be supplied through the runtime environment or a secret manager.

## Embeddings

| Variable | Default | Description |
| --- | --- | --- |
| `EMBEDDING_BASE_URL` | `https://api.openai.com/v1` | Embedding API base URL |
| `EMBEDDING_API_KEY` | unset | Provider credential |
| `EMBEDDING_MODEL` | `text-embedding-3-small` | Embedding model |
| `EMBEDDING_DIMENSION` | `1536` | Expected vector dimension |

When no embedding provider is configured, memory retrieval falls back to PostgreSQL full-text search.

## WASM sandbox

| Variable | Default | Description |
| --- | --- | --- |
| `DEMONCLAW_SANDBOX_FUEL_LIMIT` | `10000000` | Maximum Wasmtime fuel per payload |
| `DEMONCLAW_SANDBOX_TIMEOUT_SECS` | `30` | Maximum payload execution time |

Payloads are scanned before execution and receive a capability manifest. Resource limits do not replace engagement, approval, or target policy.

## GhostMCP

| Variable | Default | Description |
| --- | --- | --- |
| `GHOSTMCP_AUTO_APPROVE` | `false` | Automatically approve protected actions for development only |
| `GHOSTMCP_APPROVAL_TOKEN` | unset | Automated approval token |
| `GHOSTMCP_HUMAN_TOKEN` | unset | Human approval token |
| `GHOSTMCP_ALLOWED_ACTIONS` | unset | Comma-separated action allowlist |
| `DC_SECRET_*` | unset | Runtime secret injection namespace |

Do not enable automatic approval in an operational environment.

## Scheduler

| Variable | Default | Description |
| --- | --- | --- |
| `DEMONCLAW_SCHEDULER_INTERVAL_SECS` | `60` | Heartbeat interval |

Additional interval and cron jobs can be provided in the JSON configuration under `runtime.scheduler_jobs`.

## Active defense

### SSH targeting

| Variable | Default | Description |
| --- | --- | --- |
| `DEMONCLAW_SSH_ALLOWLIST` | unset | Comma-separated exact `user@host` or host-only destinations |
| `DEMONCLAW_SSH_ALLOW_ANY` | `false` | Development-only bypass for SSH destination allowlisting |

### Remediation

| Variable | Default | Description |
| --- | --- | --- |
| `DEMONCLAW_REMEDIATE_USE_SUDO` | `true` | Run supported remediation through non-interactive sudo |
| `DEMONCLAW_REMEDIATE_ALLOW_APT_UPGRADE` | `true` | Permit supported apt upgrade actions after approval |

Supported command families include:

- `scan:vuln`
- `scan:intrusion`
- `verify`
- `defend:run`
- `remediate:plan`
- `remediate:apply`

Remote operations must remain inside the configured engagement and SSH scope. Verification and remediation actions are GhostMCP-gated where implemented.

## Local PostgreSQL and pgvector

The Compose file requires a password from the current environment and binds PostgreSQL to localhost only:

```bash
export POSTGRES_PASSWORD="$(openssl rand -hex 32)"
docker compose up -d
export DATABASE_URL="postgres://postgres:${POSTGRES_PASSWORD}@127.0.0.1:5433/demonclaw"
```

The password is not embedded in the repository or Compose file.

## Runtime behavior

### Evidence Locker

- lifecycle and execution events are stored in `evidence_chain`
- each event links to the preceding event hash
- verification recomputes hashes and link relationships
- the chain is tamper-evident and still depends on database access control and retention policy

### Memory maintenance

The background optimizer periodically runs `ANALYZE` and `VACUUM ANALYZE` for `memory_chunks`. It does not run automatic `REINDEX`; index rebuilding requires a deliberate maintenance policy and window.

### Payload execution

1. receive an envelope
2. classify its intent
3. verify engagement and applicable policy
4. obtain GhostMCP approval
5. load and scan the WASM module
6. apply the capability manifest
7. execute with fuel, timeout, and concurrency limits
8. record the outcome in the evidence chain
