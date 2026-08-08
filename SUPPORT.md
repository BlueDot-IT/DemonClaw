# DemonClaw Support Policy

## Supported production surfaces

DemonClaw 1.1 supports these release targets:

| Surface | Status | Validation |
| --- | --- | --- |
| Ubuntu 24.04 x86_64 | Supported | Native CI and release build |
| Ubuntu 24.04 arm64 | Supported | Native GitHub-hosted arm64 release build |
| Docker on Linux | Supported | Dockerfile build and CLI smoke test |
| Debian 13 x86_64/arm64 | Best effort | Expected compatible; not a required release gate |
| macOS | Development only | No production release artifact |
| Windows | Unsupported | No production runtime support |

## Required services

- PostgreSQL 16 or newer
- pgvector 0.8.x
- outbound TLS trust roots for configured HTTPS providers
- OpenSSH client when SSH targets are used

The upstream LLM and embedding providers are optional. Deterministic local routing and PostgreSQL full-text retrieval remain available when those providers are not configured.

## Compatibility policy

- Patch releases (`1.1.x`) must preserve the 1.1 configuration and database schema contract.
- Minor releases may add backward-compatible configuration fields and forward-only SQL migrations.
- Major releases may change public CLI/API/config contracts and require an explicit migration guide.
- Database downgrades are not guaranteed. Back up PostgreSQL before every minor or major upgrade.

## Supported public interfaces

The supported operator interfaces are:

- the `demonclaw` CLI documented by `demonclaw help`
- documented environment variables and `demonclaw.json`
- HTTP routes under `/api/v1/*` documented in the repository; unversioned `/api/*` routes are compatibility aliases for the 1.1 line
- SQL migrations shipped with a release

Rust module internals, raw AgentLoop envelopes, and internal event names are implementation details unless explicitly documented otherwise.

## Reporting problems

Security vulnerabilities must follow `.github/SECURITY.md`. General defects should include the DemonClaw version, host architecture, PostgreSQL/pgvector versions, `demonclaw doctor` output with secrets removed, and the relevant log excerpt.
