# DemonClaw Security Model

DemonClaw is a defensive and controlled purple-team operations runtime. It is designed around explicit scope, least privilege, approval boundaries, constrained execution, and tamper-evident evidence. It is not a substitute for host isolation, database access control, or an authorization boundary in front of remotely exposed dashboard/read APIs.

## Protected assets

DemonClaw protects or processes:

- engagement scope and target allowlists
- target credentials supplied outside the repository
- GhostMCP approval decisions and secret injection
- payload capability manifests
- persistent target/finding state
- PostgreSQL memory and operational records
- Evidence Locker events and chain hashes
- optional upstream-provider credentials

## Trust boundaries

### Operator to DemonClaw

The operator is trusted to define engagement scope, target allowlists, tool level, maintenance windows, and approval policy. CLI operations that change remote systems still pass through runtime policy and GhostMCP where applicable.

### Network and target systems

Target output is untrusted. SSH destinations are syntax-validated and must satisfy both the security policy and SSH allowlist. Remote command arguments are shell-escaped before execution. Host-key verification is strict.

### LLM/provider boundary

Upstream model output is untrusted input, not authority. A model cannot expand engagement scope, tool level, target allowlists, WASM capabilities, remediation allowlists, or GhostMCP approvals. Provider URLs are constrained by configured scheme and allowlist policy.

### WASM payload boundary

Payloads are scanned before execution and run inside Wasmtime with explicit capability manifests, fuel limits, epoch deadlines, and restricted executable/HTTP access. Sandbox controls reduce payload authority; they do not make arbitrary untrusted code risk-free.

### Database boundary

PostgreSQL is trusted for availability and durable storage but Evidence Locker records are independently hash-linked so unauthorized record modification can be detected. Database administrators can still delete the database, deny service, or remove the entire evidence history. External backups and database auditing remain necessary.

### Dashboard/API boundary

`POST /api/v1/ingest` has application token authentication by default. The legacy `/ingest` route remains a 1.1 compatibility alias. Dashboard and read-only JSON APIs rely on the deployment boundary and must remain loopback-only or be placed behind an authenticated reverse proxy before remote exposure.

## Fail-closed defaults

A default deployment:

- binds the HTTP listener to loopback
- requires ingest authentication
- requires engagement context
- limits tools to `passive`
- denies arbitrary SSH destinations
- disables automatic remediation
- disables apt remediation
- disables GhostMCP automatic approval
- fails startup when PostgreSQL, migrations, or Evidence Locker initialization fails

## Remediation authority

Automatic remediation is permitted only when every relevant gate succeeds:

1. the active engagement permits the target
2. the requested tool level is allowed
3. automatic remediation is explicitly enabled
4. the current time is inside the configured UTC maintenance window
5. GhostMCP approves the action
6. the concrete remediation action is allowlisted

Current remediation support is deliberately narrow. Expanding remediation commands is a security-sensitive change.

## Evidence guarantees and limitations

Evidence events contain a UUID, timestamp, previous-event hash, kind, detail, optional envelope ID, and event hash. Appends are serialized and chain forks are rejected. Timestamps are normalized to PostgreSQL microsecond precision before hashing so events remain verifiable after storage round trips.

The chain is tamper-evident, not immutable. An attacker with sufficient database authority can delete the whole chain or restore an older database snapshot. For higher assurance, export or anchor evidence hashes outside the DemonClaw database.

## Secret handling

Repository files and examples must not contain operational credentials. Runtime secrets belong in environment variables, a process supervisor's protected environment file, or an external secret manager. `.env`, local configuration, and populated service environment files must not be committed.

## Explicit non-goals

DemonClaw does not promise:

- containment of a fully compromised host on which DemonClaw itself runs
- protection against a malicious database superuser deleting all records
- automatic authorization of offensive actions
- safe remote exposure of unauthenticated dashboard/read APIs
- universal vulnerability detection or replacement of specialized EDR/scanners

See `SUPPORT.md` for supported deployment surfaces and `.github/SECURITY.md` for vulnerability reporting.
