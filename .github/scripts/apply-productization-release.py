from pathlib import Path


def read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def write(path: str, content: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}: {old[:120]!r}")
    write(path, text.replace(old, new, 1))


replace_once(
    "Cargo.toml",
    '''[package]
name = "demonclaw"
version = "1.0.0"
edition = "2024"
''',
    '''[package]
name = "demonclaw"
version = "1.1.0"
edition = "2024"
rust-version = "1.97"
description = "Security-first purple-team and defensive operations runtime"
license = "MIT"
repository = "https://github.com/BlueDot-IT/DemonClaw"
homepage = "https://github.com/BlueDot-IT/DemonClaw"
readme = "README.md"
keywords = ["security", "purple-team", "defense", "wasm", "agent"]
categories = ["command-line-utilities", "development-tools"]
''',
)

write(
    "rust-toolchain.toml",
    '''[toolchain]\nchannel = "1.97.1"\nprofile = "minimal"\ncomponents = ["clippy", "rustfmt"]\ntargets = ["wasm32-wasip1"]\n''',
)

write(
    ".dockerignore",
    '''.git\n.github\ntarget\n.env\n.env.*\ndemonclaw.json\n*.log\n*.tmp\n.DS_Store\n''',
)

write(
    "Dockerfile",
    r'''FROM rust:1.97-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --locked --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/demonclaw --create-home \
         --shell /usr/sbin/nologin demonclaw

WORKDIR /app
COPY --from=builder /src/target/release/demonclaw /usr/local/bin/demonclaw
COPY --from=builder /src/templates /app/templates
COPY --from=builder /src/migrations /app/migrations

USER demonclaw
EXPOSE 3000
ENTRYPOINT ["demonclaw"]
CMD ["run"]
''',
)

write(
    "docker-compose.yml",
    r'''services:
  db:
    image: pgvector/pgvector@sha256:1d533553fefe4f12e5d80c7b80622ba0c382abb5758856f52983d8789179f0fb
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set}
      POSTGRES_DB: demonclaw
    ports:
      - "127.0.0.1:5433:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d demonclaw"]
      interval: 10s
      timeout: 5s
      retries: 20
    volumes:
      - demonclaw_pgdata:/var/lib/postgresql/data

  demonclaw:
    build:
      context: .
    image: demonclaw:local
    depends_on:
      db:
        condition: service_healthy
    environment:
      DATABASE_URL: postgres://postgres:${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set}@db:5432/demonclaw
      DEMONCLAW_HTTP_BIND: 0.0.0.0:3000
      DEMONCLAW_INGEST_AUTH_ENABLED: "true"
      DEMONCLAW_TOKEN: ${DEMONCLAW_TOKEN:?DEMONCLAW_TOKEN must be set}
      DEMONCLAW_REQUIRE_ENGAGEMENT: ${DEMONCLAW_REQUIRE_ENGAGEMENT:-true}
      DEMONCLAW_ENGAGEMENT_ID: ${DEMONCLAW_ENGAGEMENT_ID:-}
      DEMONCLAW_MAX_TOOL_LEVEL: ${DEMONCLAW_MAX_TOOL_LEVEL:-passive}
      DEMONCLAW_SSH_ALLOWLIST: ${DEMONCLAW_SSH_ALLOWLIST:-}
      GHOSTMCP_AUTO_APPROVE: ${GHOSTMCP_AUTO_APPROVE:-false}
    ports:
      - "127.0.0.1:3000:3000"
    read_only: true
    tmpfs:
      - /tmp:size=64m,mode=1777
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    restart: unless-stopped

volumes:
  demonclaw_pgdata:
''',
)

write(
    "packaging/demonclaw.env.example",
    r'''# Copy to /etc/demonclaw/demonclaw.env and replace the commented placeholders.
# Never commit the populated file.

# DATABASE_URL=postgres://USER:PASSWORD@HOST:5432/demonclaw
# DEMONCLAW_TOKEN=GENERATE_A_RANDOM_RUNTIME_TOKEN

DEMONCLAW_HTTP_BIND=127.0.0.1:3000
DEMONCLAW_INGEST_AUTH_ENABLED=true
DEMONCLAW_REQUIRE_ENGAGEMENT=true
DEMONCLAW_MAX_TOOL_LEVEL=passive
GHOSTMCP_AUTO_APPROVE=false
''',
)

write(
    "packaging/systemd/demonclaw.service",
    r'''[Unit]
Description=DemonClaw defensive operations runtime
Documentation=https://github.com/BlueDot-IT/DemonClaw
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=demonclaw
Group=demonclaw
WorkingDirectory=/opt/demonclaw
Environment=HOME=/var/lib/demonclaw
EnvironmentFile=/etc/demonclaw/demonclaw.env
ExecStart=/usr/local/bin/demonclaw run
Restart=on-failure
RestartSec=5s
UMask=0077

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/lib/demonclaw

[Install]
WantedBy=multi-user.target
''',
)

write(
    "packaging/install.sh",
    r'''#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run this installer as root (for example: sudo ./packaging/install.sh)." >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="$ROOT_DIR/demonclaw"

if [[ ! -x "$BINARY" ]]; then
  echo "Expected packaged binary at $BINARY" >&2
  exit 1
fi

if ! id demonclaw >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/demonclaw --create-home --shell /usr/sbin/nologin demonclaw
fi

install -d -m 0755 /opt/demonclaw
install -d -m 0755 /opt/demonclaw/templates
install -d -m 0755 /opt/demonclaw/migrations
install -d -o demonclaw -g demonclaw -m 0700 /var/lib/demonclaw
install -d -m 0750 /etc/demonclaw

install -m 0755 "$BINARY" /usr/local/bin/demonclaw
cp -a "$ROOT_DIR/templates/." /opt/demonclaw/templates/
cp -a "$ROOT_DIR/migrations/." /opt/demonclaw/migrations/
install -m 0644 "$ROOT_DIR/packaging/systemd/demonclaw.service" /etc/systemd/system/demonclaw.service

if [[ ! -e /etc/demonclaw/demonclaw.env.example ]]; then
  install -m 0640 "$ROOT_DIR/packaging/demonclaw.env.example" /etc/demonclaw/demonclaw.env.example
fi

systemctl daemon-reload

cat <<'EOF'
DemonClaw installed.

Next steps:
  1. sudo cp /etc/demonclaw/demonclaw.env.example /etc/demonclaw/demonclaw.env
  2. sudo editor /etc/demonclaw/demonclaw.env
  3. sudo chmod 600 /etc/demonclaw/demonclaw.env
  4. sudo -u demonclaw -H sh -c 'cd /opt/demonclaw && demonclaw migrate'
  5. sudo -u demonclaw -H sh -c 'cd /opt/demonclaw && demonclaw doctor'
  6. sudo systemctl enable --now demonclaw

The installer intentionally does not create secrets or start the service.
EOF
''',
)

write(
    "SUPPORT.md",
    r'''# DemonClaw Support Policy

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
- HTTP routes under `/api/*` documented in the repository
- SQL migrations shipped with a release

Rust module internals, raw AgentLoop envelopes, and internal event names are implementation details unless explicitly documented otherwise.

## Reporting problems

Security vulnerabilities must follow `.github/SECURITY.md`. General defects should include the DemonClaw version, host architecture, PostgreSQL/pgvector versions, `demonclaw doctor` output with secrets removed, and the relevant log excerpt.
''',
)

write(
    "SECURITY_MODEL.md",
    r'''# DemonClaw Security Model

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

`POST /ingest` has application token authentication by default. Dashboard and read-only JSON APIs rely on the deployment boundary and must remain loopback-only or be placed behind an authenticated reverse proxy before remote exposure.

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
''',
)

write(
    "UPGRADING.md",
    r'''# Upgrading DemonClaw

DemonClaw database migrations are forward-only. Treat the PostgreSQL database and Evidence Locker as release-critical state.

## Before upgrading

1. Read the target release section in `CHANGELOG.md`.
2. Back up PostgreSQL with your normal tested backup procedure.
3. Export or retain any external Evidence Locker anchors you use.
4. Record the current `demonclaw version` and `demonclaw doctor` output.
5. Stop the DemonClaw service before replacing the binary or container.

## Binary/systemd installation

After extracting the new release bundle:

```bash
sudo ./packaging/install.sh
sudo -u demonclaw -H sh -c 'cd /opt/demonclaw && demonclaw migrate'
sudo -u demonclaw -H sh -c 'cd /opt/demonclaw && demonclaw doctor'
sudo systemctl restart demonclaw
sudo systemctl status demonclaw --no-pager
```

The installer replaces program files but intentionally does not overwrite `/etc/demonclaw/demonclaw.env`.

## Docker Compose installation

Build the new image, run migrations/health validation, then replace the daemon:

```bash
docker compose build demonclaw
docker compose run --rm demonclaw migrate
docker compose run --rm demonclaw doctor
docker compose up -d demonclaw
```

## Rollback

Binary rollback is only safe when the older release understands every migration already applied to the database. Minor and major releases may be forward-only. When compatibility is uncertain, restore the pre-upgrade database backup together with the older application version.

Never "fix" a failed Evidence Locker verification by rewriting historical event hashes. Investigate the storage/history discrepancy and restore known-good state when necessary.
''',
)

write(
    "docs/DEMO.md",
    r'''# DemonClaw Reproducible Operator Demo

This demo is intended for an isolated lab VM that you control. Do not intentionally expose the demonstration listener on an untrusted network.

## 1. Start the database and daemon

```bash
export POSTGRES_PASSWORD="$(openssl rand -hex 32)"
export DEMONCLAW_TOKEN="$(openssl rand -hex 32)"
export DEMONCLAW_REQUIRE_ENGAGEMENT=1
export DEMONCLAW_ENGAGEMENT_ID=demo-lab
export DEMONCLAW_MAX_TOOL_LEVEL=passive

docker compose up -d
```

Verify the runtime:

```bash
docker compose exec demonclaw demonclaw doctor
```

## 2. Register a lab target

For a native installation on the lab VM:

```bash
demonclaw target add lab-local --local --tag demo
demonclaw defend baseline lab-local
demonclaw findings list
```

## 3. Introduce controlled drift

On the isolated lab VM, start a temporary listener on a port DemonClaw classifies as high risk:

```bash
python3 -m http.server 6379 --bind 0.0.0.0
```

In another shell:

```bash
demonclaw defend drift lab-local
demonclaw scan vuln lab-local
demonclaw findings list
```

The listener is deliberately not Redis; the point is to demonstrate that the listening-port detector recognizes a new wildcard bind on the Redis port and creates persistent finding state. The finding remains linked to the evidence trail and gains occurrence counts instead of being recreated as unrelated events.

## 4. Inspect operations state

Open the local dashboard at `http://127.0.0.1:3000/dashboard/operations` or use:

```bash
curl -s http://127.0.0.1:3000/api/targets
curl -s http://127.0.0.1:3000/api/findings
```

## 5. Resolve the drift

Stop the temporary listener, then run:

```bash
demonclaw scan vuln lab-local
demonclaw findings list --status resolved
```

The previous finding should transition to `resolved` when it is absent from a subsequent scan of the same target/scope.

## 6. Verify evidence integrity

```bash
demonclaw doctor
curl -s http://127.0.0.1:3000/api/evidence/verify
```

This demonstrates the intended operator loop: register -> baseline -> detect -> persist -> investigate -> resolve -> verify evidence.
''',
)

write(
    ".github/dependabot.yml",
    r'''version: 2
updates:
  - package-ecosystem: cargo
    directory: "/"
    schedule:
      interval: weekly
    open-pull-requests-limit: 5
  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
    open-pull-requests-limit: 5
  - package-ecosystem: docker
    directory: "/"
    schedule:
      interval: weekly
    open-pull-requests-limit: 5
''',
)

write(
    ".github/workflows/release.yml",
    r'''name: release

on:
  push:
    tags: ['v*']
  workflow_dispatch:
    inputs:
      tag:
        description: Existing version tag to publish
        required: true
        default: v1.1.0
        type: string

permissions:
  contents: write

concurrency:
  group: release-${{ github.ref }}
  cancel-in-progress: false

jobs:
  prepare:
    runs-on: ubuntu-24.04
    outputs:
      tag: ${{ steps.release.outputs.tag }}
      version: ${{ steps.release.outputs.version }}
    steps:
      - name: Check out repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          fetch-tags: true
          persist-credentials: false

      - name: Validate tag and create release
        id: release
        env:
          GH_TOKEN: ${{ github.token }}
          REQUESTED_TAG: ${{ inputs.tag || 'v1.1.0' }}
        shell: bash
        run: |
          set -euo pipefail
          if [[ "$GITHUB_REF_TYPE" == "tag" ]]; then
            tag="$GITHUB_REF_NAME"
          else
            tag="$REQUESTED_TAG"
          fi
          [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
          git rev-parse --verify "refs/tags/${tag}^{commit}" >/dev/null
          version="${tag#v}"
          manifest_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n1)"
          [[ "$manifest_version" == "$version" ]]

          awk -v version="$version" '
            $0 ~ "^## " version "([[:space:]-]|$)" { found = 1; next }
            found && /^## / { exit }
            found { print }
          ' CHANGELOG.md > release-notes.md
          test -s release-notes.md

          if ! gh release view "$tag" >/dev/null 2>&1; then
            gh release create "$tag" --verify-tag --title "DemonClaw $version" --notes-file release-notes.md
          fi

          echo "tag=$tag" >> "$GITHUB_OUTPUT"
          echo "version=$version" >> "$GITHUB_OUTPUT"

  build:
    needs: prepare
    strategy:
      fail-fast: false
      matrix:
        include:
          - runner: ubuntu-24.04
            platform: linux-x86_64
          - runner: ubuntu-24.04-arm
            platform: linux-aarch64
    runs-on: ${{ matrix.runner }}
    steps:
      - name: Check out release tag
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ needs.prepare.outputs.tag }}
          persist-credentials: false

      - name: Install Rust
        uses: dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c
        with:
          toolchain: 1.97.1

      - name: Build release binary
        run: cargo build --locked --release

      - name: Package release bundle
        env:
          VERSION: ${{ needs.prepare.outputs.version }}
          PLATFORM: ${{ matrix.platform }}
        shell: bash
        run: |
          set -euo pipefail
          package="demonclaw-${VERSION}-${PLATFORM}"
          mkdir -p "dist/${package}/packaging/systemd"
          install -m 0755 target/release/demonclaw "dist/${package}/demonclaw"
          cp -a templates migrations "dist/${package}/"
          install -m 0755 packaging/install.sh "dist/${package}/packaging/install.sh"
          install -m 0644 packaging/demonclaw.env.example "dist/${package}/packaging/demonclaw.env.example"
          install -m 0644 packaging/systemd/demonclaw.service "dist/${package}/packaging/systemd/demonclaw.service"
          cp README.md CONFIG.md SUPPORT.md SECURITY_MODEL.md UPGRADING.md CHANGELOG.md LICENSE "dist/${package}/"
          tar -C dist -czf "dist/${package}.tar.gz" "$package"
          (cd dist && sha256sum "${package}.tar.gz" > "${package}.tar.gz.sha256")

      - name: Upload immutable release assets
        env:
          GH_TOKEN: ${{ github.token }}
          TAG: ${{ needs.prepare.outputs.tag }}
          VERSION: ${{ needs.prepare.outputs.version }}
          PLATFORM: ${{ matrix.platform }}
        shell: bash
        run: |
          set -euo pipefail
          package="demonclaw-${VERSION}-${PLATFORM}"
          gh release upload "$TAG" \
            "dist/${package}.tar.gz" \
            "dist/${package}.tar.gz.sha256" \
            --clobber
''',
)

replace_once(
    ".github/workflows/ci.yml",
    '''      - name: Install Rust
        uses: dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c # stable
        with:
          components: clippy, rustfmt
          targets: wasm32-wasip1
''',
    '''      - name: Install Rust
        uses: dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c
        with:
          toolchain: 1.97.1
          components: clippy, rustfmt
          targets: wasm32-wasip1
''',
)
replace_once(
    ".github/workflows/security.yml",
    '''      - name: Install Rust
        uses: dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c # stable
''',
    '''      - name: Install Rust
        uses: dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c
        with:
          toolchain: 1.97.1
''',
)

changelog = read("CHANGELOG.md")
if not changelog.startswith("# Changelog\n\n## Unreleased\n"):
    raise SystemExit("CHANGELOG.md: expected Unreleased section at top")
changelog = changelog.replace(
    "# Changelog\n\n## Unreleased\n",
    "# Changelog\n\n## Unreleased\n\nNo unreleased changes.\n\n## 1.1.0 - 2026-08-07\n",
    1,
)
write("CHANGELOG.md", changelog)

readme = read("README.md")
readme = readme.replace("releases/tag/v1.0.0", "releases/tag/v1.1.0")
readme = readme.replace("release-v1.0.0", "release-v1.1.0")
readme = readme.replace("Release v1.0.0", "Release v1.1.0")
readme = readme.replace("The current release is `v1.0.0`.", "The current release is `v1.1.0`.")
readme = readme.replace(
    "## Quick start\n",
    '''## Installation\n\n### Release bundle\n\nDownload the release archive for `linux-x86_64` or `linux-aarch64`, verify its adjacent SHA-256 file, extract it, then run:\n\n```bash\nsudo ./packaging/install.sh\n```\n\nThe installer does not create secrets or start the service. Follow the printed steps to populate `/etc/demonclaw/demonclaw.env`, migrate, run `doctor`, and enable the service.\n\n### Docker Compose\n\n```bash\nexport POSTGRES_PASSWORD="$(openssl rand -hex 32)"\nexport DEMONCLAW_TOKEN="$(openssl rand -hex 32)"\ndocker compose up -d --build\ndocker compose exec demonclaw demonclaw doctor\n```\n\nThe Compose deployment publishes both PostgreSQL and DemonClaw only on loopback. SSH keys are never mounted automatically; add an explicit read-only mount only when remote SSH targets require one.\n\nSee `SUPPORT.md`, `UPGRADING.md`, `SECURITY_MODEL.md`, and `docs/DEMO.md` before production deployment.\n\n## Quick start\n''',
    1,
)
readme = readme.replace("cargo run --locked\n", "cargo run --locked -- run\n", 1)
readme = readme.replace(
    "- `SECURITY_EXCEPTIONS.md`: reviewed dependency-advisory exceptions\n- `.github/workflows/release.yml`: idempotent publication of existing version tags",
    "- `SECURITY_EXCEPTIONS.md`: reviewed dependency-advisory exceptions\n- `SECURITY_MODEL.md`: trust boundaries, guarantees, and explicit non-goals\n- `SUPPORT.md`: production support and compatibility policy\n- `UPGRADING.md`: forward-migration and rollback procedure\n- `docs/DEMO.md`: reproducible operator demo\n- `.github/workflows/release.yml`: native x86_64/arm64 release bundles and checksums",
)
write("README.md", readme)

write(
    "RELEASE_CHECKLIST.md",
    r'''# Release Checklist

## Version and documentation

- [ ] confirm `Cargo.toml`, `Cargo.lock`, tag, and changelog versions match
- [ ] verify `README.md`, `SPEC.md`, `CONFIG.md`, `SUPPORT.md`, `SECURITY_MODEL.md`, and `UPGRADING.md`
- [ ] review `SECURITY_EXCEPTIONS.md` and remove obsolete exceptions
- [ ] verify the release support matrix still matches tested runners/services

## Locked build verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --locked --all-targets --all-features -- -D warnings`
- [ ] `cargo test --locked --all`
- [ ] `cargo audit --file Cargo.lock`
- [ ] `zizmor .github/workflows`
- [ ] native x86_64 release build passes
- [ ] native arm64 release build passes
- [ ] Docker image builds and `demonclaw version` runs inside it

## Runtime and upgrade smoke

- [ ] start PostgreSQL and pgvector from a clean volume
- [ ] `demonclaw migrate`
- [ ] `demonclaw doctor`
- [ ] register/list/remove a target
- [ ] establish an active-defense baseline and run a drift check
- [ ] verify findings persist and reconcile across scans
- [ ] verify authorized and unauthorized `POST /ingest` behavior
- [ ] verify the Evidence Locker chain after a database round trip
- [ ] upgrade a database created by the previous release and rerun `doctor`

## Distribution

- [ ] inspect x86_64 and arm64 tarball contents
- [ ] verify each published SHA-256 checksum
- [ ] `bash -n packaging/install.sh`
- [ ] verify systemd unit paths match the release bundle installer
- [ ] verify Docker Compose remains loopback-only by default
- [ ] verify release bundles contain templates, packaging files, and operator documentation

## Release publication

- [ ] sync the final reviewed commit to `BlueDot-IT/DemonClaw:main`
- [ ] verify CI and security workflows are green on that exact commit
- [ ] create the version tag through the BlueDot bridge
- [ ] verify `.github/workflows/release.yml` publishes both architecture bundles
- [ ] verify GitHub Release notes match the changelog
- [ ] keep the prior release available for rollback
''',
)
