#!/usr/bin/env bash
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
