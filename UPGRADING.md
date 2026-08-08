# Upgrading DemonClaw

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
