# Release Checklist

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
- [ ] verify authorized and unauthorized `POST /api/v1/ingest` behavior
- [ ] verify the Evidence Locker chain after a database round trip
- [ ] upgrade a database created by the previous release and rerun `doctor`

## Distribution

- [ ] inspect x86_64 and arm64 tarball contents
- [ ] verify each published SHA-256 checksum
- [ ] verify both SPDX SBOM assets are present
- [ ] verify both release tarballs with `gh attestation verify ... -R BlueDot-IT/DemonClaw`
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
