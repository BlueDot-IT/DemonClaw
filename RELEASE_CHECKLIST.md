# Release Checklist

## Version and documentation

- [ ] confirm the `Cargo.toml` version and target tag
- [ ] update `CHANGELOG.md`
- [ ] verify `README.md`, `SPEC.md`, and `CONFIG.md` match the implementation
- [ ] review `SECURITY_EXCEPTIONS.md` and remove obsolete exceptions

## Locked build verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --locked --all-targets --all-features -- -D warnings`
- [ ] `cargo test --locked --all`
- [ ] `cargo audit --file Cargo.lock`
- [ ] `zizmor .github/workflows`

## Runtime smoke

- [ ] generate a runtime-only PostgreSQL password
- [ ] start PostgreSQL and pgvector with `docker compose up -d`
- [ ] launch DemonClaw with a valid `DATABASE_URL`
- [ ] verify `GET /healthz`
- [ ] enable ingest authentication and verify authorized and unauthorized `POST /ingest` requests
- [ ] run `payload:test_payload` under an approved engagement configuration
- [ ] confirm lifecycle evidence was recorded
- [ ] verify the evidence chain
- [ ] confirm interval and cron jobs enter the normal envelope lifecycle

## Release publication

- [ ] push the final reviewed commit
- [ ] create or verify the version tag
- [ ] allow `.github/workflows/release.yml` to publish the existing tag
- [ ] verify the GitHub Release notes match the changelog
- [ ] verify CI and security workflows pass on the release commit
