from pathlib import Path


def patch(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}: {old[:100]!r}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


patch(
    "src/main.rs",
    '''async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    if demonclaw::cli::handle_cli().await? {
''',
    '''async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    demonclaw::tls::ensure_crypto_provider_installed();
    if demonclaw::cli::handle_cli().await? {
''',
)

patch(
    "src/evidence.rs",
    '''        let timestamp = Utc::now();
        let kind_str = kind.into();
''',
    '''        // PostgreSQL TIMESTAMPTZ stores microsecond precision. Normalize before hashing
        // so a freshly-created event verifies identically after a database round trip.
        let now = Utc::now();
        let timestamp = DateTime::<Utc>::from_timestamp_micros(now.timestamp_micros())
            .expect("UTC timestamp should be representable at microsecond precision");
        let kind_str = kind.into();
''',
)

patch(
    "CHANGELOG.md",
    '''- versioned SQLx migration for operational state

### Changed
''',
    '''- versioned SQLx migration for operational state

### Fixed

- normalized Evidence Locker timestamps to PostgreSQL microsecond precision before hashing
- initialized the configured rustls crypto provider before CLI HTTP clients are constructed

### Changed
''',
)
