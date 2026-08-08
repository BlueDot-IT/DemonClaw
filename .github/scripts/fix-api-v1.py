from pathlib import Path


def patch(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}: {old[:100]!r}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


patch(
    "src/channels/mod.rs",
    '''            .route("/api/status", get(api_status))
            .route("/api/evidence", get(api_evidence))
            .route("/api/evidence/verify", get(api_evidence_verify))
            .route("/api/targets", get(api_targets))
            .route("/api/findings", get(api_findings))
            .route("/api/policy", get(api_policy))
            .route("/api/events/stream", get(sse_events_handler))
            .route("/api/memory/search", get(api_memory_search))
''',
    '''            // Stable v1 operator API. Keep the unversioned routes below as 1.1 compatibility aliases.
            .route("/api/v1/ingest", post(ingest_handler))
            .route("/api/v1/status", get(api_status))
            .route("/api/v1/evidence", get(api_evidence))
            .route("/api/v1/evidence/verify", get(api_evidence_verify))
            .route("/api/v1/targets", get(api_targets))
            .route("/api/v1/findings", get(api_findings))
            .route("/api/v1/policy", get(api_policy))
            .route("/api/v1/events/stream", get(sse_events_handler))
            .route("/api/v1/memory/search", get(api_memory_search))
            .route("/api/status", get(api_status))
            .route("/api/evidence", get(api_evidence))
            .route("/api/evidence/verify", get(api_evidence_verify))
            .route("/api/targets", get(api_targets))
            .route("/api/findings", get(api_findings))
            .route("/api/policy", get(api_policy))
            .route("/api/events/stream", get(sse_events_handler))
            .route("/api/memory/search", get(api_memory_search))
''',
)

patch(
    "src/cli.rs",
    '.post(format!("{}/ingest", api_base_url(&cfg)))',
    '.post(format!("{}/api/v1/ingest", api_base_url(&cfg)))',
)
patch(
    "src/cli.rs",
    '.get(format!("{}/api/status", api_base_url(&cfg)))',
    '.get(format!("{}/api/v1/status", api_base_url(&cfg)))',
)

readme_path = Path("README.md")
readme = readme_path.read_text(encoding="utf-8")
old = '''Key endpoints:

- `POST /ingest`
- `GET /healthz`
- `GET /dashboard/`
- `GET /api/status`
- `GET /api/evidence`
- `GET /api/evidence/verify`
- `GET /api/policy`
- `GET /api/events/stream`
- `GET /api/memory/search?q=...`
'''
new = '''Stable operator API endpoints:

- `POST /api/v1/ingest`
- `GET /api/v1/status`
- `GET /api/v1/targets`
- `GET /api/v1/findings`
- `GET /api/v1/evidence`
- `GET /api/v1/evidence/verify`
- `GET /api/v1/policy`
- `GET /api/v1/events/stream`
- `GET /api/v1/memory/search?q=...`

`GET /healthz` and `/dashboard/*` are operational surfaces outside the versioned API. The older unversioned `/api/*` routes remain 1.1 compatibility aliases but new integrations should use `/api/v1/*`.
'''
if readme.count(old) != 1:
    raise SystemExit(f"README endpoint anchor expected once, found {readme.count(old)}")
readme = readme.replace(old, new, 1)
readme = readme.replace(
    "  http://127.0.0.1:3000/ingest",
    "  http://127.0.0.1:3000/api/v1/ingest",
)
readme_path.write_text(readme, encoding="utf-8")

support_path = Path("SUPPORT.md")
support = support_path.read_text(encoding="utf-8")
needle = "- HTTP routes under `/api/*` documented in the repository"
replacement = "- HTTP routes under `/api/v1/*` documented in the repository; unversioned `/api/*` routes are compatibility aliases for the 1.1 line"
if support.count(needle) != 1:
    raise SystemExit(f"SUPPORT API anchor expected once, found {support.count(needle)}")
support_path.write_text(support.replace(needle, replacement, 1), encoding="utf-8")

changelog_path = Path("CHANGELOG.md")
changelog = changelog_path.read_text(encoding="utf-8")
needle = "- operations dashboard and JSON APIs for targets and findings\n"
replacement = "- operations dashboard and JSON APIs for targets and findings\n- stable `/api/v1/*` operator API aliases while retaining unversioned 1.1 compatibility routes\n"
if changelog.count(needle) != 1:
    raise SystemExit(f"CHANGELOG API anchor expected once, found {changelog.count(needle)}")
changelog_path.write_text(changelog.replace(needle, replacement, 1), encoding="utf-8")
