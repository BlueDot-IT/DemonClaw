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


write(
    "migrations/202608070002_operational_state.sql",
    r'''CREATE TABLE IF NOT EXISTS operational_targets (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    target JSONB NOT NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_operational_targets_enabled
    ON operational_targets(enabled);

CREATE TABLE IF NOT EXISTS operational_findings (
    id UUID PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    target JSONB NOT NULL,
    scope TEXT NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN (
            'new', 'confirmed', 'accepted', 'remediation_planned',
            'remediated', 'resolved', 'false_positive'
        )),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    occurrence_count BIGINT NOT NULL DEFAULT 1,
    evidence_event_id UUID,
    resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_operational_findings_status
    ON operational_findings(status);
CREATE INDEX IF NOT EXISTS idx_operational_findings_scope
    ON operational_findings(scope);
CREATE INDEX IF NOT EXISTS idx_operational_findings_last_seen
    ON operational_findings(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_operational_findings_target
    ON operational_findings USING GIN(target);
''',
)

write(
    "src/operations.rs",
    r'''use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Pool, Postgres, Row};
use uuid::Uuid;

use crate::active_defense::{
    findings::{Finding, Severity},
    types::Target,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    New,
    Confirmed,
    Accepted,
    RemediationPlanned,
    Remediated,
    Resolved,
    FalsePositive,
}

impl FindingStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Confirmed => "confirmed",
            Self::Accepted => "accepted",
            Self::RemediationPlanned => "remediation_planned",
            Self::Remediated => "remediated",
            Self::Resolved => "resolved",
            Self::FalsePositive => "false_positive",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "new" => Ok(Self::New),
            "confirmed" => Ok(Self::Confirmed),
            "accepted" => Ok(Self::Accepted),
            "remediation_planned" | "planned" => Ok(Self::RemediationPlanned),
            "remediated" => Ok(Self::Remediated),
            "resolved" => Ok(Self::Resolved),
            "false_positive" | "false-positive" => Ok(Self::FalsePositive),
            other => bail!("unsupported finding status: {other}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetRecord {
    pub id: Uuid,
    pub name: String,
    pub target: Target,
    pub target_label: String,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRecord {
    pub id: Uuid,
    pub fingerprint: String,
    pub target: Target,
    pub target_label: String,
    pub scope: String,
    pub kind: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub source: String,
    pub status: FindingStatus,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub occurrence_count: i64,
    pub evidence_event_id: Option<Uuid>,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct OperationsStore {
    pool: Pool<Postgres>,
}

impl OperationsStore {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    pub async fn add_target(
        &self,
        name: &str,
        target: Target,
        tags: Vec<String>,
    ) -> Result<TargetRecord> {
        validate_target_name(name)?;
        let id = Uuid::new_v4();
        let target_value = serde_json::to_value(&target)?;
        let row = sqlx::query(
            r#"
            INSERT INTO operational_targets (id, name, target, tags)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (name) DO UPDATE SET
                target = EXCLUDED.target,
                tags = EXCLUDED.tags,
                enabled = TRUE,
                updated_at = NOW()
            RETURNING id, name, target, tags, enabled, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(target_value)
        .bind(tags)
        .fetch_one(&self.pool)
        .await?;
        target_record_from_row(&row)
    }

    pub async fn remove_target(&self, name: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM operational_targets WHERE name = $1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list_targets(&self) -> Result<Vec<TargetRecord>> {
        let rows = sqlx::query(
            "SELECT id, name, target, tags, enabled, created_at, updated_at
             FROM operational_targets ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(target_record_from_row).collect()
    }

    pub async fn resolve_target(&self, name: &str) -> Result<Option<Target>> {
        let row = sqlx::query(
            "SELECT target FROM operational_targets WHERE name = $1 AND enabled = TRUE",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| serde_json::from_value::<Target>(row.get::<Value, _>("target")))
            .transpose()
            .map_err(Into::into)
    }

    pub async fn reconcile_findings(
        &self,
        target: &Target,
        scope: &str,
        source: &str,
        findings: &[Finding],
        evidence_event_id: Option<Uuid>,
    ) -> Result<Vec<FindingRecord>> {
        let target_value = serde_json::to_value(target)?;
        let mut seen = Vec::with_capacity(findings.len());
        let mut output = Vec::with_capacity(findings.len());

        for finding in findings {
            let fingerprint = finding_fingerprint(target, finding)?;
            seen.push(fingerprint.clone());
            let id = Uuid::new_v4();
            let severity = severity_name(&finding.severity);
            let row = sqlx::query(
                r#"
                INSERT INTO operational_findings (
                    id, fingerprint, target, scope, kind, severity, title, detail,
                    source, status, evidence_event_id
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'new', $10)
                ON CONFLICT (fingerprint) DO UPDATE SET
                    target = EXCLUDED.target,
                    scope = EXCLUDED.scope,
                    kind = EXCLUDED.kind,
                    severity = EXCLUDED.severity,
                    title = EXCLUDED.title,
                    detail = EXCLUDED.detail,
                    source = EXCLUDED.source,
                    last_seen = NOW(),
                    occurrence_count = operational_findings.occurrence_count + 1,
                    evidence_event_id = COALESCE(EXCLUDED.evidence_event_id, operational_findings.evidence_event_id),
                    status = CASE
                        WHEN operational_findings.status = 'resolved' THEN 'new'
                        ELSE operational_findings.status
                    END,
                    resolved_at = CASE
                        WHEN operational_findings.status = 'resolved' THEN NULL
                        ELSE operational_findings.resolved_at
                    END
                RETURNING id, fingerprint, target, scope, kind, severity, title, detail,
                          source, status, first_seen, last_seen, occurrence_count,
                          evidence_event_id, resolved_at
                "#,
            )
            .bind(id)
            .bind(&fingerprint)
            .bind(&target_value)
            .bind(scope)
            .bind(&finding.kind)
            .bind(severity)
            .bind(&finding.title)
            .bind(&finding.detail)
            .bind(source)
            .bind(evidence_event_id)
            .fetch_one(&self.pool)
            .await?;
            output.push(finding_record_from_row(&row)?);
        }

        if seen.is_empty() {
            sqlx::query(
                r#"
                UPDATE operational_findings
                SET status = 'resolved', resolved_at = NOW()
                WHERE target = $1
                  AND scope = $2
                  AND status NOT IN ('resolved', 'false_positive')
                "#,
            )
            .bind(&target_value)
            .bind(scope)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                r#"
                UPDATE operational_findings
                SET status = 'resolved', resolved_at = NOW()
                WHERE target = $1
                  AND scope = $2
                  AND status NOT IN ('resolved', 'false_positive')
                  AND NOT (fingerprint = ANY($3))
                "#,
            )
            .bind(&target_value)
            .bind(scope)
            .bind(&seen)
            .execute(&self.pool)
            .await?;
        }

        Ok(output)
    }

    pub async fn list_findings(
        &self,
        status: Option<FindingStatus>,
        limit: i64,
    ) -> Result<Vec<FindingRecord>> {
        let rows = if let Some(status) = status {
            sqlx::query(
                r#"
                SELECT id, fingerprint, target, scope, kind, severity, title, detail,
                       source, status, first_seen, last_seen, occurrence_count,
                       evidence_event_id, resolved_at
                FROM operational_findings
                WHERE status = $1
                ORDER BY last_seen DESC
                LIMIT $2
                "#,
            )
            .bind(status.as_str())
            .bind(limit.clamp(1, 1000))
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT id, fingerprint, target, scope, kind, severity, title, detail,
                       source, status, first_seen, last_seen, occurrence_count,
                       evidence_event_id, resolved_at
                FROM operational_findings
                ORDER BY last_seen DESC
                LIMIT $1
                "#,
            )
            .bind(limit.clamp(1, 1000))
            .fetch_all(&self.pool)
            .await?
        };
        rows.iter().map(finding_record_from_row).collect()
    }

    pub async fn list_open_findings(&self, limit: i64) -> Result<Vec<FindingRecord>> {
        let rows = sqlx::query(
            r#"
            SELECT id, fingerprint, target, scope, kind, severity, title, detail,
                   source, status, first_seen, last_seen, occurrence_count,
                   evidence_event_id, resolved_at
            FROM operational_findings
            WHERE status NOT IN ('resolved', 'false_positive')
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 5
                    WHEN 'high' THEN 4
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 2
                    ELSE 1
                END DESC,
                last_seen DESC
            LIMIT $1
            "#,
        )
        .bind(limit.clamp(1, 1000))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(finding_record_from_row).collect()
    }

    pub async fn count_open_findings(&self) -> Result<i64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM operational_findings
             WHERE status NOT IN ('resolved', 'false_positive')",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    pub async fn set_finding_status(&self, id: Uuid, status: FindingStatus) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE operational_findings
            SET status = $2,
                resolved_at = CASE
                    WHEN $2 IN ('resolved', 'false_positive') THEN NOW()
                    ELSE NULL
                END
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(status.as_str())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

fn validate_target_name(name: &str) -> Result<()> {
    let re = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")?;
    if !re.is_match(name) {
        bail!(
            "target name must be 1-64 characters and contain only letters, digits, '.', '_' or '-'"
        );
    }
    Ok(())
}

fn severity_name(severity: &Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn target_label(target: &Target) -> String {
    match target {
        Target::Local => "local".to_string(),
        Target::Ssh { destination } => format!("ssh:{destination}"),
    }
}

fn finding_fingerprint(target: &Target, finding: &Finding) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(target)?);
    hasher.update(b"\0");
    hasher.update(finding.kind.as_bytes());
    hasher.update(b"\0");
    hasher.update(finding.title.trim().as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

fn target_record_from_row(row: &sqlx::postgres::PgRow) -> Result<TargetRecord> {
    let target = serde_json::from_value::<Target>(row.get::<Value, _>("target"))?;
    Ok(TargetRecord {
        id: row.get("id"),
        name: row.get("name"),
        target_label: target_label(&target),
        target,
        tags: row.get("tags"),
        enabled: row.get("enabled"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn finding_record_from_row(row: &sqlx::postgres::PgRow) -> Result<FindingRecord> {
    let target = serde_json::from_value::<Target>(row.get::<Value, _>("target"))?;
    let status = FindingStatus::parse(row.get::<String, _>("status").as_str())?;
    Ok(FindingRecord {
        id: row.get("id"),
        fingerprint: row.get("fingerprint"),
        target_label: target_label(&target),
        target,
        scope: row.get("scope"),
        kind: row.get("kind"),
        severity: row.get("severity"),
        title: row.get("title"),
        detail: row.get("detail"),
        source: row.get("source"),
        status,
        first_seen: row.get("first_seen"),
        last_seen: row.get("last_seen"),
        occurrence_count: row.get("occurrence_count"),
        evidence_event_id: row.get("evidence_event_id"),
        resolved_at: row.get("resolved_at"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_status_aliases_parse() {
        assert_eq!(
            FindingStatus::parse("false-positive").unwrap(),
            FindingStatus::FalsePositive
        );
        assert_eq!(
            FindingStatus::parse("planned").unwrap(),
            FindingStatus::RemediationPlanned
        );
    }

    #[test]
    fn target_name_validation_is_conservative() {
        assert!(validate_target_name("web-01.prod").is_ok());
        assert!(validate_target_name("bad target").is_err());
        assert!(validate_target_name("../bad").is_err());
    }
}
''',
)

write(
    "src/cli.rs",
    r'''use anyhow::{Context, Result, bail};
use reqwest::header::{HeaderName, HeaderValue};
use serde_json::Value;
use sqlx::Row;
use std::path::Path;
use uuid::Uuid;

use crate::{
    active_defense::types::Target,
    config::DemonClawConfig,
    evidence::EvidenceLocker,
    memory::MemoryManager,
    operations::{FindingStatus, OperationsStore},
};

pub async fn handle_cli() -> Result<bool> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(false);
    };

    match command {
        "run" => Ok(false),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(true)
        }
        "version" | "--version" | "-V" => {
            println!("demonclaw {}", env!("CARGO_PKG_VERSION"));
            Ok(true)
        }
        "init" => {
            init_config()?;
            Ok(true)
        }
        "migrate" => {
            migrate().await?;
            Ok(true)
        }
        "doctor" => {
            doctor().await?;
            Ok(true)
        }
        "status" => {
            print_api_status().await?;
            Ok(true)
        }
        "target" => {
            target_command(&args[1..]).await?;
            Ok(true)
        }
        "findings" => {
            findings_command(&args[1..]).await?;
            Ok(true)
        }
        "scan" => {
            scan_command(&args[1..]).await?;
            Ok(true)
        }
        "verify" => {
            let name = required_arg(&args[1..], 0, "verify <target-name>")?;
            submit_for_target("verify", name, false).await?;
            Ok(true)
        }
        "defend" => {
            defend_command(&args[1..]).await?;
            Ok(true)
        }
        "remediate" => {
            remediate_command(&args[1..]).await?;
            Ok(true)
        }
        other => bail!("unknown command '{other}'. Run 'demonclaw help'."),
    }
}

fn print_help() {
    println!(
        r#"DemonClaw — controlled purple-team and defensive operations runtime

USAGE:
  demonclaw run
  demonclaw init
  demonclaw migrate
  demonclaw doctor
  demonclaw status

TARGETS:
  demonclaw target add <name> --local [--tag <tag> ...]
  demonclaw target add <name> --ssh <user@host|host> [--tag <tag> ...]
  demonclaw target list
  demonclaw target remove <name>

DEFENSIVE OPERATIONS:
  demonclaw scan vuln <target-name>
  demonclaw scan intrusion <target-name>
  demonclaw verify <target-name>
  demonclaw defend baseline <target-name>
  demonclaw defend drift <target-name> [--apply]
  demonclaw defend run <target-name> [--apply]
  demonclaw remediate plan <target-name>
  demonclaw remediate apply <target-name>

FINDINGS:
  demonclaw findings list [--status <status>]
  demonclaw findings status <finding-uuid> <status>

Environment:
  DEMONCLAW_API_URL overrides the local daemon API URL.
  The configured ingest token is read from DEMONCLAW_TOKEN (or the configured token env name).
"#
    );
}

fn init_config() -> Result<()> {
    let path = Path::new("demonclaw.json");
    if path.exists() {
        bail!("demonclaw.json already exists; refusing to overwrite it");
    }
    let content = serde_json::to_string_pretty(&DemonClawConfig::default())?;
    std::fs::write(path, format!("{content}\n"))?;
    println!("Created demonclaw.json with safe defaults.");
    println!("Next: set POSTGRES_PASSWORD, DATABASE_URL and DEMONCLAW_TOKEN in your environment.");
    Ok(())
}

async fn migrate() -> Result<()> {
    let cfg = DemonClawConfig::load()?;
    let memory = MemoryManager::new(&cfg.runtime.database_url)
        .await
        .context("database connection failed")?;
    memory.init_schema().await.context("SQLx migrations failed")?;
    let evidence = EvidenceLocker::new(memory.pool.clone());
    evidence
        .init_schema()
        .await
        .context("Evidence Locker schema initialization failed")?;
    println!("Database migrations and Evidence Locker schema are current.");
    Ok(())
}

async fn doctor() -> Result<()> {
    let cfg = DemonClawConfig::load().context("configuration is invalid")?;
    let mut failures = 0usize;

    println!("DemonClaw doctor");
    println!("  [ok] configuration parsed");

    if cfg.security.ingest_auth_enabled {
        match std::env::var(&cfg.security.ingest_token_env) {
            Ok(value) if !value.trim().is_empty() => println!("  [ok] ingest token is configured"),
            _ => {
                println!(
                    "  [fail] ingest authentication is enabled but {} is unset/empty",
                    cfg.security.ingest_token_env
                );
                failures += 1;
            }
        }
    } else {
        println!("  [warn] ingest authentication is disabled");
    }

    let memory = match MemoryManager::new(&cfg.runtime.database_url).await {
        Ok(memory) => {
            println!("  [ok] PostgreSQL reachable");
            memory
        }
        Err(error) => {
            println!("  [fail] PostgreSQL unavailable: {error}");
            bail!("doctor found a critical failure");
        }
    };

    match sqlx::query("SELECT extversion FROM pg_extension WHERE extname = 'vector'")
        .fetch_optional(&memory.pool)
        .await
    {
        Ok(Some(row)) => {
            let version: String = row.get("extversion");
            println!("  [ok] pgvector installed ({version})");
        }
        Ok(None) => {
            println!("  [fail] pgvector extension is not installed");
            failures += 1;
        }
        Err(error) => {
            println!("  [fail] pgvector check failed: {error}");
            failures += 1;
        }
    }

    match sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&memory.pool)
        .await
    {
        Ok(count) => println!("  [ok] SQLx migration ledger present ({count} applied)"),
        Err(error) => {
            println!("  [fail] migrations have not been applied: {error}");
            failures += 1;
        }
    }

    let evidence = EvidenceLocker::new(memory.pool.clone());
    match evidence.verify_chain().await {
        Ok(result) if result.is_valid => println!(
            "  [ok] Evidence Locker chain valid ({} events)",
            result.total_events
        ),
        Ok(result) => {
            println!(
                "  [fail] Evidence Locker chain invalid ({} broken links, {} hash mismatches)",
                result.broken_links.len(),
                result.hash_mismatches.len()
            );
            failures += 1;
        }
        Err(error) => {
            println!("  [fail] Evidence Locker unavailable: {error}");
            failures += 1;
        }
    }

    let operations = OperationsStore::new(memory.pool.clone());
    match operations.list_targets().await {
        Ok(targets) => println!("  [ok] operational state available ({} targets)", targets.len()),
        Err(error) => {
            println!("  [fail] operational state unavailable: {error}");
            failures += 1;
        }
    }

    if cfg.security.ingest_auth_enabled {
        match reqwest::Client::new()
            .get(format!("{}/healthz", api_base_url(&cfg)))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => println!("  [ok] local daemon API reachable"),
            _ => println!("  [warn] local daemon API is not currently reachable"),
        }
    }

    if failures > 0 {
        bail!("doctor found {failures} critical issue(s)");
    }
    println!("Doctor completed with no critical issues.");
    Ok(())
}

async fn target_command(args: &[String]) -> Result<()> {
    let action = required_arg(args, 0, "target <add|list|remove> ...")?;
    let store = open_store(true).await?;
    match action {
        "add" => {
            let name = required_arg(args, 1, "target add <name> --local|--ssh <destination>")?;
            let target = if args.iter().any(|value| value == "--local") {
                Target::Local
            } else if let Some(index) = args.iter().position(|value| value == "--ssh") {
                let destination = args
                    .get(index + 1)
                    .context("--ssh requires a destination")?
                    .trim();
                if destination.is_empty() || destination.starts_with('-') {
                    bail!("invalid SSH destination");
                }
                Target::Ssh {
                    destination: destination.to_string(),
                }
            } else {
                bail!("target add requires either --local or --ssh <destination>");
            };
            let tags = values_after_flag(args, "--tag");
            let record = store.add_target(name, target, tags).await?;
            println!("registered target {} -> {}", record.name, record.target_label);
        }
        "list" => {
            let targets = store.list_targets().await?;
            if targets.is_empty() {
                println!("No registered targets.");
            }
            for target in targets {
                let tags = if target.tags.is_empty() {
                    "-".to_string()
                } else {
                    target.tags.join(",")
                };
                println!(
                    "{:<24} {:<40} tags={} enabled={}",
                    target.name, target.target_label, tags, target.enabled
                );
            }
        }
        "remove" => {
            let name = required_arg(args, 1, "target remove <name>")?;
            if store.remove_target(name).await? {
                println!("removed target {name}");
            } else {
                bail!("target '{name}' does not exist");
            }
        }
        other => bail!("unknown target action '{other}'"),
    }
    Ok(())
}

async fn findings_command(args: &[String]) -> Result<()> {
    let action = required_arg(args, 0, "findings <list|status> ...")?;
    let store = open_store(false).await?;
    match action {
        "list" => {
            let status = if let Some(index) = args.iter().position(|value| value == "--status") {
                Some(FindingStatus::parse(
                    args.get(index + 1).context("--status requires a value")?,
                )?)
            } else {
                None
            };
            let findings = store.list_findings(status, 200).await?;
            if findings.is_empty() {
                println!("No findings.");
            }
            for finding in findings {
                println!(
                    "{} {:<9} {:<20} {:<28} {}",
                    finding.id,
                    finding.severity,
                    finding.status.as_str(),
                    finding.target_label,
                    finding.title
                );
            }
        }
        "status" => {
            let id = Uuid::parse_str(required_arg(
                args,
                1,
                "findings status <finding-uuid> <status>",
            )?)?;
            let status = FindingStatus::parse(required_arg(
                args,
                2,
                "findings status <finding-uuid> <status>",
            )?)?;
            if !store.set_finding_status(id, status.clone()).await? {
                bail!("finding {id} does not exist");
            }
            println!("finding {id} -> {}", status.as_str());
        }
        other => bail!("unknown findings action '{other}'"),
    }
    Ok(())
}

async fn scan_command(args: &[String]) -> Result<()> {
    let kind = required_arg(args, 0, "scan <vuln|intrusion> <target-name>")?;
    let target_name = required_arg(args, 1, "scan <vuln|intrusion> <target-name>")?;
    let command = match kind {
        "vuln" => "scan:vuln",
        "intrusion" => "scan:intrusion",
        other => bail!("unknown scan kind '{other}'"),
    };
    submit_for_target(command, target_name, false).await
}

async fn defend_command(args: &[String]) -> Result<()> {
    let action = required_arg(args, 0, "defend <baseline|drift|run> <target-name>")?;
    let target_name = required_arg(args, 1, "defend <baseline|drift|run> <target-name>")?;
    let apply = args.iter().any(|value| value == "--apply");
    let command = match action {
        "baseline" => "defend:baseline",
        "drift" => "defend:drift",
        "run" => "defend:run",
        other => bail!("unknown defend action '{other}'"),
    };
    submit_for_target(command, target_name, apply).await
}

async fn remediate_command(args: &[String]) -> Result<()> {
    let action = required_arg(args, 0, "remediate <plan|apply> <target-name>")?;
    let target_name = required_arg(args, 1, "remediate <plan|apply> <target-name>")?;
    let command = match action {
        "plan" => "remediate:plan",
        "apply" => "remediate:apply",
        other => bail!("unknown remediation action '{other}'"),
    };
    submit_for_target(command, target_name, false).await
}

async fn submit_for_target(command: &str, target_name: &str, apply: bool) -> Result<()> {
    let store = open_store(false).await?;
    let target = store
        .resolve_target(target_name)
        .await?
        .with_context(|| format!("target '{target_name}' is not registered or is disabled"))?;
    let mut content = format!("{command} --target {}", target_token(&target));
    if apply {
        content.push_str(" --apply");
    }
    submit_envelope(&content).await?;
    println!("submitted {command} for {target_name}");
    Ok(())
}

async fn submit_envelope(content: &str) -> Result<Value> {
    let cfg = DemonClawConfig::load()?;
    let client = reqwest::Client::new();
    let mut request = client
        .post(format!("{}/ingest", api_base_url(&cfg)))
        .json(&serde_json::json!({"content": content}));

    if cfg.security.ingest_auth_enabled {
        let token = std::env::var(&cfg.security.ingest_token_env).with_context(|| {
            format!("{} is required for daemon API authentication", cfg.security.ingest_token_env)
        })?;
        let header_name = HeaderName::from_bytes(cfg.security.ingest_auth_header.as_bytes())?;
        let header_value = HeaderValue::from_str(&token)?;
        request = request.header(header_name, header_value);
    }

    let response = request.send().await.context("failed to reach DemonClaw daemon")?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("daemon returned {status}: {body}");
    }
    Ok(serde_json::from_str(&body)?)
}

async fn print_api_status() -> Result<()> {
    let cfg = DemonClawConfig::load()?;
    let response = reqwest::Client::new()
        .get(format!("{}/api/status", api_base_url(&cfg)))
        .send()
        .await
        .context("failed to reach DemonClaw daemon")?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("daemon returned {status}: {body}");
    }
    let value: Value = serde_json::from_str(&body)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn open_store(run_migrations: bool) -> Result<OperationsStore> {
    let cfg = DemonClawConfig::load()?;
    let memory = MemoryManager::new(&cfg.runtime.database_url)
        .await
        .context("database connection failed")?;
    if run_migrations {
        memory.init_schema().await?;
    }
    Ok(OperationsStore::new(memory.pool))
}

fn api_base_url(cfg: &DemonClawConfig) -> String {
    if let Ok(value) = std::env::var("DEMONCLAW_API_URL")
        && !value.trim().is_empty()
    {
        return value.trim_end_matches('/').to_string();
    }
    let bind = cfg.server.http_bind.trim();
    let normalized = bind
        .strip_prefix("0.0.0.0:")
        .map(|port| format!("127.0.0.1:{port}"))
        .unwrap_or_else(|| bind.to_string());
    format!("http://{normalized}")
}

fn target_token(target: &Target) -> String {
    match target {
        Target::Local => "local".to_string(),
        Target::Ssh { destination } => format!("ssh:{destination}"),
    }
}

fn required_arg<'a>(args: &'a [String], index: usize, usage: &str) -> Result<&'a str> {
    args.get(index)
        .map(String::as_str)
        .with_context(|| format!("usage: demonclaw {usage}"))
}

fn values_after_flag(args: &[String], flag: &str) -> Vec<String> {
    args.iter()
        .enumerate()
        .filter_map(|(index, value)| {
            (value == flag)
                .then(|| args.get(index + 1))
                .flatten()
                .filter(|value| !value.starts_with('-'))
                .cloned()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_tokens_hide_internal_shape() {
        assert_eq!(target_token(&Target::Local), "local");
        assert_eq!(
            target_token(&Target::Ssh {
                destination: "admin@10.0.0.5".to_string()
            }),
            "ssh:admin@10.0.0.5"
        );
    }
}
''',
)

write(
    "templates/operations.html",
    r'''{% extends "base.html" %}
{% block title %}Operations — DemonClaw{% endblock %}
{% block content %}
<div class="stats">
  <div class="stat"><div class="stat-lbl">Registered Targets</div><div class="stat-val c">{{ targets | length }}</div></div>
  <div class="stat"><div class="stat-lbl">Open Findings</div><div class="stat-val {% if open_count > 0 %}r{% else %}g{% endif %}">{{ open_count }}</div></div>
</div>

<div class="card">
  <div class="card-hdr">Registered Targets <span class="badge bg-c">CLI: demonclaw target</span></div>
  <div class="card-body">
    {% if targets | length == 0 %}<div class="empty">No targets registered. Use <code>demonclaw target add</code>.</div>{% else %}
    <table class="tbl">
      <thead><tr><th>Name</th><th>Target</th><th>Tags</th><th>Enabled</th><th>Updated</th></tr></thead>
      <tbody>{% for target in targets %}<tr>
        <td><strong>{{ target.name }}</strong></td><td><code>{{ target.target_label }}</code></td>
        <td>{{ target.tags | join(sep=",") | default(value="-") }}</td>
        <td>{% if target.enabled %}<span class="badge bg-g">YES</span>{% else %}<span class="badge bg-r">NO</span>{% endif %}</td>
        <td class="time">{{ target.updated_at | date(format="%b %d %H:%M:%S") }}</td>
      </tr>{% endfor %}</tbody>
    </table>{% endif %}
  </div>
</div>

<div class="card">
  <div class="card-hdr">Finding Lifecycle <span class="badge bg-p">persistent state</span></div>
  <div class="card-body">
    {% if findings | length == 0 %}<div class="empty">No findings recorded.</div>{% else %}
    <table class="tbl">
      <thead><tr><th>Severity</th><th>Status</th><th>Target</th><th>Finding</th><th>Seen</th><th>Count</th></tr></thead>
      <tbody>{% for finding in findings %}<tr>
        <td><span class="badge {% if finding.severity == 'critical' or finding.severity == 'high' %}bg-r{% elif finding.severity == 'medium' %}bg-y{% else %}bg-c{% endif %}">{{ finding.severity }}</span></td>
        <td><span class="badge {% if finding.status == 'resolved' %}bg-g{% elif finding.status == 'false_positive' %}bg-c{% else %}bg-p{% endif %}">{{ finding.status }}</span></td>
        <td><code>{{ finding.target_label }}</code></td><td><strong>{{ finding.title }}</strong><div class="db">{{ finding.detail }}</div></td>
        <td class="time">{{ finding.last_seen | date(format="%b %d %H:%M:%S") }}</td><td>{{ finding.occurrence_count }}</td>
      </tr>{% endfor %}</tbody>
    </table>{% endif %}
  </div>
</div>
{% endblock %}
''',
)

write(
    "src/lib.rs",
    '''pub mod active_defense;\npub mod channels;\npub mod cli;\npub mod config;\npub mod darkprompt;\npub mod embeddings;\npub mod evidence;\npub mod ghostmcp;\npub mod r#loop;\npub mod memory;\npub mod operations;\npub mod sandbox;\npub mod scanner;\npub mod scheduler;\npub mod security;\npub mod signalgate;\npub mod tls;\npub mod types;\n''',
)

write(
    "src/main.rs",
    r'''use anyhow::{Context, Result, bail, ensure};
use std::sync::Arc;
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;

use demonclaw::{
    channels::Channels,
    config::DemonClawConfig,
    darkprompt::DarkPrompt,
    evidence::EvidenceLocker,
    ghostmcp::GhostMcp,
    r#loop::{AgentLoop, AgentLoopDeps},
    memory::MemoryManager,
    operations::OperationsStore,
    sandbox::Sandbox,
    scanner::Scanner,
    scheduler::Scheduler,
    signalgate::SignalGate,
};

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    if demonclaw::cli::handle_cli().await? {
        return Ok(());
    }
    run_daemon().await
}

async fn run_daemon() -> Result<()> {
    let cfg = DemonClawConfig::load()?;
    if cfg.security.ingest_auth_enabled {
        let token = std::env::var(&cfg.security.ingest_token_env).with_context(|| {
            format!(
                "ingest authentication is enabled but {} is not set",
                cfg.security.ingest_token_env
            )
        })?;
        ensure!(
            !token.trim().is_empty(),
            "ingest authentication is enabled but {} is empty",
            cfg.security.ingest_token_env
        );
    }

    let log_level = match cfg.logging.level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("failed to install tracing subscriber")?;

    info!("DemonClaw initialized. Core architecture booting...");

    let security_policy = cfg.security_policy();
    let signalgate = SignalGate::new(cfg.signalgate_config())?;
    let sandbox = Sandbox::new()?;
    let ghostmcp = GhostMcp::new();
    let scanner = Scanner::new();
    let darkprompt = DarkPrompt::new();

    let memory = MemoryManager::new(&cfg.runtime.database_url)
        .await
        .context("DemonClaw requires a reachable PostgreSQL and pgvector database")?;
    memory
        .init_schema()
        .await
        .context("failed to initialize database migrations")?;

    let evidence_locker = EvidenceLocker::new(memory.pool.clone());
    evidence_locker
        .init_schema()
        .await
        .context("failed to initialize Evidence Locker schema")?;
    let operations = OperationsStore::new(memory.pool.clone());

    let memory_optimizer = memory.clone();
    tokio::spawn(async move {
        memory_optimizer.run_optimizer(3600).await;
    });

    let mut agent_loop = AgentLoop::new(AgentLoopDeps {
        signalgate,
        memory: memory.clone(),
        sandbox,
        ghostmcp,
        scanner,
        darkprompt,
        security_policy: security_policy.clone(),
        evidence_locker: evidence_locker.clone(),
        operations: operations.clone(),
        max_concurrent_payloads: cfg.runtime.max_concurrent_payloads,
    });

    let (tx, rx) = tokio::sync::mpsc::channel(cfg.runtime.event_buffer);

    let scheduler = Scheduler::new(tx.clone());
    let channels = Arc::new(Channels::new(
        tx.clone(),
        cfg.security.clone(),
        evidence_locker,
        operations,
        security_policy,
        Some(memory),
    ));

    let heartbeat_secs = cfg.runtime.scheduler_interval_secs;
    tokio::spawn(async move {
        scheduler.run_heartbeat(heartbeat_secs).await;
    });

    let scheduler_jobs = Scheduler::new(tx.clone());
    scheduler_jobs.spawn_jobs(&cfg.runtime.scheduler_jobs);

    let channels_repl = channels.clone();
    tokio::spawn(async move {
        channels_repl.run_repl().await;
    });

    let agent_task = tokio::spawn(async move { agent_loop.run(rx).await });
    let http_bind = cfg.server.http_bind.clone();
    let channels_http = channels.clone();

    tokio::select! {
        result = agent_task => {
            result.context("agent loop task failed")??;
            bail!("agent loop exited unexpectedly")
        }
        result = channels_http.run_http_server(&http_bind) => {
            result.context("HTTP server failed")?;
            bail!("HTTP server exited unexpectedly")
        }
    }
}
''',
)

replace_once(
    "src/loop/mod.rs",
    "    memory::MemoryManager,\n    sandbox::{Manifest, Sandbox},",
    "    memory::MemoryManager,\n    operations::OperationsStore,\n    sandbox::{Manifest, Sandbox},",
)
replace_once(
    "src/loop/mod.rs",
    "    evidence_locker: EvidenceLocker,\n    payload_slots: Semaphore,",
    "    evidence_locker: EvidenceLocker,\n    operations: OperationsStore,\n    payload_slots: Semaphore,",
)
replace_once(
    "src/loop/mod.rs",
    "    pub evidence_locker: EvidenceLocker,\n    pub max_concurrent_payloads: usize,",
    "    pub evidence_locker: EvidenceLocker,\n    pub operations: OperationsStore,\n    pub max_concurrent_payloads: usize,",
)
replace_once(
    "src/loop/mod.rs",
    "            evidence_locker: deps.evidence_locker,\n            payload_slots:",
    "            evidence_locker: deps.evidence_locker,\n            operations: deps.operations,\n            payload_slots:",
)
replace_once(
    "src/loop/mod.rs",
    "                            &self.evidence_locker,\n                        )",
    "                            &self.evidence_locker,\n                            &self.operations,\n                        )",
)

replace_once(
    "src/active_defense/commands.rs",
    "    ghostmcp::GhostMcp,\n    security::{SecurityPolicy, ToolLevel},",
    "    ghostmcp::GhostMcp,\n    operations::OperationsStore,\n    security::{SecurityPolicy, ToolLevel},",
)
replace_once(
    "src/active_defense/commands.rs",
    "    evidence: &EvidenceLocker,\n) -> Result<bool> {",
    "    evidence: &EvidenceLocker,\n    operations: &OperationsStore,\n) -> Result<bool> {",
)
replace_once(
    "src/active_defense/commands.rs",
    '''            evidence
                .record(
                    "active_defense.scan.findings",
                    json!({"kind": req.kind, "target": req.target, "payload": evidence_payload_for_findings(&findings)}),
                    Some(env.id),
                )
                .await?;
''',
    '''            let scan_event = evidence
                .record(
                    "active_defense.scan.findings",
                    json!({"kind": req.kind, "target": req.target, "payload": evidence_payload_for_findings(&findings)}),
                    Some(env.id),
                )
                .await?;
            let scope = match req.kind {
                ScanKind::Vuln => "vulnerability",
                ScanKind::Intrusion => "intrusion",
            };
            operations
                .reconcile_findings(&req.target, scope, "scan", &findings, Some(scan_event.id))
                .await?;
''',
)
replace_once(
    "src/active_defense/commands.rs",
    '''            evidence
                .record(
                    "active_defense.findings",
                    evidence_payload_for_findings(&findings),
                    Some(env.id),
                )
                .await?;
''',
    '''            let findings_event = evidence
                .record(
                    "active_defense.findings",
                    evidence_payload_for_findings(&findings),
                    Some(env.id),
                )
                .await?;
            operations
                .reconcile_findings(
                    &target,
                    "vulnerability",
                    "verify",
                    &findings,
                    Some(findings_event.id),
                )
                .await?;
''',
)
replace_once(
    "src/active_defense/commands.rs",
    '''            let snapshot = capture_baseline(target.clone(), evidence, Some(env.id)).await?;
            evidence
''',
    '''            let vuln_findings = detect_vuln_findings(target.clone())?;
            let intrusion_findings = detect_intrusion_findings(target.clone())?;
            operations
                .reconcile_findings(&target, "vulnerability", "baseline", &vuln_findings, None)
                .await?;
            operations
                .reconcile_findings(&target, "intrusion", "baseline", &intrusion_findings, None)
                .await?;
            let snapshot = capture_baseline(target.clone(), evidence, Some(env.id)).await?;
            evidence
''',
)
replace_once(
    "src/active_defense/commands.rs",
    '''            let has_added = !report.added.is_empty();
            evidence
''',
    '''            let vuln_findings = detect_vuln_findings(target.clone())?;
            let intrusion_findings = detect_intrusion_findings(target.clone())?;
            operations
                .reconcile_findings(&target, "vulnerability", "drift", &vuln_findings, None)
                .await?;
            operations
                .reconcile_findings(&target, "intrusion", "drift", &intrusion_findings, None)
                .await?;

            let has_added = !report.added.is_empty();
            evidence
''',
)
replace_once(
    "src/active_defense/commands.rs",
    '''            let mut findings = detect_vuln_findings(target.clone())?;
            findings.extend(detect_intrusion_findings(target.clone())?);
            evidence
                .record(
                    "active_defense.defend_run.findings",
                    evidence_payload_for_findings(&findings),
                    Some(env.id),
                )
                .await?;
''',
    '''            let vuln_findings = detect_vuln_findings(target.clone())?;
            let intrusion_findings = detect_intrusion_findings(target.clone())?;
            let mut findings = vuln_findings.clone();
            findings.extend(intrusion_findings.clone());
            let findings_event = evidence
                .record(
                    "active_defense.defend_run.findings",
                    evidence_payload_for_findings(&findings),
                    Some(env.id),
                )
                .await?;
            operations
                .reconcile_findings(
                    &target,
                    "vulnerability",
                    "defend_run",
                    &vuln_findings,
                    Some(findings_event.id),
                )
                .await?;
            operations
                .reconcile_findings(
                    &target,
                    "intrusion",
                    "defend_run",
                    &intrusion_findings,
                    Some(findings_event.id),
                )
                .await?;
''',
)

replace_once(
    "src/channels/mod.rs",
    "    config::SecurityConfig, evidence::EvidenceLocker, memory::MemoryManager,\n    security::SecurityPolicy, types::Envelope,",
    "    config::SecurityConfig, evidence::EvidenceLocker, memory::MemoryManager,\n    operations::{FindingStatus, OperationsStore}, security::SecurityPolicy, types::Envelope,",
)
replace_once(
    "src/channels/mod.rs",
    "    evidence: EvidenceLocker,\n    policy: SecurityPolicy,",
    "    evidence: EvidenceLocker,\n    operations: OperationsStore,\n    policy: SecurityPolicy,",
)
replace_once(
    "src/channels/mod.rs",
    '''        evidence: EvidenceLocker,
        policy: SecurityPolicy,
        memory: Option<MemoryManager>,
''',
    '''        evidence: EvidenceLocker,
        operations: OperationsStore,
        policy: SecurityPolicy,
        memory: Option<MemoryManager>,
''',
)
replace_once(
    "src/channels/mod.rs",
    "            evidence,\n            policy,",
    "            evidence,\n            operations,\n            policy,",
)
replace_once(
    "src/channels/mod.rs",
    '''            .route("/dashboard/evidence", get(evidence_handler))
            .route("/dashboard/policy", get(policy_handler))
''',
    '''            .route("/dashboard/evidence", get(evidence_handler))
            .route("/dashboard/operations", get(operations_handler))
            .route("/dashboard/policy", get(policy_handler))
''',
)
replace_once(
    "src/channels/mod.rs",
    '''            .route("/api/evidence/verify", get(api_evidence_verify))
            .route("/api/policy", get(api_policy))
''',
    '''            .route("/api/evidence/verify", get(api_evidence_verify))
            .route("/api/targets", get(api_targets))
            .route("/api/findings", get(api_findings))
            .route("/api/policy", get(api_policy))
''',
)
replace_once(
    "src/channels/mod.rs",
    '''    ctx.insert("tool_level", &format!("{:?}", state.policy.max_tool_level));
    ctx.insert("engagement_id", &state.policy.engagement_id);

    let html = render_template(&state.templates, "dashboard.html", &ctx)?;
''',
    '''    ctx.insert("tool_level", &format!("{:?}", state.policy.max_tool_level));
    ctx.insert("engagement_id", &state.policy.engagement_id);
    let targets = state
        .operations
        .list_targets()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let open_findings = state
        .operations
        .list_open_findings(8)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let open_finding_count = state
        .operations
        .count_open_findings()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    ctx.insert("target_count", &targets.len());
    ctx.insert("open_finding_count", &open_finding_count);
    ctx.insert("open_findings", &open_findings);

    let html = render_template(&state.templates, "dashboard.html", &ctx)?;
''',
)
replace_once(
    "src/channels/mod.rs",
    "async fn policy_handler(\n",
    '''async fn operations_handler(
    State(state): State<Arc<Channels>>,
) -> Result<Html<String>, (StatusCode, String)> {
    let targets = state
        .operations
        .list_targets()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let findings = state
        .operations
        .list_findings(None, 250)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let open_count = state
        .operations
        .count_open_findings()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut ctx = tera::Context::new();
    ctx.insert("page", &"operations");
    ctx.insert("targets", &targets);
    ctx.insert("findings", &findings);
    ctx.insert("open_count", &open_count);
    let html = render_template(&state.templates, "operations.html", &ctx)?;
    Ok(Html(html))
}

async fn policy_handler(
''',
)
replace_once(
    "src/channels/mod.rs",
    '''    Ok(Json(serde_json::json!({
        "status": "operational",
        "evidence_count": evidence_count,
        "latest_events": latest_events,
''',
    '''    let target_count = state
        .operations
        .list_targets()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .len();
    let open_finding_count = state
        .operations
        .count_open_findings()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "operational",
        "evidence_count": evidence_count,
        "registered_targets": target_count,
        "open_findings": open_finding_count,
        "latest_events": latest_events,
''',
)
replace_once(
    "src/channels/mod.rs",
    "async fn api_policy(\n",
    '''async fn api_targets(
    State(state): State<Arc<Channels>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let targets = state
        .operations
        .list_targets()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({"targets": targets})))
}

async fn api_findings(
    State(state): State<Arc<Channels>>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let status = params
        .get("status")
        .map(|value| FindingStatus::parse(value))
        .transpose()
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let findings = state
        .operations
        .list_findings(status, 250)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({"findings": findings})))
}

async fn api_policy(
''',
)

base = read("templates/base.html")
base = base.replace(".verify.bad{background:rgba(255,61,87,.07);border:1px solid var(--red-dim}", ".verify.bad{background:rgba(255,61,87,.07);border:1px solid var(--red-dim)}")
base = base.replace(
    '''    <a class="sb-nav {% if page == 'dashboard' %}on{% endif %}" href="/dashboard/">◈ Dashboard</a>
    <a class="sb-nav {% if page == 'evidence' %}on{% endif %}" href="/dashboard/evidence">◉ Evidence</a>
''',
    '''    <a class="sb-nav {% if page == 'dashboard' %}on{% endif %}" href="/dashboard/">◈ Dashboard</a>
    <a class="sb-nav {% if page == 'operations' %}on{% endif %}" href="/dashboard/operations">◆ Operations</a>
    <a class="sb-nav {% if page == 'evidence' %}on{% endif %}" href="/dashboard/evidence">◉ Evidence</a>
''',
)
write("templates/base.html", base)

write(
    "templates/dashboard.html",
    r'''{% extends "base.html" %}
{% block title %}Dashboard — DemonClaw{% endblock %}
{% block content %}
<div class="stats">
  <div class="stat"><div class="stat-lbl">Registered Targets</div><div class="stat-val c">{{ target_count }}</div></div>
  <div class="stat"><div class="stat-lbl">Open Findings</div><div class="stat-val {% if open_finding_count > 0 %}r{% else %}g{% endif %}">{{ open_finding_count }}</div></div>
  <div class="stat"><div class="stat-lbl">Evidence Events</div><div class="stat-val a" id="evt-count">{{ evidence_count }}</div></div>
  <div class="stat"><div class="stat-lbl">Chain Integrity</div><div class="stat-val {% if chain_valid %}g{% else %}r{% endif %}">{% if chain_valid %}✓ VALID{% else %}✗ BROKEN{% endif %}</div></div>
  <div class="stat"><div class="stat-lbl">Tool Level</div><div class="stat-val c">{{ tool_level }}</div></div>
  <div class="stat"><div class="stat-lbl">Engagement</div><div class="stat-val c">{{ engagement_id | default(value="None") }}</div></div>
</div>

<div class="card">
  <div class="card-hdr">Open Findings <a href="/dashboard/operations">View operations →</a></div>
  <div class="card-body">
    {% if open_findings | length == 0 %}<div class="empty">No open findings.</div>{% else %}
    <table class="tbl"><thead><tr><th>Severity</th><th>Target</th><th>Finding</th><th>Status</th><th>Last Seen</th></tr></thead>
    <tbody>{% for finding in open_findings %}<tr>
      <td><span class="badge {% if finding.severity == 'critical' or finding.severity == 'high' %}bg-r{% elif finding.severity == 'medium' %}bg-y{% else %}bg-c{% endif %}">{{ finding.severity }}</span></td>
      <td><code>{{ finding.target_label }}</code></td><td>{{ finding.title }}</td><td><span class="badge bg-p">{{ finding.status }}</span></td>
      <td class="time">{{ finding.last_seen | date(format="%b %d %H:%M:%S") }}</td>
    </tr>{% endfor %}</tbody></table>{% endif %}
  </div>
</div>

<div class="card">
  <div class="card-hdr">Recent Evidence <span class="badge bg-p">LIVE</span></div>
  <div class="card-body" id="events-body">
    {% if events | length == 0 %}<div class="empty" id="no-events">No evidence events recorded yet.</div>{% else %}
    <table class="tbl" id="events-tbl"><thead><tr><th>Time</th><th>Kind</th><th>Detail</th></tr></thead><tbody id="events-tbody">
      {% for ev in events %}<tr><td class="time">{{ ev.timestamp | date(format="%b %d %H:%M:%S") }}</td>
      <td><span class="badge {% if ev.kind is containing("completed") %}bg-g{% elif ev.kind is containing("failed") or ev.kind is containing("denied") %}bg-r{% elif ev.kind is containing("running") %}bg-y{% else %}bg-c{% endif %}">{{ ev.kind }}</span></td>
      <td><div class="db" style="max-height:60px">{{ ev.detail }}</div></td></tr>{% endfor %}
    </tbody></table>{% endif %}
  </div>
</div>

<script>
(function(){
  var evtCount={{ evidence_count }}; var tbody=document.getElementById('events-tbody'); var eventsBody=document.getElementById('events-body'); var count=document.getElementById('evt-count');
  if(typeof EventSource==='undefined') return;
  var es=new EventSource('/api/events/stream');
  es.onmessage=function(msg){
    try{
      var ev=JSON.parse(msg.data); if(!tbody){ location.reload(); return; }
      var tr=document.createElement('tr'); var time=ev.timestamp?ev.timestamp.replace('T',' ').substring(0,19):'';
      tr.innerHTML='<td class="time">'+time+'</td><td><span class="badge bg-c">'+(ev.kind||ev.type||'event')+'</span></td><td><div class="db">'+JSON.stringify(ev.detail||ev)+'</div></td>';
      tbody.insertBefore(tr,tbody.firstChild); while(tbody.children.length>10) tbody.removeChild(tbody.lastChild); evtCount++; if(count) count.textContent=evtCount;
    }catch(e){}
  };
})();
</script>
{% endblock %}
''',
)

replace_once(
    ".github/workflows/ci.yml",
    "    branches: [main, org-sync, 'fix/**']",
    "    branches: [main, org-sync, 'fix/**', 'feat/**']",
)
replace_once(
    ".github/workflows/security.yml",
    "    branches: [main, org-sync, 'fix/**']",
    "    branches: [main, org-sync, 'fix/**', 'feat/**']",
)

replace_once(
    "CONFIG.md",
    "| `DEMONCLAW_HTTP_BIND` | `127.0.0.1:3000` | HTTP listener address |",
    "| `DEMONCLAW_HTTP_BIND` | `127.0.0.1:3000` | HTTP listener address |\n| `DEMONCLAW_API_URL` | derived from HTTP bind | CLI connection URL for an already-running daemon |",
)
replace_once(
    "CHANGELOG.md",
    "### Changed\n\n",
    "### Added\n\n- first-class registered targets and persistent finding lifecycle state\n- operator CLI for initialization, health checks, target management, findings, scans, defense, and remediation\n- operations dashboard and JSON APIs for targets and findings\n- versioned SQLx migration for operational state\n\n### Changed\n\n",
)

readme = read("README.md")
needle = "## Quick start\n"
if needle not in readme:
    raise SystemExit("README.md: Quick start heading missing")
readme = readme.replace(
    needle,
    '''## Operator CLI\n\nDemonClaw now exposes a supported operator CLI instead of requiring raw internal envelope commands:\n\n```bash\ndemonclaw init\ndemonclaw migrate\ndemonclaw doctor\ndemonclaw target add web-01 --ssh admin@10.0.0.20 --tag production\ndemonclaw defend baseline web-01\ndemonclaw scan vuln web-01\ndemonclaw findings list\n```\n\nThe daemon remains available with `demonclaw run`. CLI security operations submit authenticated commands to the local daemon after resolving the registered target.\n\n## Quick start\n''',
    1,
)
write("README.md", readme)
