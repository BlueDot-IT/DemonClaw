use anyhow::{Result, bail};
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
