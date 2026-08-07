use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

use crate::evidence::EvidenceLocker;

use super::{
    finders::{detect_intrusion_findings, detect_vuln_findings},
    findings::Finding,
    types::Target,
};

pub const BASELINE_EVENT_KIND: &str = "active_defense.baseline";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaselineSnapshot {
    pub target: Target,
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriftReport {
    pub target: Target,
    pub added: Vec<String>,
    pub resolved: Vec<String>,
    pub unchanged: Vec<String>,
}

fn finding_signature(finding: &Finding) -> String {
    format!(
        "{}|{:?}|{}",
        finding.kind,
        finding.severity,
        finding.title.trim()
    )
}

fn collect_signatures(target: Target) -> Result<Vec<String>> {
    let mut findings = detect_vuln_findings(target.clone())?;
    findings.extend(detect_intrusion_findings(target)?);

    let mut signatures: Vec<String> = findings.iter().map(finding_signature).collect();
    signatures.sort();
    signatures.dedup();
    Ok(signatures)
}

fn diff_signatures(target: Target, baseline: &[String], current: &[String]) -> DriftReport {
    let baseline: BTreeSet<&str> = baseline.iter().map(String::as_str).collect();
    let current: BTreeSet<&str> = current.iter().map(String::as_str).collect();

    DriftReport {
        target,
        added: current
            .difference(&baseline)
            .map(|value| (*value).to_string())
            .collect(),
        resolved: baseline
            .difference(&current)
            .map(|value| (*value).to_string())
            .collect(),
        unchanged: current
            .intersection(&baseline)
            .map(|value| (*value).to_string())
            .collect(),
    }
}

pub async fn capture_baseline(
    target: Target,
    evidence: &EvidenceLocker,
    envelope_id: Option<Uuid>,
) -> Result<BaselineSnapshot> {
    let snapshot = BaselineSnapshot {
        signatures: collect_signatures(target.clone())?,
        target,
    };
    evidence
        .record(
            BASELINE_EVENT_KIND,
            serde_json::to_value(&snapshot)?,
            envelope_id,
        )
        .await?;
    Ok(snapshot)
}

pub async fn evaluate_drift(
    target: Target,
    evidence: &EvidenceLocker,
) -> Result<Option<DriftReport>> {
    let events = evidence.query_by_kind(BASELINE_EVENT_KIND, 100).await?;
    let baseline = events.into_iter().find_map(|event| {
        serde_json::from_value::<BaselineSnapshot>(event.detail)
            .ok()
            .filter(|snapshot| snapshot.target == target)
    });

    let Some(baseline) = baseline else {
        return Ok(None);
    };

    let current = collect_signatures(target.clone())?;
    Ok(Some(diff_signatures(
        target,
        &baseline.signatures,
        &current,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drift_reports_added_resolved_and_unchanged() {
        let baseline = vec!["a".to_string(), "b".to_string()];
        let current = vec!["b".to_string(), "c".to_string()];
        let report = diff_signatures(Target::Local, &baseline, &current);
        assert_eq!(report.added, vec!["c"]);
        assert_eq!(report.resolved, vec!["a"]);
        assert_eq!(report.unchanged, vec!["b"]);
    }
}
