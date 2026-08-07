from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}: {old[:80]!r}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


Path("src/active_defense/monitor.rs").write_text(
    '''use anyhow::Result;
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
''',
    encoding="utf-8",
)

replace_once(
    "src/active_defense/mod.rs",
    "pub mod findings;\npub mod probes;",
    "pub mod findings;\npub mod monitor;\npub mod probes;",
)

replace_once(
    "src/active_defense/remediation.rs",
    "use anyhow::Result;\nuse serde::{Deserialize, Serialize};",
    "use anyhow::Result;\nuse chrono::{NaiveTime, Utc};\nuse serde::{Deserialize, Serialize};",
)

replace_once(
    "src/active_defense/remediation.rs",
    '''pub fn is_action_allowed(action: &RemediationAction) -> bool {
    match action {
        RemediationAction::AptUpgrade { .. } => {
            bool_from_env("DEMONCLAW_REMEDIATE_ALLOW_APT_UPGRADE", false)
        }
    }
}
''',
    '''pub fn is_action_allowed(action: &RemediationAction) -> bool {
    match action {
        RemediationAction::AptUpgrade { .. } => {
            bool_from_env("DEMONCLAW_REMEDIATE_ALLOW_APT_UPGRADE", false)
        }
    }
}

fn parse_maintenance_window(value: &str) -> Option<(NaiveTime, NaiveTime)> {
    let (start, end) = value.trim().split_once('-')?;
    let start = NaiveTime::parse_from_str(start.trim(), "%H:%M").ok()?;
    let end = NaiveTime::parse_from_str(end.trim(), "%H:%M").ok()?;
    if start == end {
        return None;
    }
    Some((start, end))
}

pub fn auto_remediation_allowed_now() -> bool {
    if !bool_from_env("DEMONCLAW_REMEDIATE_AUTO", false) {
        return false;
    }

    let Ok(raw_window) = std::env::var("DEMONCLAW_REMEDIATE_MAINTENANCE_WINDOW_UTC") else {
        return false;
    };
    let Some((start, end)) = parse_maintenance_window(&raw_window) else {
        return false;
    };

    let now = Utc::now().time();
    if start < end {
        now >= start && now < end
    } else {
        now >= start || now < end
    }
}
''',
)

replace_once(
    "src/active_defense/commands.rs",
    '''    finders::{detect_intrusion_findings, detect_vuln_findings},
    probes::run_probe,
    remediation::{apply_action, is_action_allowed, plan_remediation},
''',
    '''    finders::{detect_intrusion_findings, detect_vuln_findings},
    monitor::{capture_baseline, evaluate_drift},
    probes::run_probe,
    remediation::{
        apply_action, auto_remediation_allowed_now, is_action_allowed, plan_remediation,
    },
''',
)

replace_once(
    "src/active_defense/commands.rs",
    '''    Verify { target: Target },
    DefendRun { target: Target, apply: bool },
''',
    '''    Verify { target: Target },
    Baseline { target: Target },
    Drift { target: Target, apply: bool },
    DefendRun { target: Target, apply: bool },
''',
)

replace_once(
    "src/active_defense/commands.rs",
    '''        "verify" => Some(ActiveDefenseCommand::Verify { target }),
        "defend:run" => Some(ActiveDefenseCommand::DefendRun { target, apply }),
''',
    '''        "verify" => Some(ActiveDefenseCommand::Verify { target }),
        "defend:baseline" => Some(ActiveDefenseCommand::Baseline { target }),
        "defend:drift" => Some(ActiveDefenseCommand::Drift { target, apply }),
        "defend:run" => Some(ActiveDefenseCommand::DefendRun { target, apply }),
''',
)

replace_once(
    "src/active_defense/commands.rs",
    '''        | ActiveDefenseCommand::Verify { target }
        | ActiveDefenseCommand::DefendRun { target, .. } => target,
''',
    '''        | ActiveDefenseCommand::Verify { target }
        | ActiveDefenseCommand::Baseline { target }
        | ActiveDefenseCommand::Drift { target, .. }
        | ActiveDefenseCommand::DefendRun { target, .. } => target,
''',
)

marker = "        ActiveDefenseCommand::DefendRun { target, apply } => {"
phase3_arms = '''        ActiveDefenseCommand::Baseline { target } => {
            security.check_tool_level(ToolLevel::Passive)?;
            if matches!(target, Target::Ssh { .. }) {
                security.check_engagement_context("active_defense_remote_baseline")?;
            }

            let snapshot = capture_baseline(target.clone(), evidence, Some(env.id)).await?;
            evidence
                .record(
                    "active_defense.baseline.completed",
                    json!({"target": target, "finding_count": snapshot.signatures.len()}),
                    Some(env.id),
                )
                .await?;
            Ok(true)
        }
        ActiveDefenseCommand::Drift { target, apply } => {
            security.check_tool_level(if apply {
                ToolLevel::Intrusive
            } else {
                ToolLevel::Passive
            })?;
            if matches!(target, Target::Ssh { .. }) {
                security.check_engagement_context("active_defense_remote_drift")?;
            }

            evidence
                .record(
                    "active_defense.drift.started",
                    json!({"target": target, "apply": apply}),
                    Some(env.id),
                )
                .await?;

            let Some(report) = evaluate_drift(target.clone(), evidence).await? else {
                let snapshot = capture_baseline(target.clone(), evidence, Some(env.id)).await?;
                evidence
                    .record(
                        "active_defense.drift.baseline_initialized",
                        json!({"target": target, "finding_count": snapshot.signatures.len()}),
                        Some(env.id),
                    )
                    .await?;
                return Ok(true);
            };

            let has_added = !report.added.is_empty();
            evidence
                .record(
                    "active_defense.drift.completed",
                    json!({"report": &report}),
                    Some(env.id),
                )
                .await?;

            if apply && has_added {
                if !auto_remediation_allowed_now() {
                    evidence
                        .record(
                            "active_defense.remediation.auto.denied",
                            json!({
                                "target": target,
                                "reason": "automatic remediation is disabled or outside the configured UTC maintenance window"
                            }),
                            Some(env.id),
                        )
                        .await?;
                    return Ok(true);
                }

                let approved = ghostmcp
                    .authorize_action("remediation:auto_apply")
                    .await
                    .unwrap_or(false);
                if !approved {
                    evidence
                        .record(
                            "active_defense.remediation.auto.denied",
                            json!({"target": target, "reason": "ghostmcp denied"}),
                            Some(env.id),
                        )
                        .await?;
                    return Ok(true);
                }

                let plan = plan_remediation(target.clone())?;
                let mut results = Vec::new();
                for action in plan.actions {
                    if !is_action_allowed(&action) {
                        evidence
                            .record(
                                "active_defense.remediation.auto.denied",
                                json!({
                                    "target": target,
                                    "reason": "action not allowed by policy",
                                    "action": action
                                }),
                                Some(env.id),
                            )
                            .await?;
                        continue;
                    }
                    results.push(apply_action(target.clone(), action)?);
                }

                evidence
                    .record(
                        "active_defense.remediation.auto.completed",
                        json!({"target": target, "results": results}),
                        Some(env.id),
                    )
                    .await?;
            }

            Ok(true)
        }
'''
replace_once("src/active_defense/commands.rs", marker, phase3_arms + marker)

replace_once(
    "CONFIG.md",
    '''| `DEMONCLAW_REMEDIATE_USE_SUDO` | `false` | Run supported remediation through non-interactive sudo |
| `DEMONCLAW_REMEDIATE_ALLOW_APT_UPGRADE` | `false` | Permit supported apt upgrade actions after approval |
''',
    '''| `DEMONCLAW_REMEDIATE_USE_SUDO` | `false` | Run supported remediation through non-interactive sudo |
| `DEMONCLAW_REMEDIATE_ALLOW_APT_UPGRADE` | `false` | Permit supported apt upgrade actions after approval |
| `DEMONCLAW_REMEDIATE_AUTO` | `false` | Permit scheduled drift checks to request automatic remediation |
| `DEMONCLAW_REMEDIATE_MAINTENANCE_WINDOW_UTC` | unset | Required UTC window for automatic remediation, formatted `HH:MM-HH:MM` |
''',
)

replace_once(
    "CONFIG.md",
    '''- `verify`
- `defend:run`
- `remediate:plan`
''',
    '''- `verify`
- `defend:run`
- `defend:baseline`
- `defend:drift`
- `remediate:plan`
''',
)

replace_once(
    "CONFIG.md",
    "Remote operations must remain inside the configured engagement and SSH scope. Verification and remediation actions are GhostMCP-gated where implemented.\n",
    '''Remote operations must remain inside the configured engagement and SSH scope. Verification and remediation actions are GhostMCP-gated where implemented.

Phase 3 drift monitoring reuses `runtime.scheduler_jobs`. Establish a reviewed baseline with `defend:baseline`, then schedule `defend:drift` as an interval or cron job. A scheduled `defend:drift --apply` remains fail-closed unless all of the following are true: the runtime permits intrusive tools, `DEMONCLAW_REMEDIATE_AUTO=1`, the current UTC time is inside `DEMONCLAW_REMEDIATE_MAINTENANCE_WINDOW_UTC`, GhostMCP approves `remediation:auto_apply`, and the individual remediation action is allowlisted.

Example polling job:

```json
{
  "runtime": {
    "scheduler_jobs": [
      {
        "name": "active-defense-drift",
        "content": "defend:drift --target local",
        "source": "scheduler",
        "interval_secs": 300
      }
    ]
  }
}
```
''',
)

replace_once(
    "ACTIVE_DEFENSE.md",
    '''### Phase 3

- continuous intrusion monitoring (polling and/or streaming)
- stateful baselines and drift detection
- auto-remediation allowlists + maintenance windows
''',
    '''### Phase 3

Implemented:

- scheduler-driven continuous polling through `defend:drift`
- persistent, tamper-evident baselines stored in Evidence Locker with `defend:baseline`
- drift reports separating newly observed, resolved, and unchanged findings
- optional `defend:drift --apply` auto-remediation with fail-closed maintenance windows
- automatic remediation still requires intrusive tool permission, GhostMCP approval, and the existing per-action allowlist
''',
)

replace_once(
    "CHANGELOG.md",
    "### Security\n\n",
    '''### Added

- Active Defense Phase 3 baselines and drift detection backed by tamper-evident evidence events
- scheduler-driven `defend:drift` monitoring and guarded `--apply` auto-remediation
- fail-closed UTC maintenance windows for automatic remediation

### Security

''',
)
