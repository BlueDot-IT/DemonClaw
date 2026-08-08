use anyhow::Result;
use serde_json::json;
use tracing::info;

use crate::{
    evidence::EvidenceLocker,
    ghostmcp::GhostMcp,
    operations::OperationsStore,
    security::{SecurityPolicy, ToolLevel},
    types::Envelope,
};

use super::{
    finders::{detect_intrusion_findings, detect_vuln_findings},
    monitor::{capture_baseline, evaluate_drift},
    probes::run_probe,
    remediation::{
        apply_action, auto_remediation_allowed_now, is_action_allowed, plan_remediation,
    },
    types::{ProbeKind, ScanKind, ScanRequest, Target},
    verify::{evidence_payload_for_findings, evidence_payload_for_verifications, run_verify},
};

#[derive(Debug, Clone)]
enum ActiveDefenseCommand {
    Scan(ScanRequest),
    RemediatePlan { target: Target },
    RemediateApply { target: Target },
    Verify { target: Target },
    Baseline { target: Target },
    Drift { target: Target, apply: bool },
    DefendRun { target: Target, apply: bool },
}

fn parse_target(tokens: &[&str]) -> Target {
    // Default is local.
    // Accept:
    //   --target local
    //   --target ssh:user@host
    //   --target ssh:host
    for w in tokens.windows(2) {
        if w[0] == "--target" {
            let v = w[1];
            if v == "local" {
                return Target::Local;
            }
            if let Some(rest) = v.strip_prefix("ssh:") {
                return Target::Ssh {
                    destination: rest.to_string(),
                };
            }
        }
    }
    Target::Local
}

fn has_flag(tokens: &[&str], flag: &str) -> bool {
    tokens.contains(&flag)
}

fn validate_target_scope(security: &SecurityPolicy, target: &Target) -> Result<()> {
    let Target::Ssh { destination } = target else {
        return Ok(());
    };

    let host = destination
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(destination);
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);

    if host.parse::<std::net::IpAddr>().is_err() {
        security.validate_domain(host)?;
    }
    security.validate_target(host)?;
    Ok(())
}

fn parse_active_defense_command(env: &Envelope) -> Option<ActiveDefenseCommand> {
    let content = env.content.trim();
    let parts: Vec<&str> = content.split_whitespace().collect();
    let head = parts.first().copied().unwrap_or("");

    let target = parse_target(&parts);
    let apply = has_flag(&parts, "--apply");

    match head {
        "scan:vuln" => Some(ActiveDefenseCommand::Scan(ScanRequest {
            kind: ScanKind::Vuln,
            target,
        })),
        "scan:intrusion" => Some(ActiveDefenseCommand::Scan(ScanRequest {
            kind: ScanKind::Intrusion,
            target,
        })),
        "remediate:plan" => Some(ActiveDefenseCommand::RemediatePlan { target }),
        "remediate:apply" => Some(ActiveDefenseCommand::RemediateApply { target }),
        "verify" => Some(ActiveDefenseCommand::Verify { target }),
        "defend:baseline" => Some(ActiveDefenseCommand::Baseline { target }),
        "defend:drift" => Some(ActiveDefenseCommand::Drift { target, apply }),
        "defend:run" => Some(ActiveDefenseCommand::DefendRun { target, apply }),
        _ => None,
    }
}

pub async fn handle_active_defense_command(
    env: &Envelope,
    security: &SecurityPolicy,
    ghostmcp: &GhostMcp,
    evidence: &EvidenceLocker,
    operations: &OperationsStore,
) -> Result<bool> {
    let Some(cmd) = parse_active_defense_command(env) else {
        return Ok(false);
    };

    let target = match &cmd {
        ActiveDefenseCommand::Scan(request) => &request.target,
        ActiveDefenseCommand::RemediatePlan { target }
        | ActiveDefenseCommand::RemediateApply { target }
        | ActiveDefenseCommand::Verify { target }
        | ActiveDefenseCommand::Baseline { target }
        | ActiveDefenseCommand::Drift { target, .. }
        | ActiveDefenseCommand::DefendRun { target, .. } => target,
    };
    security.check_engagement_context("active_defense")?;
    validate_target_scope(security, target)?;

    match cmd {
        ActiveDefenseCommand::Scan(req) => {
            security.check_tool_level(ToolLevel::Passive)?;
            // Remote operations require explicit engagement context.
            if matches!(req.target, Target::Ssh { .. }) {
                security.check_engagement_context("active_defense_remote_scan")?;
            }

            info!("Active defense scan requested: {:?}", req.kind);
            evidence
                .record(
                    "active_defense.scan.started",
                    json!({"kind": req.kind, "target": req.target}),
                    Some(env.id),
                )
                .await?;

            // Phase 1: just run a couple of probes and record their results.
            let probe_set: &[ProbeKind] = match req.kind {
                ScanKind::Vuln => &[
                    ProbeKind::ListeningPorts,
                    ProbeKind::PackageInventory,
                    ProbeKind::UpgradablePackages,
                ],
                ScanKind::Intrusion => &[ProbeKind::ListeningPorts, ProbeKind::SshAuthLog],
            };

            for probe in probe_set {
                let probe_target = req.target.clone();
                let res = run_probe(probe_target, probe.clone())?;
                evidence
                    .record(
                        "active_defense.probe.completed",
                        json!({"result": res}),
                        Some(env.id),
                    )
                    .await?;
            }

            let findings = match req.kind {
                ScanKind::Vuln => detect_vuln_findings(req.target.clone())?,
                ScanKind::Intrusion => detect_intrusion_findings(req.target.clone())?,
            };
            let scan_event = evidence
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

            evidence
                .record(
                    "active_defense.scan.completed",
                    json!({"kind": req.kind, "target": req.target}),
                    Some(env.id),
                )
                .await?;

            Ok(true)
        }
        ActiveDefenseCommand::RemediatePlan { target } => {
            security.check_tool_level(ToolLevel::Passive)?;
            if matches!(target, Target::Ssh { .. }) {
                security.check_engagement_context("active_defense_remote_remediation_plan")?;
            }

            evidence
                .record(
                    "active_defense.remediation.plan.started",
                    json!({"target": target}),
                    Some(env.id),
                )
                .await?;

            let plan = plan_remediation(target.clone())?;

            evidence
                .record(
                    "active_defense.remediation.plan.completed",
                    json!({"plan": plan}),
                    Some(env.id),
                )
                .await?;

            Ok(true)
        }
        ActiveDefenseCommand::RemediateApply { target } => {
            security.check_tool_level(ToolLevel::Intrusive)?;
            if matches!(target, Target::Ssh { .. }) {
                security.check_engagement_context("active_defense_remote_remediation_apply")?;
            }

            // Always require explicit approval for remediation apply.
            let approved = ghostmcp
                .authorize_action("remediation:apply")
                .await
                .unwrap_or(false);
            if !approved {
                evidence
                    .record(
                        "active_defense.remediation.apply.denied",
                        json!({"target": target, "reason": "ghostmcp denied"}),
                        Some(env.id),
                    )
                    .await?;
                return Ok(true);
            }

            evidence
                .record(
                    "active_defense.remediation.apply.started",
                    json!({"target": target}),
                    Some(env.id),
                )
                .await?;

            let plan = plan_remediation(target.clone())?;
            let mut results = Vec::new();
            for action in plan.actions {
                if !is_action_allowed(&action) {
                    evidence
                        .record(
                            "active_defense.remediation.apply.denied",
                            json!({"target": target, "reason": "action not allowed by policy", "action": action}),
                            Some(env.id),
                        )
                        .await?;
                    continue;
                }
                let res = apply_action(target.clone(), action)?;
                results.push(res);
            }

            evidence
                .record(
                    "active_defense.remediation.apply.completed",
                    json!({"target": target, "results": results}),
                    Some(env.id),
                )
                .await?;

            Ok(true)
        }
        ActiveDefenseCommand::Verify { target } => {
            security.check_tool_level(ToolLevel::Passive)?;
            if matches!(target, Target::Ssh { .. }) {
                security.check_engagement_context("active_defense_remote_verify")?;
            }

            // Verification uses safe PoCs (read-only config interrogation) but still requires
            // explicit approval by default.
            let approved = ghostmcp
                .authorize_action("verify:safe_pocs")
                .await
                .unwrap_or(false);
            if !approved {
                evidence
                    .record(
                        "active_defense.verify.denied",
                        json!({"target": target, "reason": "ghostmcp denied"}),
                        Some(env.id),
                    )
                    .await?;
                return Ok(true);
            }

            evidence
                .record(
                    "active_defense.verify.started",
                    json!({"target": target}),
                    Some(env.id),
                )
                .await?;

            let (findings, verifications) = run_verify(target.clone())?;

            let findings_event = evidence
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
            evidence
                .record(
                    "active_defense.verifications",
                    evidence_payload_for_verifications(&verifications),
                    Some(env.id),
                )
                .await?;

            evidence
                .record(
                    "active_defense.verify.completed",
                    json!({"target": target}),
                    Some(env.id),
                )
                .await?;

            Ok(true)
        }
        ActiveDefenseCommand::Baseline { target } => {
            security.check_tool_level(ToolLevel::Passive)?;
            if matches!(target, Target::Ssh { .. }) {
                security.check_engagement_context("active_defense_remote_baseline")?;
            }

            let vuln_findings = detect_vuln_findings(target.clone())?;
            let intrusion_findings = detect_intrusion_findings(target.clone())?;
            operations
                .reconcile_findings(&target, "vulnerability", "baseline", &vuln_findings, None)
                .await?;
            operations
                .reconcile_findings(&target, "intrusion", "baseline", &intrusion_findings, None)
                .await?;
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

            let vuln_findings = detect_vuln_findings(target.clone())?;
            let intrusion_findings = detect_intrusion_findings(target.clone())?;
            operations
                .reconcile_findings(&target, "vulnerability", "drift", &vuln_findings, None)
                .await?;
            operations
                .reconcile_findings(&target, "intrusion", "drift", &intrusion_findings, None)
                .await?;

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
        ActiveDefenseCommand::DefendRun { target, apply } => {
            security.check_tool_level(if apply {
                ToolLevel::Intrusive
            } else {
                ToolLevel::Passive
            })?;
            if matches!(target, Target::Ssh { .. }) {
                security.check_engagement_context("active_defense_remote_defend_run")?;
            }

            evidence
                .record(
                    "active_defense.defend_run.started",
                    json!({"target": target}),
                    Some(env.id),
                )
                .await?;

            // Vuln scan probes.
            for probe in [
                ProbeKind::ListeningPorts,
                ProbeKind::PackageInventory,
                ProbeKind::UpgradablePackages,
            ] {
                let res = run_probe(target.clone(), probe)?;
                evidence
                    .record(
                        "active_defense.probe.completed",
                        json!({"result": res}),
                        Some(env.id),
                    )
                    .await?;
            }

            // Intrusion probes.
            for probe in [
                ProbeKind::SshAuthLog,
                ProbeKind::Uid0Accounts,
                ProbeKind::ProcessList,
            ] {
                let res = run_probe(target.clone(), probe)?;
                evidence
                    .record(
                        "active_defense.probe.completed",
                        json!({"result": res}),
                        Some(env.id),
                    )
                    .await?;
            }

            let vuln_findings = detect_vuln_findings(target.clone())?;
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

            // Verification: GhostMCP gated.
            let approved_verify = ghostmcp
                .authorize_action("verify:safe_pocs")
                .await
                .unwrap_or(false);
            if approved_verify {
                let (_findings2, verifications) = run_verify(target.clone())?;
                evidence
                    .record(
                        "active_defense.verifications",
                        evidence_payload_for_verifications(&verifications),
                        Some(env.id),
                    )
                    .await?;
            } else {
                evidence
                    .record(
                        "active_defense.verify.denied",
                        json!({"target": target, "reason": "ghostmcp denied"}),
                        Some(env.id),
                    )
                    .await?;
            }

            // Remediation planning.
            let plan = plan_remediation(target.clone())?;
            evidence
                .record(
                    "active_defense.remediation.plan.completed",
                    json!({"plan": plan}),
                    Some(env.id),
                )
                .await?;

            if apply {
                let approved_apply = ghostmcp
                    .authorize_action("remediation:apply")
                    .await
                    .unwrap_or(false);
                if approved_apply {
                    let plan = plan_remediation(target.clone())?;
                    let mut results = Vec::new();
                    for action in plan.actions {
                        if !is_action_allowed(&action) {
                            evidence
                                .record(
                                    "active_defense.remediation.apply.denied",
                                    json!({"target": target, "reason": "action not allowed by policy", "action": action}),
                                    Some(env.id),
                                )
                                .await?;
                            continue;
                        }
                        let res = apply_action(target.clone(), action)?;
                        results.push(res);
                    }

                    evidence
                        .record(
                            "active_defense.remediation.apply.completed",
                            json!({"target": target, "results": results}),
                            Some(env.id),
                        )
                        .await?;

                    // Post-remediation verification (still safe/read-only).
                    let (_findings2, verifications) = run_verify(target.clone())?;
                    evidence
                        .record(
                            "active_defense.verifications.post_remediation",
                            evidence_payload_for_verifications(&verifications),
                            Some(env.id),
                        )
                        .await?;
                } else {
                    evidence
                        .record(
                            "active_defense.remediation.apply.denied",
                            json!({"target": target, "reason": "ghostmcp denied"}),
                            Some(env.id),
                        )
                        .await?;
                }
            }

            evidence
                .record(
                    "active_defense.defend_run.completed",
                    json!({"target": target}),
                    Some(env.id),
                )
                .await?;

            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_defaults_local() {
        let env = Envelope::new("repl", "scan:vuln");
        let cmd = parse_active_defense_command(&env).unwrap();
        match cmd {
            ActiveDefenseCommand::Scan(req) => assert_eq!(req.target, Target::Local),
            _ => panic!("expected scan"),
        }
    }

    #[test]
    fn parse_target_ssh() {
        let env = Envelope::new("repl", "scan:vuln --target ssh:root@10.0.0.5");
        let cmd = parse_active_defense_command(&env).unwrap();
        match cmd {
            ActiveDefenseCommand::Scan(req) => {
                assert_eq!(
                    req.target,
                    Target::Ssh {
                        destination: "root@10.0.0.5".to_string()
                    }
                );
            }
            _ => panic!("expected scan"),
        }
    }

    #[test]
    fn parse_remediate_plan() {
        let env = Envelope::new("repl", "remediate:plan --target local");
        let cmd = parse_active_defense_command(&env).unwrap();
        match cmd {
            ActiveDefenseCommand::RemediatePlan { target } => assert_eq!(target, Target::Local),
            _ => panic!("expected remediate plan"),
        }
    }

    #[test]
    fn parse_verify() {
        let env = Envelope::new("repl", "verify --target local");
        let cmd = parse_active_defense_command(&env).unwrap();
        match cmd {
            ActiveDefenseCommand::Verify { target } => assert_eq!(target, Target::Local),
            _ => panic!("expected verify"),
        }
    }

    #[test]
    fn parse_defend_run() {
        let env = Envelope::new("repl", "defend:run --target local");
        let cmd = parse_active_defense_command(&env).unwrap();
        match cmd {
            ActiveDefenseCommand::DefendRun { target, apply } => {
                assert_eq!(target, Target::Local);
                assert!(!apply);
            }
            _ => panic!("expected defend:run"),
        }
    }

    #[test]
    fn parse_defend_run_apply_flag() {
        let env = Envelope::new("repl", "defend:run --apply --target local");
        let cmd = parse_active_defense_command(&env).unwrap();
        match cmd {
            ActiveDefenseCommand::DefendRun { target, apply } => {
                assert_eq!(target, Target::Local);
                assert!(apply);
            }
            _ => panic!("expected defend:run"),
        }
    }
}
