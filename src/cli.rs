use anyhow::{Context, Result, bail};
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
    memory
        .init_schema()
        .await
        .context("SQLx migrations failed")?;
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
        Ok(targets) => println!(
            "  [ok] operational state available ({} targets)",
            targets.len()
        ),
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
            Ok(response) if response.status().is_success() => {
                println!("  [ok] local daemon API reachable")
            }
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
            println!(
                "registered target {} -> {}",
                record.name, record.target_label
            );
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
            format!(
                "{} is required for daemon API authentication",
                cfg.security.ingest_token_env
            )
        })?;
        let header_name = HeaderName::from_bytes(cfg.security.ingest_auth_header.as_bytes())?;
        let header_value = HeaderValue::from_str(&token)?;
        request = request.header(header_name, header_value);
    }

    let response = request
        .send()
        .await
        .context("failed to reach DemonClaw daemon")?;
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
