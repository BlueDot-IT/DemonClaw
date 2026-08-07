use anyhow::{Context, Result, bail, ensure};
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
    sandbox::Sandbox,
    scanner::Scanner,
    scheduler::Scheduler,
    signalgate::SignalGate,
};

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

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
        .context("failed to initialize memory schema")?;

    let evidence_locker = EvidenceLocker::new(memory.pool.clone());
    evidence_locker
        .init_schema()
        .await
        .context("failed to initialize Evidence Locker schema")?;

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
        max_concurrent_payloads: cfg.runtime.max_concurrent_payloads,
    });

    let (tx, rx) = tokio::sync::mpsc::channel(cfg.runtime.event_buffer);

    let scheduler = Scheduler::new(tx.clone());
    let channels = Arc::new(Channels::new(
        tx.clone(),
        cfg.security.clone(),
        evidence_locker,
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
