use anyhow::{Context, Result};
use sqlx::{PgPool, migrate::Migrator};
use std::path::Path;
use url::Url;
use uuid::Uuid;

#[tokio::test]
async fn legacy_schema_upgrades_to_current_operational_state() -> Result<()> {
    let Ok(base_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL is unset; skipping PostgreSQL migration upgrade test");
        return Ok(());
    };

    let mut admin_url = Url::parse(&base_url).context("invalid DATABASE_URL")?;
    admin_url.set_path("/postgres");
    let admin = PgPool::connect(admin_url.as_str())
        .await
        .context("failed to connect to PostgreSQL admin database")?;

    let database_name = format!("demonclaw_upgrade_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE \"{database_name}\""))
        .execute(&admin)
        .await
        .context("failed to create migration-upgrade test database")?;

    let mut upgrade_url = Url::parse(&base_url)?;
    upgrade_url.set_path(&format!("/{database_name}"));
    let pool = PgPool::connect(upgrade_url.as_str())
        .await
        .context("failed to connect to migration-upgrade test database")?;

    sqlx::raw_sql(include_str!(
        "../migrations/202603200001_init_memory_schema.sql"
    ))
    .execute(&pool)
    .await
    .context("failed to install the legacy 1.0 memory schema")?;

    let legacy_memory: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.memory_chunks')::text")
            .fetch_one(&pool)
            .await?;
    let pre_upgrade_targets: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.operational_targets')::text")
            .fetch_one(&pool)
            .await?;

    assert_eq!(legacy_memory.as_deref(), Some("memory_chunks"));
    assert!(pre_upgrade_targets.is_none());

    let migration_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let migrator = Migrator::new(migration_path)
        .await
        .context("failed to load current migrations")?;
    migrator
        .run(&pool)
        .await
        .context("current migrations failed against legacy schema")?;

    let memory_after: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.memory_chunks')::text")
            .fetch_one(&pool)
            .await?;
    let targets_after: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.operational_targets')::text")
            .fetch_one(&pool)
            .await?;
    let findings_after: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.operational_findings')::text")
            .fetch_one(&pool)
            .await?;
    let applied_migrations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await?;

    assert_eq!(memory_after.as_deref(), Some("memory_chunks"));
    assert_eq!(targets_after.as_deref(), Some("operational_targets"));
    assert_eq!(findings_after.as_deref(), Some("operational_findings"));
    assert!(applied_migrations >= 2);

    pool.close().await;
    sqlx::query(&format!("DROP DATABASE \"{database_name}\" WITH (FORCE)"))
        .execute(&admin)
        .await
        .context("failed to remove migration-upgrade test database")?;
    admin.close().await;

    Ok(())
}
