//! SQLite persistence layer.
//!
//! Tables:
//!   agents(id TEXT PK, hostname, username, os_version, arch, pid INTEGER,
//!          elevated INTEGER, last_seen TEXT, listener_id TEXT,
//!          sleep_ms INTEGER, jitter_pct INTEGER, build_id TEXT)
//!   tasks (id TEXT PK, agent_id TEXT, operator TEXT, command TEXT,
//!          status TEXT, output TEXT, created_at TEXT, completed_at TEXT)

use anyhow::Result;
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use ghoststrike_common::{AgentInfo, Task, TaskCommand, TaskStatus};

#[derive(Clone, Debug)]
pub struct Db {
    pool: SqlitePool,
}

impl Db {
    pub async fn open(path: &str) -> Result<Self> {
        let url = format!("sqlite://{path}?mode=rwc");
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS agents (
                id          TEXT PRIMARY KEY,
                hostname    TEXT NOT NULL,
                username    TEXT NOT NULL,
                os_version  TEXT NOT NULL,
                arch        TEXT NOT NULL,
                pid         INTEGER NOT NULL,
                elevated    INTEGER NOT NULL,
                last_seen   TEXT NOT NULL,
                listener_id TEXT NOT NULL,
                sleep_ms    INTEGER NOT NULL,
                jitter_pct  INTEGER NOT NULL,
                build_id    TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS tasks (
                id           TEXT PRIMARY KEY,
                agent_id     TEXT NOT NULL,
                operator     TEXT NOT NULL,
                command      TEXT NOT NULL,
                status       TEXT NOT NULL,
                output       TEXT,
                created_at   TEXT NOT NULL,
                completed_at TEXT
            )",
        )
        .execute(&pool)
        .await?;

        Ok(Self { pool })
    }

    // ── Agents ────────────────────────────────────────────────────────────────

    pub async fn upsert_agent(&self, a: &AgentInfo) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO agents
             (id, hostname, username, os_version, arch, pid, elevated,
              last_seen, listener_id, sleep_ms, jitter_pct, build_id)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(a.id.to_string())
        .bind(&a.hostname)
        .bind(&a.username)
        .bind(&a.os_version)
        .bind(&a.arch)
        .bind(a.pid as i64)
        .bind(a.elevated as i64)
        .bind(a.last_seen.to_rfc3339())
        .bind(a.listener_id.to_string())
        .bind(a.sleep_ms as i64)
        .bind(a.jitter_pct as i64)
        .bind(&a.build_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_agents(&self) -> Result<Vec<AgentInfo>> {
        let rows = sqlx::query("SELECT * FROM agents")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::new();
        for row in rows {
            let id:          String = row.try_get("id")?;
            let last_seen:   String = row.try_get("last_seen")?;
            let listener_id: String = row.try_get("listener_id")?;
            out.push(AgentInfo {
                id:          Uuid::parse_str(&id)?,
                hostname:    row.try_get("hostname")?,
                username:    row.try_get("username")?,
                os_version:  row.try_get("os_version")?,
                arch:        row.try_get("arch")?,
                pid:         row.try_get::<i64, _>("pid")? as u32,
                elevated:    row.try_get::<i64, _>("elevated")? != 0,
                last_seen:   DateTime::parse_from_rfc3339(&last_seen)?.with_timezone(&Utc),
                listener_id: Uuid::parse_str(&listener_id)?,
                sleep_ms:    row.try_get::<i64, _>("sleep_ms")? as u64,
                jitter_pct:  row.try_get::<i64, _>("jitter_pct")? as u8,
                build_id:    row.try_get("build_id")?,
            });
        }
        Ok(out)
    }

    // ── Tasks ─────────────────────────────────────────────────────────────────

    pub async fn insert_task(&self, t: &Task) -> Result<()> {
        let cmd = serde_json::to_string(&t.command)?;
        sqlx::query(
            "INSERT OR IGNORE INTO tasks
             (id, agent_id, operator, command, status, output, created_at, completed_at)
             VALUES (?,?,?,?,?,?,?,?)",
        )
        .bind(t.id.to_string())
        .bind(t.agent_id.to_string())
        .bind(&t.operator)
        .bind(&cmd)
        .bind(t.status.to_string())
        .bind(t.output.as_deref())
        .bind(t.created_at.to_rfc3339())
        .bind(t.completed_at.map(|d| d.to_rfc3339()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_task(
        &self,
        task_id: Uuid,
        status: &TaskStatus,
        output: Option<&str>,
        completed_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE tasks SET status=?, output=?, completed_at=? WHERE id=?",
        )
        .bind(status.to_string())
        .bind(output)
        .bind(completed_at.map(|d| d.to_rfc3339()))
        .bind(task_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn pending_tasks_for(&self, agent_id: Uuid) -> Result<Vec<Task>> {
        let rows = sqlx::query(
            "SELECT * FROM tasks WHERE agent_id=? AND status='pending'",
        )
        .bind(agent_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows_to_tasks(rows)
    }

    pub async fn tasks_for(&self, agent_id: Uuid, limit: i64) -> Result<Vec<Task>> {
        let rows = sqlx::query(
            "SELECT * FROM tasks WHERE agent_id=? ORDER BY created_at DESC LIMIT ?",
        )
        .bind(agent_id.to_string())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows_to_tasks(rows)
    }
}

fn rows_to_tasks(rows: Vec<sqlx::sqlite::SqliteRow>) -> Result<Vec<Task>> {
    let mut out = Vec::new();
    for row in rows {
        let id:       String = row.try_get("id")?;
        let agent_id: String = row.try_get("agent_id")?;
        let cmd_str:  String = row.try_get("command")?;
        let status_s: String = row.try_get("status")?;
        let created:  String = row.try_get("created_at")?;
        let done: Option<String> = row.try_get("completed_at")?;

        let status = match status_s.as_str() {
            "pending"   => TaskStatus::Pending,
            "running"   => TaskStatus::Running,
            "completed" => TaskStatus::Completed,
            _           => TaskStatus::Failed,
        };
        let command: TaskCommand = serde_json::from_str(&cmd_str)?;

        out.push(Task {
            id:          Uuid::parse_str(&id)?,
            agent_id:    Uuid::parse_str(&agent_id)?,
            operator:    row.try_get("operator")?,
            command,
            status,
            output:       row.try_get("output")?,
            created_at:  DateTime::parse_from_rfc3339(&created)?.with_timezone(&Utc),
            completed_at: done.and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                              .map(|d| d.with_timezone(&Utc)),
        });
    }
    Ok(out)
}
