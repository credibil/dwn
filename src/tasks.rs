//! # Task Manager

// use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration};

use crate::endpoint::Message;
use crate::provider::{Provider, TaskStore};
use crate::records::Delete;
use crate::{unexpected, Result};

// Frequency with which an automatic timeout extension is requested.
const EXTEND_SECS: u64 = 30;

/// Runs a resumable task with automatic timeout extension.
pub async fn run(owner: &str, task: TaskType, provider: &impl Provider) -> Result<()> {
    // register the task
    let timeout = (Utc::now() + Duration::from_secs(EXTEND_SECS * 2)).timestamp();
    let timeout =
        u64::try_from(timeout).map_err(|e| unexpected!("issue converting timeout: {e}"))?;

    let resumable = ResumableTask {
        task_id: task.cid()?,
        task: task.clone(),
        timeout,
        retry_count: 0,
    };
    TaskStore::register(provider, owner, &resumable, timeout).await?;

    // wait until the task is complete or the timeout is reached
    tokio::select! {
        _ = task.run(owner, provider) => Ok(()),
        _ = extend_timeout(owner, &resumable.task_id,provider) => Ok(()),
    }
}

// Extend the timeout period.
async fn extend_timeout(owner: &str, task_id: &str, provider: &impl Provider) -> Result<()> {
    for _ in 0..2 {
        sleep(Duration::from_secs(EXTEND_SECS)).await;
        TaskStore::extend(provider, owner, task_id, EXTEND_SECS)
            .await
            .map_err(|e| unexpected!("failed to extend timeout: {e}"))?;
    }
    Ok(())
}

/// The Task trait required to be implemented by resumable tasks.
#[async_trait]
pub trait Task: Serialize + DeserializeOwned + Send + Sync
where
    Self: Sized,
{
    /// Runs the task.
    async fn run(&self, owner: &str, provider: &impl Provider) -> Result<()>;
}

/// Used by the task manager to resume running a task.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResumableTask {
    /// Globally unique ID. Used to extend or delete the task.
    pub task_id: String,

    /// Task type, serialized as bytes.
    pub task: TaskType,

    /// Task timeout in Epoch Time.
    pub timeout: u64,

    /// Number of retries
    pub retry_count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum TaskType {
    RecordsDelete(Delete),
}

impl TaskType {
    pub fn cid(&self) -> Result<String> {
        match self {
            Self::RecordsDelete(delete) => delete.cid(),
        }
    }

    pub async fn run(&self, owner: &str, provider: &impl Provider) -> Result<()> {
        match self {
            Self::RecordsDelete(delete) => delete.run(owner, provider).await,
        }
    }
}
