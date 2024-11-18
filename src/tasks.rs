//! # Task Manager

use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::endpoint::Message;
// use tokio::time::{interval, sleep};
use crate::provider::{Provider, TaskStore};
use crate::records::Delete;
use crate::Result;

// Frequency with which an automatic timeout extension is requested.
const EXTENSION_PERIOD: u64 = 30;

/// Runs a resumable task with automatic timeout extension.
pub async fn run(owner: &str, task: TaskType, provider: &impl Provider) -> Result<()> {
    let timeout = EXTENSION_PERIOD * 2;

    // let mut interval = interval(Duration::from_millis(100));
    let timeout = (Utc::now() + Duration::from_secs(timeout)).timestamp() as u64;

    // register the task
    let resumable = ResumableTask {
        task_id: task.cid()?,
        task: task.clone(),
        timeout,
        retry_count: 0,
    };

    TaskStore::register(provider, owner, &resumable, timeout).await?;

    // // extend the timeout  until complete
    // let task_id = resumable.id.clone();
    // let store_1 = store.clone();
    // tokio::spawn(async move {
    //     sleep(Duration::from_secs(EXTENSION_PERIOD)).await;
    //     let _ = store_1.extend(&task_id, timeout).await;
    // });

    task.run(owner, provider).await?;

    // clearTimeoutExtensionTimer(timer);

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
            TaskType::RecordsDelete(delete) => delete.cid(),
        }
    }

    pub async fn run(&self, owner: &str, provider: &impl Provider) -> Result<()> {
        match self {
            TaskType::RecordsDelete(delete) => delete.run(owner, provider).await,
        }
    }
}
