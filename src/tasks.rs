//! # Resumable Task Manager
//!
//! The task manager is responsible for running long-running or background
//! tasks — tasks that can be paused and restarted at a later time.
//!
//! The task manager is useful for long-running tasks that may be interrupted
//! by network issues or other problems. It is responsible for running the task
//! and ensuring that it is completed within a certain time frame.
//!
//! # Implementer Note:
//!
//! The implementation of the backing [`TaskStore`] must allow for
//! concurrent access by multiple `TaskStore` instances when used in a
//! multi-node deployment. It would be undesirable to have many node
//! instances attempting to run the same resumable task.
//!
//! A minimal viable implementation may use a per tenant lock on the store
//! when the `grab()`  method is called.
//!
//! A more performant, multi-node implementation could:
//!
//! 1. Use a persistent store for storing the data of each resumable task
//! 2. Use pub/sub to distribute task processing exclusively to a single
//!    subscribing task manager service.
//! 3. The `grab()` and/or `open()` implementation will need to publish
//!    expired tasks for distributed processing when there are no resumable
//!    tasks in the queue.

use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::time::{Duration, sleep};

use crate::endpoint::Message;
use crate::interfaces::records::Delete;
use crate::provider::{Provider, TaskStore};
use crate::{Result, unexpected};

// The frequency with which an automatic timeout extension is requested.
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
pub trait Task: Serialize + DeserializeOwned + Send + Sync
where
    Self: Sized,
{
    /// Runs the task.
    fn run(&self, owner: &str, provider: &impl Provider)
    -> impl Future<Output = Result<()>> + Send;
}

/// `ResumableTask` is used by the task manager to resume running a paused
/// task.
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
