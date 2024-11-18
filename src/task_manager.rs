//! # Task Manager

use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};

// use tokio::time::{interval, sleep};
use crate::data::cid;
use crate::provider::{Provider, TaskStore};
use crate::records::{delete, Delete};
use crate::Result;


// Frequency with which an automatic timeout extension is requested.
const EXTENSION_PERIOD: u64 = 30;

/// Runs a resumable task with automatic timeout extension.
pub async fn run(owner: &str, task: Task, provider: &impl Provider) -> Result<()> {
    let timeout = EXTENSION_PERIOD * 2;

    // let mut interval = interval(Duration::from_millis(100));

    let timeout = (Utc::now() + Duration::from_secs(timeout)).timestamp() as u64;

    // register the task
    let managed = ManagedTask {
        id: cid::from_value(&task)?,
        timeout,
        retry_count: 0,
        task: task.clone(),
    };
    TaskStore::register(provider, &managed, timeout).await?;

    // // extend the timeout  until complete
    // let task_id = managed.id.clone();
    // let store_1 = store.clone();
    // tokio::spawn(async move {
    //     sleep(Duration::from_secs(EXTENSION_PERIOD)).await;
    //     let _ = store_1.extend(&task_id, timeout).await;
    // });

    match task {
        Task::RecordsDelete(del) => {
            delete::delete(owner, &del, provider).await?;
        }
    }

    TaskStore::delete(provider, &managed.id).await?;

    // clearTimeoutExtensionTimer(timer);

    Ok(())
}

/// Managed task is used by the task manager.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManagedTask {
    /// Globally unique ID. Used to extend or delete the task.
    pub id: String,

    /// Task specific data. This is deliberately of type `any` because this store
    /// should not have to be ware of its type.
    pub task: Task,

    /// Task timeout in Epoch Time.
    pub timeout: u64,

    /// Number of retries
    pub retry_count: u64,
}

/// Permitted task names.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Task {
    /// `RecordsDelete` task.
    RecordsDelete(Delete),
}
