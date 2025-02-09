//! # Event Log

// use crate::store::{Cursor, Storable, Query, block, index};
use crate::Result;
use crate::provider::BlockStore;
pub use crate::tasks::ResumableTask;

/// Registers a new resumable task that is currently in-flight/under
/// processing to the store.
///
/// If the task has timed out, a client will be able to grab it through the
/// `grab()` method and resume the task.
#[allow(clippy::unused_async)]
pub async fn register(
    _owner: &str, _task: &ResumableTask, _timeout_secs: u64, _store: &impl BlockStore,
) -> Result<()> {
    Ok(())
}

/// Grabs `count` unhandled tasks from the store.
///
/// Unhandled tasks are tasks that are not currently in-flight/under processing
/// (ie. tasks that have timed-out).
///
/// N.B.: The implementation must make sure that once a task is grabbed by a client,
/// tis timeout must be updated so that it is considered in-flight/under processing
/// and cannot be grabbed by another client until it is timed-out.
#[allow(clippy::unused_async)]
pub async fn grab(
    _owner: &str, _count: u64, _store: &impl BlockStore,
) -> Result<Vec<ResumableTask>> {
    todo!()
}

/// Reads the task associated with the task ID provided regardless of whether
/// it is in-flight/under processing or not.
///
/// This is mainly introduced for testing purposes: ie. to check the status of
/// a task for easy test verification.
#[allow(clippy::unused_async)]
pub async fn read(
    _owner: &str, _task_id: &str, _store: &impl BlockStore,
) -> Result<Option<ResumableTask>> {
    todo!()
}

/// Extends the timeout of the task associated with the task ID provided.
///
/// No-op if the task is not found, as this implies that the task has already
/// been completed. This allows the client that is executing the task to
/// continue working on it before the task is considered timed out.
#[allow(clippy::unused_async)]
pub async fn extend(
    _owner: &str, _task_id: &str, _timeout_secs: u64, _store: &impl BlockStore,
) -> Result<()> {
    todo!()
}

/// Delete data associated with the specified id.
#[allow(clippy::unused_async)]
pub async fn delete(_owner: &str, _task_id: &str, _store: &impl BlockStore) -> Result<()> {
    todo!()
}
