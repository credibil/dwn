use serde_json::Value;
use vercre_dwn::provider::{ResumableTask, TaskStore};

use super::ProviderImpl;

impl TaskStore for ProviderImpl {
    async fn register(&self, task: Value, timeout_secs: u64) -> anyhow::Result<ResumableTask> {
        todo!()
    }

    async fn grab(count: u64) -> anyhow::Result<Vec<ResumableTask>> {
        todo!()
    }

    async fn read(task_id: &str) -> anyhow::Result<Option<ResumableTask>> {
        todo!()
    }

    async fn extend(task_id: &str, timeout_secs: u64) -> anyhow::Result<()> {
        todo!()
    }

    async fn delete(&self, task_id: &str) -> anyhow::Result<()> {
        todo!()
    }

    async fn purge(&self) -> anyhow::Result<()> {
        Ok(())
    }
}
