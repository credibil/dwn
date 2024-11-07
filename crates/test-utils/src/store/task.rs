use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use vercre_dwn::provider::{ResumableTask, TaskStore};

use super::ProviderImpl;

#[async_trait]
impl TaskStore for ProviderImpl {
    async fn register(&self, task: &Value, timeout_secs: u64) -> Result<ResumableTask> {
        todo!()
    }

    async fn grab(count: u64) -> Result<Vec<ResumableTask>> {
        todo!()
    }

    async fn read(task_id: &str) -> Result<Option<ResumableTask>> {
        todo!()
    }

    async fn extend(task_id: &str, timeout_secs: u64) -> Result<()> {
        todo!()
    }

    async fn delete(&self, task_id: &str) -> Result<()> {
        todo!()
    }

    async fn purge(&self) -> Result<()> {
        Ok(())
    }
}
