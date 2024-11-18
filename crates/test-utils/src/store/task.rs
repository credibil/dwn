use anyhow::Result;
use async_trait::async_trait;
use vercre_dwn::provider::{ManagedTask, TaskStore};

use super::ProviderImpl;
use crate::store::NAMESPACE;

pub(crate) const DB: &str = "task";
pub(crate) const TABLE: &str = "task";

#[async_trait]
impl TaskStore for ProviderImpl {
    async fn register(&self, task: &ManagedTask, timeout_secs: u64) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(DB).await?;
        let _: Option<ManagedTask> = self.db.create((TABLE, &task.id)).content(task).await?;
        Ok(())
    }

    async fn grab(&self, count: u64) -> Result<Vec<ManagedTask>> {
        todo!()
    }

    async fn read(&self, task_id: &str) -> Result<Option<ManagedTask>> {
        todo!()
    }

    async fn extend(&self, task_id: &str, timeout_secs: u64) -> Result<()> {
        todo!()
    }

    async fn delete(&self, task_id: &str) -> Result<()> {
        todo!()
    }

    async fn purge(&self) -> Result<()> {
        Ok(())
    }
}
