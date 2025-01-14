use anyhow::Result;
use vercre_dwn_server::provider::{ResumableTask, TaskStore};

use super::ProviderImpl;
use crate::provider::NAMESPACE;

pub(crate) const TABLE: &str = "task";

impl TaskStore for ProviderImpl {
    async fn register(&self, owner: &str, task: &ResumableTask, timeout_secs: u64) -> Result<()> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<ResumableTask> = self.db.create((TABLE, &task.task_id)).content(task).await?;
        Ok(())
    }

    async fn grab(&self, owner: &str, count: u64) -> Result<Vec<ResumableTask>> {
        todo!()
    }

    async fn read(&self, owner: &str, task_id: &str) -> Result<Option<ResumableTask>> {
        todo!()
    }

    async fn extend(&self, owner: &str, task_id: &str, timeout_secs: u64) -> Result<()> {
        Ok(())
    }

    async fn delete(&self, owner: &str, task_id: &str) -> Result<()> {
        todo!()
    }

    async fn purge(&self, owner: &str) -> Result<()> {
        Ok(())
    }
}
