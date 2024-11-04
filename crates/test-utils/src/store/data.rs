use std::io::{Cursor, Read};

use anyhow::Result;
use vercre_dwn::provider::DataStore;

use super::ProviderImpl;
use crate::store::{DATA, NAMESPACE};

impl DataStore for ProviderImpl {
    async fn put(
        &self, owner: &str, record_id: &str, data_cid: &str, mut data: impl Read + Send,
    ) -> Result<()> {
        let mut buffer = Vec::new();
        data.read_to_end(&mut buffer)?;

        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let _: Option<()> = self.db.create((DATA, record_id)).content(buffer).await?;
        Ok(())
    }

    async fn get(&self, owner: &str, record_id: &str, data_cid: &str) -> Result<Option<impl Read>> {
        self.db.use_ns(NAMESPACE).use_db(owner).await?;
        let res: Option<Vec<u8>> = self.db.select((DATA, record_id)).await?;

        if let Some(data) = res {
            return Ok(Some(Cursor::new(data)));
        }
        Ok(None)
    }

    async fn delete(&self, owner: &str, record_id: &str, data_cid: &str) -> Result<()> {
        todo!()
    }

    async fn purge(&self) -> Result<()> {
        todo!()
    }
}
