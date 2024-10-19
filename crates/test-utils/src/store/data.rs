use std::future::Future;
use std::io::Read;

use vercre_dwn::provider::DataStore;

use super::ProviderImpl;

impl DataStore for ProviderImpl {
    fn put(
        &self, tenant: &str, record_id: &str, data_cid: &str, data: impl Read,
    ) -> impl Future<Output = anyhow::Result<()>> + Send {
        async { Ok(()) }
    }

    fn get(
        &self, tenant: &str, record_id: &str, data_cid: &str,
    ) -> impl Future<Output = anyhow::Result<Option<impl Read>>> + Send {
        let buf = vec![];
        let reader = std::io::Cursor::new(buf);
        async { Ok(Some(reader)) }
    }

    async fn delete(&self, tenant: &str, record_id: &str, data_cid: &str) -> anyhow::Result<()> {
        todo!()
    }

    async fn purge(&self) -> anyhow::Result<()> {
        todo!()
    }
}
