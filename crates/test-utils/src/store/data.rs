use std::io::Read;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use blockstore::Blockstore;
// use cid::Cid;
use ipld::Ipld;
use libipld::block::Block;
use libipld::cbor::DagCborCodec;
use libipld::ipld;
use libipld::store::{DefaultParams, StoreParams};
use multihash::Code;
use vercre_dwn::provider::DataStore;

use super::ProviderImpl;

// fn to_cid<T: Serialize>(payload: &T) -> Result<Cid> {
//     let mut buf = Vec::new();
//     ciborium::into_writer(payload, &mut buf)?;
//     let hash = Code::Sha2_256.digest(&buf);
//     Ok(Cid::new_v1(RAW, hash))
// }

#[async_trait]
impl DataStore for ProviderImpl {
    async fn put(
        &self, owner: &str, record_id: &str, data_cid: &str, mut data: impl Read + Send,
    ) -> Result<usize> {
        let mut links = vec![];
        let mut data_size = 0;

        loop {
            // let mut buffer = [0u8; DefaultParams::MAX_BLOCK_SIZE]; // = 1MB
            let mut buffer = [0u8; 10];
            let block = None::<Block<DefaultParams>>;

            if let Ok(bytes_read) = data.read(&mut buffer[..]) {
                if bytes_read > 0 {
                    // encode buffer to IPLD block
                    let ipld = Ipld::Bytes(buffer[..bytes_read].to_vec());
                    let block =
                        Block::<DefaultParams>::encode(DagCborCodec, Code::Sha2_256, &ipld)?;

                    // insert into the blockstore
                    // HACK: convert libipld CID to blockstore CID
                    let block_cid = cid::Cid::from_str(&block.cid().to_string())?;
                    self.blockstore.put_keyed(&block_cid, block.data()).await?;

                    // save block's CID as a link
                    links.push(Ipld::Link(block.cid().clone()));
                    data_size += bytes_read;
                } else {
                    break;
                }
            }
        }

        // create a root-like block linking data blocks
        let links_list = Ipld::List(links);
        let block = Block::<DefaultParams>::encode(DagCborCodec, Code::Sha2_256, &links_list)?;
        let root_bytes = block.cid().to_bytes();

        let store_cid = cid::Cid::try_from(root_bytes.as_slice())?;
        self.blockstore.put_keyed(&store_cid, &block.data()).await?;

        // finally, store provided CID
        let data_cid = cid::Cid::from_str(data_cid)?;
        self.blockstore.put_keyed(&data_cid, &root_bytes).await?;

        Ok(data_size)
    }

    async fn get(&self, owner: &str, record_id: &str, data_cid: &str) -> Result<Option<Vec<u8>>> {
        // get CID for root block
        let data_cid = cid::Cid::from_str(data_cid)?;
        let Some(root_bytes) = self.blockstore.get(&data_cid).await? else {
            return Ok(None);
        };

        // get root block containg links to data blocks
        let root_cid = cid::Cid::try_from(root_bytes.as_slice())?;
        let Some(bytes) = self.blockstore.get(&root_cid).await? else {
            return Ok(None);
        };

        // convert to Ipld::List containg links to data blocks
        let root_cid = libipld::Cid::try_from(root_bytes.as_slice())?;
        let block = Block::<DefaultParams>::new(root_cid, bytes)?;
        let ipld = block.decode::<DagCborCodec, Ipld>()?;
        let Ipld::List(links) = ipld else {
            return Ok(None);
        };

        // resolve each data block link
        let mut data = Vec::new();
        for link in links {
            let Ipld::Link(link_cid) = link else {
                return Err(anyhow!("invalid link"));
            };

            // get data block
            let block_cid = cid::Cid::try_from(link_cid.to_bytes())?;
            let Some(bytes) = self.blockstore.get(&block_cid).await? else {
                return Ok(None);
            };
            let block = Block::<DefaultParams>::new(link_cid, bytes)?;

            // get data block's payload
            let ipld = block.decode::<DagCborCodec, Ipld>()?;
            let Ipld::Bytes(bytes) = ipld else {
                return Ok(None);
            };
            data.extend(bytes);
        }

        return Ok(Some(data));
    }

    async fn delete(&self, owner: &str, record_id: &str, data_cid: &str) -> Result<()> {
        let cid = cid::Cid::from_str(data_cid)?;
        self.blockstore.remove(&cid).await?;
        Ok(())
    }

    async fn purge(&self) -> Result<()> {
        unimplemented!()
    }
}
