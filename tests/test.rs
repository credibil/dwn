#![allow(missing_docs)]
#![allow(dead_code)]

use std::io::{Cursor, Read};

use test_utils::store::ProviderImpl;
use vercre_dwn::records::Write;
use vercre_dwn::service::*;
use vercre_dwn::{Provider, Result};

struct WriteRequest {}

impl Request2 for WriteRequest {
    type M = Write;
    type P = ProviderImpl;

    fn message(&self) -> &Self::M {
        todo!()
    }

    fn provider(&self) -> &Self::P {
        todo!()
    }
}

impl WriteRequest2 for WriteRequest {
    type R = Cursor<Vec<u8>>;

    fn data_reader(&self) -> Option<&Self::R> {
        todo!()
    }
}

#[test]
fn handle_write() {
    let request = WriteRequest {};
    let _ = handle_request(request);
}

pub struct Request<M: Message, R: Read, S: Subscriber<M>> {
    pub message: M,
    pub data_reader: Option<R>,
    pub subscriber: Option<S>,
}

pub trait Request2 {
    type M: Message;
    type P: Provider;

    fn message(&self) -> &Self::M;
    fn provider(&self) -> &Self::P;
}

pub trait WriteRequest2: Request2 {
    type R: Read;

    fn data_reader(&self) -> Option<&Self::R>;
}

pub trait SubscribeRequest2: Request2 {
    type S: Subscriber<Self::M>;

    fn subscriber(&self) -> Option<&Self::S>;
}

pub trait Subscriber<M: Message> {
    fn subscribe(&self, event: Event<M>) -> Result<()>;
}

pub struct Event<M: Message> {
    message: M,
    initial_write: Option<M>,
}

pub fn handle_request<R: Request2>(_request: R) -> Result<()> {
    Ok(())
}
