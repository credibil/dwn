# Decentralized Web Node (DWN)

A Rust-based implementation of the Decentralized Web Node [specification], as ported from TBD's 
(now DIF's) TypeScript [reference implementation].

> [!CAUTION] Experimental code!
> While the library is functionally complete, it has not yet had the
> hardening that comes with ongoing, real-world use.

## DWN in action

```rust
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_dwn::client::records::{Data, QueryBuilder, RecordsFilter, WriteBuilder};
use credibil_dwn::{StatusCode, endpoint};
use node::keystore;
use node::Provider;

#[tokio::main]
async fn main() {
    // create a provider for the DWN library
    let node = node().await;
    let alice = Keyring::new();

    // create a request to write a new record (and serialize to JSON)
    let write = WriteBuilder::new()
        .data(Data::from(b"a new write record".to_vec()))
        .sign(&alice)
        .build()
        .await
        .expect("should create write");

    // this would normally run on a web server (for example, axum)
    // ... deserialize request and pass to the endpoint
    let reply =
        endpoint::handle(alice.did(),, write.clone(), &provider).await.expect("should write");
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    // find and read the previously written record
    let query = QueryBuilder::new()
        .filter(RecordsFilter::new().record_id(&write.record_id))
        .sign(&alice)
        .build()
        .await
        .expect("should create read");

    let reply = endpoint::handle(alice.did(),, query, &provider).await.expect("should write");
    assert_eq!(reply.status, StatusCode::OK);

    let body = reply.body.expect("should have body");
    let entries = body.entries.expect("should have entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].write.encoded_data,
        Some(Base64UrlUnpadded::encode_string(b"a new write record"))
    );
}
```

Example impementations can be found in the [examples](./examples) directory. 

Additionally, the
[tests](./tests) directory contains a comprehensive suite of tests that demonstrate a wide variety
of usage scenarios.

## Contributing

### To get started:

1. Read the [contributing guide](./CONTRIBUTING.md).
2. Read the [code of conduct](./CODE-OF-CONDUCT.md).
3. Choose a task from this project's backlog of issues and follow the instructions.

Have questions? Connecting with us in our [Zulip community](https://credibil.zulipchat.com).

## Specification Conformance

The DWN [specification] lags somewhat behind the TBD/DIF (and this) implementation. The code 
incorporates learnings from active use that are yet to be reflected in the specification. As the
specification makes its way from DRAFT to FINAL, our code will be updated to reflect differences.

## Additional

[![ci](https://github.com/credibil/dwn/actions/workflows/ci.yaml/badge.svg)](https://github.com/credibil/dwn/actions/workflows/ci.yaml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE-MIT)
[![License](https://img.shields.io/badge/license-Apache-blue.svg)](./LICENSE-APACHE)

<!-- The [changelog][CHANGES] is used to record a summary of changes between releases. A more granular
record of changes can be found in the commit history. -->

More information about [contributing](CONTRIBUTING.md). Please respect we maintain this project on
a part-time basis. While we welcome suggestions and technical input, it may take time to respond.

The artefacts in this repository are dual licensed under either:

- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)

The license applies to all parts of the source code, its documentation and supplementary files
unless otherwise indicated.

[specification]: https://identity.foundation/decentralized-web-node/spec
[reference implementation]: https://github.com/decentralized-identity/dwn-sdk-js