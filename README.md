# Decentralized Web Node (DWN)

A Rust-based implementation of the Decentralized Web Node [specification], as ported from TBD's 
(now DIF's) TypeScript [reference implementation].

> [!CAUTION]
>
> **Experimental code!**
>
> The code in this repository is experimental and under active development.
> 
> While the library is functionally complete, it has not yet had the hardening that comes from a 
> significant period of use in a production environment.

## Getting Started

[TODO] Example impementations can be found in the [examples](./examples) directory. 

Additionally, the
[tests](./tests) directory contains a comprehensive suite of tests that demonstrate a wide variety
of usage scenarios.

## Contributing

### To get started:

1. Read the [contributing guide](./CONTRIBUTING.md).
2. Read the [code of conduct](./CODE_OF_CONDUCT.md).
3. Choose a task from this project's issues and follow the instructions.

Have questions? Connecting with us in our [Zulip community](https://credibil.zulipchat.com).

## Specification Conformance

The DWN [specification] lags somewhat behind the TBD/DIF (and this) implementation. The code 
incorporates learnings from active use that are yet to be reflected in the specification. As the
specification makes its way from DRAFT to FINAL, our code will be updated to reflect differences.

## Additional

[![ci](https://github.com/vercre/dwn/actions/workflows/ci.yaml/badge.svg)](https://github.com/vercre/dwn/actions/workflows/ci.yaml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE-MIT)
[![License](https://img.shields.io/badge/license-Apache-blue.svg)](./LICENSE-APACHE)

<!-- The [changelog][CHANGES] is used to record a summary of changes between releases. A more granular
record of changes can be found in the commit history. -->

More information about [contributing](CONTRIBUTING.md). Please respect we maintain this project on
a part-time basis. While we welcome suggestions and technical input, it may take time to respond.

The artefacts in this repository are dual licensed under either:

- MIT license ([LICENSE-MIT] or <http://opensource.org/licenses/MIT>)
- Apache License, Version 2.0 ([LICENSE-APACHE] or <http://www.apache.org/licenses/LICENSE-2.0>)

The license applies to all parts of the source code, its documentation and supplementary files
unless otherwise indicated.

[specification]: https://identity.foundation/decentralized-web-node/spec
[reference implementation]: https://github.com/decentralized-identity/dwn-sdk-js