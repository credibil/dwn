# Contribution Guide

Credibil welcomes community contributions to the `dwn` library.

Since the project is still unstable, there are specific priorities for development. Pull requests 
that do not address these priorities will not be accepted until Credibil is production ready.

Please familiarize yourself with the Contribution Guidelines and Project Roadmap before 
contributing.

There are many ways to help Credibil besides contributing code:

- Fix bugs or file issues
- Improve the documentation

## Table of Contents

- [Contribution Guide](#contribution-guide)
  - [Table of Contents](#table-of-contents)
  - [Contributing Code](#contributing-code)
  - [Code Style](#code-style)
  - [Developer’s Certificate of Origin](#developers-certificate-of-origin)
  - [Pull request procedure](#pull-request-procedure)

## Contributing Code

Unless you are fixing a known bug, we **strongly** recommend discussing it with the core team via a
GitHub issue before getting started to ensure your work is consistent with Credibil's open source 
roadmap and architecture.

All contributions are made via pull request. Note that **all patches from all contributors get 
reviewed**. After a pull request is made other contributors will offer feedback, and if the patch
passes review a maintainer will accept it with a comment. When pull requests fail testing, authors 
are expected to update their pull requests to address the failures until the tests pass and the 
pull request merges successfully.

At least one review from a maintainer is required for all patches (even patches from maintainers).

Reviewers should leave a "LGTM" comment once they are satisfied with the patch. If the patch was
submitted by a maintainer with write access, the pull request should be merged by the submitter
after review.

## Code Style

Please follow these guidelines when formatting source code:

- Rust code should match the output of `clippy -- -Dclippy::all -Dclippy::nursery -Dclippy::pedantic`

## Developer’s Certificate of Origin

All contributions must include acceptance of the DCO:

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
660 York Street, Suite 102,
San Francisco, CA 94110 USA

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

To accept the DCO, simply add this line to each commit message with your name and email address 
(`git commit -s` will do this for you):

```text
Signed-off-by: Jane Example <jane@example.com>
```

For legal reasons, no anonymous or pseudonymous contributions are accepted 
([contact us](mailto:andrew@credibil.io) if this is an issue).

## Pull request procedure

To make a pull request, you will need a GitHub account; if you are unclear on this process, see
GitHub's documentation on [forking](https://help.github.com/articles/fork-a-repo) and 
[pull requests](https://help.github.com/articles/using-pull-requests). Pull requests should be
targeted at the `master` branch. Before creating a pull request, go through this checklist:

1. Create a feature branch off of `master` so that changes do not get mixed up.
2. [Rebase](https://git-scm.com/book/en/Git-Branching-Rebasing) your local changes against the
   `master` branch.
3. Run the full project test suite with the `go test ./...` (or equivalent) command and confirm
   that it passes.
4. Run `gofmt -s` (if the project is written in Go).
5. Accept the Developer's Certificate of Origin on all commits (see above).
6. Ensure that each commit has a subsystem prefix (ex: `controller:`).

Pull requests will be treated as "review requests," and maintainers will give feedback on the
style and substance of the patch.

Normally, all pull requests must include tests that test your change. Occasionally, a change may
be very difficult to test for. In those cases, please include a note in your commit message 
explaining why.
