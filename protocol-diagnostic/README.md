# Protocol diagnostic methods

This folder contains two optional methods for investigating how Apple Private
Relay behaves when UDP availability changes. It supplies controllers, pairing
logic, safety checks, and neutral example profiles; it does not publish study
findings or provide a live measurement destination.

| Method | Wrapper | What it varies |
| --- | --- | --- |
| Dual protocol | `./protocol-diagnostic/protocol-diag` | UDP/443 permitted versus blocked only to one selected relay ingress |
| HTTP/3 required | `./protocol-diagnostic/h3-required-diag` | The same ingress condition while new origin TCP/443 connections are temporarily suppressed |

Both wrappers default to documentation-only profiles in [`examples/`](examples/README.md).
Those profiles are complete enough for offline validation, but their reserved
addresses and template attestations make them unsuitable for live collection.

## Start here

```sh
make setup
make test-protocol
./protocol-diagnostic/protocol-diag --help
./protocol-diagnostic/h3-required-diag --help
```

Then follow [HOW_TO_USE.md](HOW_TO_USE.md) to prepare a study-specific profile.
Run commands from the repository root because the controller reuses integrity
helpers from `experiment/icprlib.py`.

Historical study configurations, plans, references, and operator procedures
are provenance rather than reusable defaults. They are excluded from this
repository instead of being edited or relabelled.
