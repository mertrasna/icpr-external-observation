# Controlled Private Relay observations

This folder contains a macOS/Safari measurement controller and a deterministic
evidence-pairing pipeline for studying iCloud Private Relay behaviour at a
researcher-controlled HTTPS endpoint.

It is a methods package. Raw attempts, private pins, endpoint details, frozen
local configuration, and prior campaign findings are deliberately outside this
repository.

## Start here

From the repository root:

```bash
make setup
make test-experiment
./experiment/icpr --help
```

These commands are offline: they do not open Safari, change DNS or PF, start a
packet capture, or contact a measurement server.

Next, follow [HOW_TO_USE.md](HOW_TO_USE.md) to create a local configuration,
provide the routing/feed inputs, run preflight and rehearsal gates, collect an
authorised observation, and pair its evidence.

## Main files

| Path | Purpose |
| --- | --- |
| `icpr` | Command-line entry point |
| `controller.py` | Approval-gated attempt lifecycle |
| `pipeline.py` | Hash-verified client/server pairing |
| `objective_eligibility.py` | Eligibility rules and summaries |
| `icprlib.py` | Integrity, configuration, and shared helpers |
| `config/` | Neutral templates and local ignored configuration |
| `reference/asn/` | Dated origin-ASN schemas and reconstruction helper |
| `tests/` | Offline synthetic scenarios |

This repository intentionally omits historical operator procedures. Use
the shorter workflow, document your own approvals and environment, and freeze
your own protocol decisions before collection.
