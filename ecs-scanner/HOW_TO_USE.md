# How to use the ECS scanner

## Purpose

This folder enumerates DNS-derived iCloud Private Relay ingress candidates by
sending authoritative DNS queries with EDNS Client Subnet values. It does not
prove that every returned address currently accepts relay traffic.

## Choose a task

| Goal | Network access? | Command from the repository root |
| --- | --- | --- |
| Verify parsing and input validation | No | `make setup && make test-ecs` |
| Build a `/24` source list | No | `.venv/bin/python ecs-scanner/ecs_ingress_scanner.py --build-sources INPUT.pfx2as.gz --write-input OUTPUT.txt` |
| Run a small DNS measurement | Yes | Follow the authority-selection and approval steps in `ecs-scanner/README.md` |

## Requirements

- Python 3.12 or newer for the repository's supported environment.
- `dig` for live collection.
- A dated RouteViews/CAIDA prefix-to-AS file for a full source list.
- Institutional and network approval for live enumeration.

## Inputs and outputs

| Path | Description |
| --- | --- |
| `ecs_sources_small.txt` | Small public-prefix input for an approved live run. |
| `ecs_sources.txt` | Generated full input; deliberately excluded from Git. |
| `<output>/results.csv` | Append-only query results. |
| `<output>/unique_ingress_ips.txt` | Sorted unique IPv4 answers. |
| `<output>/summary.txt` | Checkpoint and progress summary. |

## Quick verification

```sh
make setup
make test-ecs
```

Expected result: six offline tests pass. No DNS query is sent.

## Live collection

Both the small run and full scan send real DNS queries. Supply a currently
authoritative server explicitly; no dated DNS server is embedded as a default.
The full scan can run for days and must use an approved rate. See
`ecs-scanner/README.md` for the resumable command, rate semantics, outputs, and
interpretation limits.
