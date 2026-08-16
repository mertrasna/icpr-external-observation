# ECS ingress-candidate enumeration

This folder implements a resumable version of the IPv4 EDNS Client Subnet
(ECS) method used by Sattler et al. to investigate iCloud Private Relay. It is
intended as a starting point for a new, authorised measurement—not as a report
of this repository's earlier observations.

The scanner:

- reads sorted public IPv4 `/24` ECS source prefixes;
- sends authoritative `A` queries with an ECS `/24` option;
- records returned IPv4 addresses and ECS scope;
- skips later `/24`s covered by a broader returned scope;
- appends results while running and checkpoints progress;
- resumes after Ctrl-C or a restart; and
- maintains a sorted unique ingress-address list and summary.

It is intentionally one standard-library Python file. There is no database,
package framework, or testbed integration.

## What the method measures

The scanner queries `mask.apple-dns.net` by default and supplies one public
IPv4 `/24` in the ECS option. You must provide the authoritative DNS server
used for the run with `--server`; authority can change, so the code deliberately
does not embed a dated server name.

```text
mask.apple-dns.net A @AUTHORITATIVE_SERVER +subnet=PREFIX/24
```

The output should be described as **DNS-derived Private Relay ingress
candidates**. DNS enumeration does not by itself prove that every returned
address is currently accepting Private Relay connections.

## Setup

- Python 3.12 or newer for the repository-supported environment
- `dig`
- sufficient storage for the chosen input (a global run may need tens of GB)
- approval from the institution and the networks involved

On Debian or Ubuntu:

```bash
sudo apt update
sudo apt install python3 dnsutils tmux curl
```

No third-party Python package is required by this folder.

## 1. Verify the code offline

From the repository root:

```bash
make setup
make test-ecs
```

The tests parse synthetic `dig` output and validate source-prefix handling.
They send no DNS queries.

Run the remaining commands from `ecs-scanner/`:

```bash
cd ecs-scanner
```

## 2. Select and record the DNS authority

Before every live run, resolve the current authoritative chain independently
and record the chosen server, target, time, and command in the study protocol.
For example, inspect the current nameservers with `dig`:

```bash
dig +short NS apple-dns.net
dig +norecurse mask.apple-dns.net A @AUTHORITATIVE_SERVER
```

Do not proceed unless the response and authority are suitable for the declared
method. A resolver hostname copied from an older study may no longer be valid.

## 3. Run a small approved measurement

`ecs_sources_small.txt` contains a small, sorted set of public `/24`s. This
command sends real queries, so choose a server and rate covered by your
approval:

```bash
python3 ecs_ingress_scanner.py ecs_sources_small.txt \
  --server AUTHORITATIVE_SERVER \
  --output-dir validation_results \
  --rate 1
```

Inspect the result:

```bash
cat validation_results/summary.txt
head validation_results/results.csv
```

## 4. Build a routed `/24` input

Acquire a dated RouteViews/CAIDA prefix-to-AS snapshot under its applicable
terms. Record its source URL, observation time, retrieval time, and SHA-256.
Then expand it offline:

```bash
python3 ecs_ingress_scanner.py \
  --build-sources ROUTEVIEWS_SNAPSHOT.pfx2as.gz \
  --write-input ecs_sources.txt
```

Input generation is offline and sends no DNS queries. The large generated file
and downloaded snapshot are excluded from Git.

## 5. Run the declared enumeration

Only run at the target, authority, source scope, rate, and dates named in the
approved protocol. Start conservatively and retain the command with the output.

Start a persistent terminal:

```bash
tmux new -s ecs-scan
```

Run the scanner:

```bash
python3 ecs_ingress_scanner.py ecs_sources.txt \
  --server AUTHORITATIVE_SERVER \
  --output-dir full_results \
  --rate APPROVED_RATE \
  --concurrency APPROVED_CONCURRENCY \
  --checkpoint-seconds 10
```

`--rate` is one aggregate query-start limit shared by all workers; it is not
multiplied by `--concurrency`. Multiple in-flight queries can hide DNS latency
while retaining the same aggregate ceiling. Results are
committed in input order, so the existing checkpoint remains resumable.

When a response reveals a broader ECS scope, a maximum of
`concurrency - 1` prefix tasks may already have started inside that newly known
scope. With retries, each task can contain more than one DNS attempt. Those
redundant responses are not written to `results.csv`, but their attempts remain
included in `dns_queries_sent` and any failures remain included in
`errors_or_timeouts`.

Detach from `tmux` with `Ctrl-B`, then `D`. Reattach later with:

```bash
tmux attach -t ecs-scan
```

Monitor progress from another terminal:

```bash
watch -n 10 cat full_results/summary.txt
```

To resume after Ctrl-C or a restart, run the exact same scanner command again.

## Outputs

The output directory contains:

| File | Contents |
| --- | --- |
| `results.csv` | Append-only query time, ECS `/24`, returned scope and answer IP |
| `unique_ingress_ips.txt` | Numerically sorted distinct IPv4 answers |
| `summary.txt` | Progress, checkpoint, query, skip, error and unique-address counts |

`results.csv` is appended and flushed after every successful query. With the
command above, all three outputs are durably checkpointed every 10 seconds and
once more on a clean Ctrl-C. A sudden power failure can cause up to one
checkpoint interval to be repeated after restart; the unique list remains
deduplicated.

A successful `NOERROR` response with no `A` records is stored with an empty
`answer_ip`. Failed prefixes are retained in `pending_error_prefixes` in the
summary and retried first on the next run. Five consecutive failed prefixes
stop the run rather than continuing through a network or DNS outage.

## Limits and interpretation

- DNS answers are time-varying; repeat counts need not match.
- Returned addresses are ingress candidates, not proof of successful relay use.
- ECS scope skipping reduces queries but makes the enumeration dependent on
  the returned scope semantics.
- The rate is a ceiling, not a guaranteed throughput. Timeouts and retries can
  extend a run considerably.
- A global scan is a substantial active measurement. Preserve incomplete and
  failed runs rather than selecting only successful observations.

## Repository layout

```text
ecs_ingress_scanner.py   scanner and routed-input builder
ecs_sources_small.txt    small live-measurement input
tests/                   offline synthetic tests
```

Downloaded routing data, generated full input, validation output, full results,
logs, local environments and credentials are excluded by `.gitignore`.

## Reference

Patrick Sattler, Juliane Aulbach, Johannes Zirngibl, and Georg Carle,
“Towards a Tectonic Traffic Shift? Investigating Apple's New Relay Network,”
IMC 2022. [doi:10.1145/3517745.3561426](https://doi.org/10.1145/3517745.3561426)
