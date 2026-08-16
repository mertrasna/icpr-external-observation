# How to use the observation method

## What this method measures

One attempt opens a tagged URL at a controlled HTTPS endpoint while preserving
client and server evidence. Pairing asks whether exactly one destination-facing
connection can be attributed to that attempt, which ingress was contacted,
which Apple-published egress prefix covered the server source, and which
transport was observed.

The method does not infer Private Relay internals that are absent from the
packets and logs. A run ID is correlation metadata, not freshness proof.

## 1. Verify the code offline

From the repository root:

```bash
make setup
make test-experiment
./experiment/icpr --help
```

## 2. Create local study inputs

The checked-in configuration is deliberately a non-frozen template. Copy the
templates to their ignored local names:

```bash
cp experiment/config/experiment_config.example.yaml \
  experiment/config/experiment_config.yaml
cp experiment/config/ingress_pins.example.yaml \
  experiment/config/ingress_pins.yaml
cp experiment/reference/asn/operator_map.example.csv \
  experiment/reference/asn/operator_map.csv
```

Follow [config/README.md](config/README.md). At minimum, replace and review:

- the endpoint hostname, exact `/probe/{run_id}` URL and private endpoint IP;
- true country/time zone and the declared general-location boundary;
- observation schedule, retry rule and freshness method selected by a pilot;
- actual software versions;
- ingress pins, operator mappings and their provenance; and
- the dated origin-ASN source and Apple egress feed workflow.

Keep `configuration_status` as `template` until every field and prerequisite is
reviewed. Changing it to `frozen` is the last configuration step, not a way to
bypass the launch gates.

## 3. Provide dated inputs

For each observation date, place the complete Apple CSV at:

```text
experiment/feeds/apple/YYYY-MM-DD/apple-egress.csv
```

Create its filename-bound `.sha256` sidecar. Populate and hash
`experiment/reference/asn/origin_prefixes.csv` using the schema and provenance
rules in [reference/asn/README.md](reference/asn/README.md). Complete the local
pin and operator-map files, then create their sidecars as documented there.

These inputs are ignored because they can contain observed infrastructure or
third-party data. Preserve them with the evidence package, not in a blanket
source commit.

## 4. Preflight and freeze a plan

Inspect each command's exact options first:

```bash
./experiment/icpr preflight --help
./experiment/icpr rehearsal-check --help
./experiment/icpr prepare-run --help
```

Run the read-only preflight with your local config:

```bash
./experiment/icpr preflight \
  --config experiment/config/experiment_config.yaml
```

Do not start collection until the dependency, configuration, mapping,
privileged-smoke, reconstruction, rehearsal, and plan-freeze gates required by
your protocol are satisfied. The status-marker schemas in
`config/status_markers.example.md` describe auditable markers; they are not
claims that a check has passed.

## 5. Collect an authorised observation

Live commands can open Safari, start narrowly filtered packet capture, edit
`/etc/hosts`, restart `networkserviceproxy`, or install a scoped PF rule. They
require macOS, a controlled endpoint, explicit approval tokens, and operator
review. Use `prepare-run --help`, the printed plan, and the controller's prompts
rather than copying a historical command unchanged.

Always finish or abort through the controller so cleanup runs and the attempt
is retained and hashed. Never delete an excluded, failed, timed-out, or aborted
attempt because of its outcome.

## 6. Pair preserved evidence

After pulling and verifying the complete server archive, rebuild derived output
with the explicit server root:

```bash
./experiment/icpr pair --server-root server/recovery-data
./experiment/icpr asn-gaps --require-empty
./experiment/icpr daily-report
```

`pair` is a cumulative full rebuild and can become slow. Run it when the method
requires a rebuild, not as a quick smoke test. If the ASN guard finds gaps,
apply the complete, outcome-independent reconstruction procedure in
`reference/asn/README.md`, then perform the one required final rebuild.

## Inputs and outputs

| Path | Meaning |
| --- | --- |
| `config/experiment_config.yaml` | Your ignored, frozen local configuration |
| `config/ingress_pins.yaml` | Your ignored, reviewed ingress pins |
| `feeds/apple/` | Complete dated Apple catalogue inputs |
| `client/`, `server/` | Raw client and server evidence roots |
| `reference/asn/` | Dated routing and operator attribution inputs |
| `derived/` | Regenerated pair tables |
| `reports/` | Regenerated eligibility and daily summaries |
| `manifests/` | Plans and gate markers with hashes |

## Limits to state with results

- A server-observed source is a destination-facing address, not a complete
  description of the relay path.
- DNS-derived ingress candidates require packet evidence for attempt-level use.
- Apple location fields are advertised labels, not physical-location proof.
- Later routing lookups are not contemporaneous unless a historical API and
  fixed observation timestamps are used and preserved.
- The pipeline excludes ambiguous attempts rather than selecting a convenient
  request or connection.
- The controller is designed for macOS/Safari and must not be represented as
  validated on other client platforms without additional work.
