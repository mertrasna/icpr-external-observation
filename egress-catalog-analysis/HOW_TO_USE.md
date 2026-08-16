# How to use the egress-catalogue analysis toolkit

## What this folder can measure

Use one or more dated copies of Apple's published Private Relay egress
catalogue to:

- validate CIDRs and count raw and collapsed prefixes;
- count published IPv4 addresses and IPv6 `/64` allocation units;
- measure the US share, or any other selected country's share;
- attribute catalogue entries to origin ASNs and operators;
- compare Apple's catalogue granularity with covering BGP routes;
- distinguish address-space additions, removals, label changes, and CIDR
  re-slicing between observations; and
- produce longitudinal tables and figures for a reproducible analysis.

These are analyses of Apple's published catalogue. They do not measure relay
traffic, capacity, or which egress a user actually received.

Run all commands below from the repository root.

## Five-minute offline tour

```bash
make setup
make test-egress

SNAPSHOT=egress-catalog-analysis/examples/snapshots/egress-2026-01-02.csv
.venv/bin/python egress-catalog-analysis/check_overlaps.py "$SNAPSHOT"
.venv/bin/python egress-catalog-analysis/us_share.py "$SNAPSHOT" \
  --country ZZ --top 10

make demo-egress
```

The example uses only IANA documentation prefixes and invented labels. The
last command demonstrates the two-date series and plotting tools, writing
ignored output under `results/egress-catalogue/generated/demo/`.

## Choose the analysis that answers your question

| Research question | Command | Inputs | What it reports or writes |
| --- | --- | --- | --- |
| Are the CIDRs valid, unique, and non-overlapping? How many raw and collapsed prefixes are present? | `check_overlaps.py` | One CSV | Malformed and duplicate CIDRs; raw/collapsed prefix counts; naive and overlap-free address totals |
| How many prefixes and allocation units are published by country? What is the US or another country's share? | `us_share.py` | One CSV | Total and selected-country prefix shares, IPv4-address share, IPv6-prefix share, and top countries |
| What is the compact overview for one snapshot? | `snapshot_report.py` | One CSV plus routing data | Selected-country share, total prefixes, per-ASN shares, and IPv4 catalogue-to-BGP granularity |
| Which operators originate the published entries? | `operator_mix.py` | One CSV plus routing data | IPv4/IPv6 operator mix using raw prefixes or collapsed blocks |
| How does the published footprint relate to BGP? | `bgp_compare.py` | One CSV plus routing data | Distinct covering BGP routes by operator and ASN, with announced-footprint context |
| What changed between two observations? | `churn_diff.py` | Two CSVs | Address-space additions/removals, published-label changes, and coverage-preserving CIDR re-slicing |
| How did those changes evolve across a window? | `churn_series.py` | At least two dated CSVs | One CSV row per address family and adjacent observed interval |
| How can I visualise the interval series? | `churn_plot.py` | `churn_series.csv` | A vector PDF and a high-resolution PNG |
| How can I generate all longitudinal audit tables? | `catalogue_audit.py` or `make analyze-egress` | At least two dated CSVs plus one fixed routing dataset | Input manifest, snapshot, country, operator, BGP, exact-change, and label-transition tables |

## 1. Prepare your inputs

Store complete snapshots with dates in their filenames:

```text
egress-catalog-analysis/snapshots/egress-YYYY-MM-DD.csv
```

The expected Apple row format is:

```text
cidr,country,region,city,<empty fifth field>
```

Create the local directory and, on each declared observation date, retain the
retrieval time and a filename-bound SHA-256 sidecar. Collection commands and
data-handling guidance are in [README.md](README.md).

The three routing-backed commands and the complete audit also need:

- a dated `pyasn` IP-to-origin-ASN `.dat` table; and
- a dated JSON mapping from ASN strings to organisation names.

See [data/README.md](data/README.md) for acquisition and provenance. Decide
before analysis whether one routing table will be held fixed or whether each
snapshot will be analysed with a contemporaneous table. The all-in-one
longitudinal audit accepts one routing pair and therefore implements the fixed
control; run the single-snapshot tools separately for same-day attribution.

The remaining examples assume these shell variables have been set in the same
terminal:

```bash
SNAPSHOT=egress-catalog-analysis/snapshots/egress-YYYY-MM-DD.csv
OLDER=egress-catalog-analysis/snapshots/egress-YYYY-MM-DD.csv
NEWER=egress-catalog-analysis/snapshots/egress-YYYY-MM-DD.csv
SNAPSHOT_DIR=egress-catalog-analysis/snapshots
ROUTING_DAT=egress-catalog-analysis/data/ipasn_YYYYMMDD.dat
ASN_NAMES=egress-catalog-analysis/data/asnames_YYYYMMDD.json
OUTPUT_DIR=results/egress-catalogue/generated
mkdir -p "$OUTPUT_DIR"
```

Replace every `YYYY-MM-DD` or `YYYYMMDD` with an actual date. `OLDER` and
`NEWER` must name different observations.

## 2. Count and validate one snapshot without routing data

Check input quality and count prefixes and address space:

```bash
.venv/bin/python egress-catalog-analysis/check_overlaps.py "$SNAPSHOT"
```

The command exits non-zero for malformed CIDRs, exact duplicate strings, or
overlapping coverage. It reports raw and collapsed prefix counts separately
for IPv4 and IPv6, plus naive and overlap-free address totals.

Count catalogue allocation by country and highlight the US:

```bash
.venv/bin/python egress-catalog-analysis/us_share.py "$SNAPSHOT" \
  --country US --top 15
```

Change `US` to any two-letter country code. The output separates IPv4 and IPv6
and reports the selected country's shares by all-prefix count, IPv4-prefix
count, IPv4-address count, and IPv6-prefix count. IPv4 address totals describe
published address-space allocation, not a count of relays or capacity.

## 3. Add ASN, operator, and BGP context to one snapshot

Start with a compact four-part summary:

```bash
.venv/bin/python egress-catalog-analysis/snapshot_report.py "$SNAPSHOT" \
  --country US --dat "$ROUTING_DAT" --names "$ASN_NAMES"
```

For operator composition, count Apple's raw prefix rows:

```bash
.venv/bin/python egress-catalog-analysis/operator_mix.py "$SNAPSHOT" \
  --dat "$ROUTING_DAT" --names "$ASN_NAMES" --top 15
```

Repeat with `--collapse` when the research unit should be contiguous merged
blocks rather than catalogue rows:

```bash
.venv/bin/python egress-catalog-analysis/operator_mix.py "$SNAPSHOT" \
  --dat "$ROUTING_DAT" --names "$ASN_NAMES" --collapse --top 15
```

Count the distinct covering BGP routes used by catalogue entries and compare
them with each operator's announced routing footprint:

```bash
.venv/bin/python egress-catalog-analysis/bgp_compare.py "$SNAPSHOT" \
  --dat "$ROUTING_DAT" --names "$ASN_NAMES" --top 15
```

These scripts warn when dates inferred from input filenames differ. Review
unrouted entries, failed lookups, containment failures, and previously unseen
organisation names before interpreting operator shares.

## 4. Compare two observations

```bash
.venv/bin/python egress-catalog-analysis/churn_diff.py \
  "$OLDER" "$NEWER" --json "$OUTPUT_DIR/churn_diff.json"
```

The comparison works at address-space level so split/merge re-slicing does not
become false addition or removal. It reports re-slicing separately and treats
country, region, or city edits as changes in Apple's published labels—not as
proof that infrastructure moved.

## 5. Analyse a complete observation window

Build interval-by-interval change data and its figure:

```bash
.venv/bin/python egress-catalog-analysis/churn_series.py \
  --dir "$SNAPSHOT_DIR" --out "$OUTPUT_DIR/churn_series.csv"

.venv/bin/python egress-catalog-analysis/churn_plot.py \
  --csv "$OUTPUT_DIR/churn_series.csv" \
  --pdf "$OUTPUT_DIR/catalogue_churn_timeline.pdf" \
  --png "$OUTPUT_DIR/catalogue_churn_timeline.png"
```

`interval_days` makes missing observation dates explicit. Rows represent
adjacent collected observations and are not automatically daily measurements.

Generate the complete audit tables with the fixed routing control:

```bash
.venv/bin/python egress-catalog-analysis/catalogue_audit.py \
  --dir "$SNAPSHOT_DIR" \
  --dat "$ROUTING_DAT" \
  --names "$ASN_NAMES" \
  --output-dir "$OUTPUT_DIR"
```

Or run the audit, change series, and figure together:

```bash
make analyze-egress \
  SNAPSHOT_DIR="$SNAPSHOT_DIR" \
  ROUTING_DAT="$ROUTING_DAT" \
  ASN_NAMES="$ASN_NAMES" \
  RESULTS_DIR="$OUTPUT_DIR"
```

## Complete audit outputs

| Output | Use |
| --- | --- |
| `snapshot_manifest.csv` | Record input path, date, size, SHA-256, and spacing between observations |
| `snapshot_series.csv` | Track rows, IPv4/IPv6 prefixes, allocation units, country/location counts, collapsed blocks, and non-canonical CIDRs |
| `country_series.csv` | Compare each country's IPv4 prefix/address and IPv6 prefix/`/64` allocation by date |
| `operator_series.csv` | Compare routing-attributed raw and collapsed operator composition by date |
| `bgp_series.csv` | Compare distinct covering BGP-route counts by operator and date |
| `catalogue_changes.csv` | Inspect exact added, removed, and relabelled catalogue rows |
| `churn_transitions.csv` | Inspect complete published country/region/city label transitions by address space |
| `churn_series.csv` | Plot or model interval-level additions, removals, relabelling, and re-slicing |
| `catalogue_churn_timeline.pdf/.png` | Use the generated timeline in review or reporting |

`catalogue_changes.csv` can reproduce complete Apple prefix rows and labels, so
treat it as a data output rather than source code. Generated files are ignored
by Git under `results/egress-catalogue/generated/`.

## What each folder file is for

The nine commands in the analysis table are the user-facing programs.
Supporting files are:

| Path | Role |
| --- | --- |
| `snapshot_common.py` | Shared date checks, defaults, and safe BGP lookup helpers imported by other scripts; not a separate analysis command |
| `requirements.txt` | Python dependencies for this folder; the root `make setup` installs the repository-wide pinned requirements |
| `examples/snapshots/` | Tiny synthetic inputs for offline demonstrations |
| `tests/` | Offline regression tests run by `make test-egress` |
| `data/README.md` | Routing-data acquisition and provenance instructions |
| `examples/README.md` | Synthetic-example scope and limitations |
| `README.md` | Detailed collection procedure, method notes, and output definitions |
| `.gitignore` | Keeps downloaded snapshots, routing data, and generated results local by default |

## Limits to state with results

- Published prefixes are not observed relay selections or relay counts.
- Country, region, and city fields are Apple's labels, not proof of physical
  location.
- IPv4 addresses and IPv6 `/64` allocation units are not directly comparable.
- Routing attribution is only as contemporaneous and complete as its inputs.
- Operator classification depends on AS-name keywords and requires review.
- A missing date turns the next comparison into a multi-day interval.
- The toolkit provides country-level allocation tables and complete label
  transitions, but not a standalone per-region or per-city frequency table.
