# Published-egress catalogue analysis

This folder contains reusable methods for collecting and comparing Apple's
published iCloud Private Relay egress catalogue. It intentionally contains no
claims about the results of an earlier campaign.

The source CSV is published at:

```text
https://mask-api.icloud.com/egress-ip-ranges.csv
```

Apple's file has no header. Each row is:

```text
cidr,country,region,city,<empty fifth field>
```

These methods describe the catalogue Apple publishes. They do not show which
egress was selected for a connection, traffic volume, relay capacity, or the
transport protocol used by a request.

Run the commands below from the repository root.

## 1. Setup and offline demonstration

```bash
make setup
make test-egress
make demo-egress
```

The demonstration uses only the documentation prefixes in
`examples/snapshots/` and writes to
`results/egress-catalogue/generated/demo/`.

## 2. Start a new snapshot series

Create a local input directory:

```bash
mkdir -p egress-catalog-analysis/snapshots
```

On every declared observation date, download the complete file, retain the
retrieval time, and create a filename-bound SHA-256 sidecar:

```bash
SNAPSHOT="egress-catalog-analysis/snapshots/egress-$(date -u +%F).csv"
curl -fsSL https://mask-api.icloud.com/egress-ip-ranges.csv -o "$SNAPSHOT"
shasum -a 256 "$SNAPSHOT" > "$SNAPSHOT.sha256"
```

Confirm that the source retains Apple's five-column row format. Then check
CIDR validity, exact duplicates, raw/collapsed counts, and overlaps before
interpreting the snapshot:

```bash
.venv/bin/python egress-catalog-analysis/check_overlaps.py "$SNAPSHOT"
```

The snapshot directory is excluded from the source repository. Publish data
only when Apple's terms and your institutional review allow it.

## 3. Analyse one snapshot

The standard-library summary can run without routing data:

```bash
.venv/bin/python egress-catalog-analysis/us_share.py "$SNAPSHOT" \
  --country US --top 10
```

`--country` selects the country code highlighted in the output; it defaults to
`US` for backward compatibility.

Operator and BGP attribution require a dated `pyasn` table plus an AS-name
mapping. Always pass the files used for the analysis explicitly:

```bash
.venv/bin/python egress-catalog-analysis/snapshot_report.py "$SNAPSHOT" \
  --country US --dat PATH_TO_IPASN.dat --names PATH_TO_ASNAMES.json

.venv/bin/python egress-catalog-analysis/operator_mix.py "$SNAPSHOT" \
  --dat PATH_TO_IPASN.dat --names PATH_TO_ASNAMES.json

.venv/bin/python egress-catalog-analysis/bgp_compare.py "$SNAPSHOT" \
  --dat PATH_TO_IPASN.dat --names PATH_TO_ASNAMES.json
```

The scripts warn when dates inferred from the snapshot and routing filenames
differ. A fixed routing table is useful for isolating catalogue changes; a
same-day table is appropriate when the question concerns routing at that date.
Declare the choice before inspecting outcomes.

## 4. Compare two observations

```bash
.venv/bin/python egress-catalog-analysis/churn_diff.py \
  egress-catalog-analysis/snapshots/egress-YYYY-MM-DD.csv \
  egress-catalog-analysis/snapshots/egress-YYYY-MM-DD.csv
```

The comparison distinguishes:

- address space added to or removed from the published list;
- changed country, region, or city labels for still-covered address space; and
- CIDR re-slicing, where boundaries change but covered address space does not.

Treat a label change as a change in Apple's published text, not proof that
infrastructure moved geographically.

## 5. Build a time series

```bash
mkdir -p results/egress-catalogue/generated

.venv/bin/python egress-catalog-analysis/churn_series.py \
  --dir egress-catalog-analysis/snapshots \
  --out results/egress-catalogue/generated/churn_series.csv

.venv/bin/python egress-catalog-analysis/churn_plot.py \
  --csv results/egress-catalogue/generated/churn_series.csv \
  --pdf results/egress-catalogue/generated/catalogue_churn_timeline.pdf \
  --png results/egress-catalogue/generated/catalogue_churn_timeline.png
```

`interval_days` records gaps between collected snapshots. Counts are per
observation interval, not automatically per calendar day.

For the complete audit tables, add the routing inputs explicitly:

```bash
.venv/bin/python egress-catalog-analysis/catalogue_audit.py \
  --dir egress-catalog-analysis/snapshots \
  --dat PATH_TO_IPASN.dat \
  --names PATH_TO_ASNAMES.json \
  --output-dir results/egress-catalogue/generated
```

The command writes snapshot, country, operator, BGP, exact-change, and
published-label-transition tables. The exact-change table can contain Apple's
complete prefix rows; treat it as data rather than a source-code artifact.

## Outputs

| Output | Meaning |
| --- | --- |
| `churn_series.csv` | Address-space changes by family and interval |
| `snapshot_manifest.csv` | Input paths, dates, sizes, hashes, and spacing |
| `snapshot_series.csv` | Catalogue size and integrity metrics |
| `country_series.csv` | Country allocation metrics by family |
| `operator_series.csv` | Routing-attributed operator counts |
| `bgp_series.csv` | Distinct covering BGP prefixes by operator |
| `catalogue_changes.csv` | Exact changed catalogue rows; potentially large |
| `churn_transitions.csv` | Complete published-label transitions |
| `catalogue_churn_timeline.pdf/.png` | Deterministic timeline figures |

## Methodological limits

- Keep IPv4 addresses and IPv6 `/64` units separate.
- Prefix-row counts are not relay counts or capacity measurements.
- AS attribution inherits the date, coverage, and ambiguity of the routing
  input.
- Organisation-name keyword classification must be reviewed when new ASNs
  appear.
- Missing observation dates create multi-day intervals; do not silently label
  them daily churn.
- Preserve every downloaded snapshot and hash, including unchanged files.

See [HOW_TO_USE.md](HOW_TO_USE.md) for the complete question-to-tool guide and
[data/README.md](data/README.md) for routing-input provenance.
