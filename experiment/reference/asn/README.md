# Dated origin-ASN and operator inputs

Pairing performs longest-prefix matching for the ingress observed in the client
capture and the egress source observed by the server. Both mappings must refer
to the observation UTC date.

## Create local files

Copy and edit the neutral schemas:

```bash
cp experiment/reference/asn/origin_prefixes.example.csv \
  experiment/reference/asn/origin_prefixes.csv
cp experiment/reference/asn/operator_map.example.csv \
  experiment/reference/asn/operator_map.csv
```

Each origin row contains `date,prefix,asn,source,source_hash`. Preserve the
complete dated routing evidence behind `source_hash`. Each operator row records
the raw ASN, stable operator ID, human-readable name, review rule, and map
version. Do not silently group an unknown ASN.

After review, create filename-bound sidecars:

```bash
(cd experiment/reference/asn && \
  shasum -a 256 origin_prefixes.csv > origin_prefixes.csv.sha256 && \
  shasum -a 256 operator_map.csv > operator_map.csv.sha256)
```

The configuration's map version must match every operator-map row. If the
longest matching prefix has multiple distinct origins, leave the observation
pending rather than choosing one.

## Resolve post-pair gaps

After pairing against the verified server archive:

```bash
./experiment/icpr pair --server-root server/recovery-data
./experiment/icpr asn-gaps --date YYYY-MM-DD --require-empty
```

If gaps remain, freeze a reconstruction plan containing the complete distinct
set of pending ingress and egress addresses. Never select addresses based on
operator or outcome.

The included helper accepts preserved RIPEstat historical BGP-state responses
at fixed observation-date times. First validate the complete evidence set, then
apply it:

```bash
python3 experiment/reference/asn/apply_historical_bgp_reconstruction.py \
  --plan PATH_TO_FROZEN_PLAN.json \
  --evidence-dir PATH_TO_COMPLETE_EVIDENCE

python3 experiment/reference/asn/apply_historical_bgp_reconstruction.py \
  --plan PATH_TO_FROZEN_PLAN.json \
  --evidence-dir PATH_TO_COMPLETE_EVIDENCE \
  --apply
```

Obtain approval before sending observed relay addresses to a public API.
Preserve the later query time and every response. Accept a mapping only when
the most-specific prefix and final AS-path origin are identical across the
complete declared timestamps and routes. Never describe a later current-state
lookup as contemporaneous evidence.

Enrichment changes the origin-file hash. Preserve previously used execution
plans; re-freeze only a not-yet-used plan, then perform the one required final
pairing rebuild and zero-gap check.
