# Routing inputs

The operator and BGP analyses require two researcher-supplied, dated files:

- a `pyasn` `.dat` table mapping IP prefixes to origin ASNs; and
- an AS-name JSON mapping from ASN strings to organisation names.

Keep the original RIB, the conversion command, retrieval metadata, source URL,
applicable licence, and SHA-256 with the study data. Large routing inputs are
ignored by Git.

You can build a table with the utilities installed by `pyasn`, for example:

```bash
.venv/bin/python .venv/bin/pyasn_util_download.py --latestv46 \
  --filename egress-catalog-analysis/data/rib_YYYYMMDD.bz2
.venv/bin/python .venv/bin/pyasn_util_convert.py --single \
  egress-catalog-analysis/data/rib_YYYYMMDD.bz2 \
  egress-catalog-analysis/data/ipasn_YYYYMMDD.dat
.venv/bin/python .venv/bin/pyasn_util_asnames.py \
  -o egress-catalog-analysis/data/asnames_YYYYMMDD.json
```

“Latest” refers to retrieval time and is not automatically the correct
historical control. Decide whether to hold one table fixed or use same-day
tables before examining catalogue changes, and pass the selected paths with
`--dat` and `--names`.
