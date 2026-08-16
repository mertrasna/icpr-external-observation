# How to use the local results folder

Run the synthetic catalogue example:

```sh
make demo-egress
```

Analyse researcher-supplied data:

```sh
make analyze-egress \
  SNAPSHOT_DIR=/path/to/snapshots \
  ROUTING_DAT=/path/to/ipasn.dat \
  ASN_NAMES=/path/to/asnames.json
```

Both commands write under `results/egress-catalogue/generated/` unless
`RESULTS_DIR` is set. Generated files are ignored and should be deleted or
archived according to the researcher's own data-management plan.

Never place raw captures, server logs, responses, credentials, private
configuration, or participant identifiers here. Do not commit generated results
to this repository.
