# Contributing

Contributions that improve clarity, reproducibility, tests, or documentation
are welcome. This is an MSc research repository: prefer small, reviewable
changes over framework migrations or broad refactors.

## Before proposing a change

1. Read the README in the folder you are changing.
2. Do not add private evidence, credentials, raw packet captures, local
   recovery archives, or researcher-identifying data.
3. Keep frozen campaign evidence and plans immutable. A change to collection
   logic must not silently reclassify earlier observations.
4. Add or update a focused test when changing deterministic parsing, pairing,
   validation, or analysis behaviour.

## Local checks

The common offline check is:

```sh
make setup
make test
```

For a focused change, use the corresponding Make target so it runs inside the
repository environment:

```sh
make test-egress
make test-ecs
make test-experiment
make test-protocol
make test-server
```

Do not run `pair` as a routine contribution check: it is a cumulative full
archive rebuild. Do not start a live measurement, cloud deployment, scanner, or
privileged command unless the contribution explicitly concerns an approved
operator task.

## Documentation and data changes

Document inputs, outputs, and assumptions in the affected folder README. Do not
add study findings or generated results to this methods repository. Any
separate data release needs SHA-256 checksums and a provenance note describing
its source date and collection method. Keep generated outputs separate from raw
inputs, and state the exact command used to create them.
