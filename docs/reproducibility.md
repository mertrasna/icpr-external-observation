# Reusing and re-measuring the methods

The repository is designed to make the implementation inspectable and the
methods reusable. It does not bundle the original study findings or evidence.
Three activities should be kept distinct.

## 1. Verify the implementation

Create the pinned environment and run the offline tests:

```sh
make setup
make test
```

The tests exercise parsing, validation, pairing, diagnostic controls, and
catalogue analysis with fixtures. They do not start Safari, contact a research
endpoint, change network settings, or perform a live scan.

The self-contained catalogue demonstration is also offline:

```sh
make demo-egress
```

It uses two synthetic snapshots and writes disposable local output. The release
checks for this source tree used Python 3.14.6; the supported baseline is Python
3.12 or newer with the versions pinned in `requirements.txt`.

## 2. Apply the analysis to your own catalogue data

Collect dated Apple egress-catalogue CSV snapshots without overwriting earlier
downloads. Prepare a pyasn IP-to-ASN database and a matching ASN-name JSON file,
then provide all three input paths explicitly:

```sh
make analyze-egress \
  SNAPSHOT_DIR=/path/to/snapshots \
  ROUTING_DAT=/path/to/ipasn.dat \
  ASN_NAMES=/path/to/asnames.json
```

The command writes tables and figures to
`results/egress-catalogue/generated/` by default. Set `RESULTS_DIR` to use a
different local output directory. Generated output is ignored by the public
source repository.

Input snapshots should follow the filename and column conventions in
`egress-catalog-analysis/HOW_TO_USE.md`. Record retrieval time, source URL,
byte size, and SHA-256 for every input. The routing database and ASN-name file
must describe the intended comparison date; substituting current routing data
changes the question being measured.

## 3. Conduct a new network measurement

The experiment, ECS scanner, endpoint, and protocol-diagnostic folders describe
live collection methods. A researcher must adapt the example configuration to
an endpoint and network they control, obtain any required approval, freeze the
configuration and plan, and preserve hashes before collection.

New observations describe the network, software, relay routing, and endpoint
state at the new measurement time. They are not a reconstruction of the
original campaign. Preserve client and server evidence separately and use:

```sh
./experiment/icpr pair --server-root server/recovery-data
./experiment/icpr daily-report
```

Pairing verifies manifests and sidecars before deriving reports. It reads the
accumulated archive and can be expensive, so it should not be used as a routine
smoke test.

## Provenance for reusable measurements

For each independently collected dataset, record:

- the code revision and dependency versions;
- configuration and execution-plan hashes;
- collection timestamps, platform versions, and network context;
- a filename-bound SHA-256 manifest for all inputs;
- the exact analysis commands and parameters; and
- exclusions, failed observations, redactions, and protocol limitations.

Keep source evidence immutable. Derived tables and figures should go to a
separate output directory and identify the input manifest from which they were
created.
