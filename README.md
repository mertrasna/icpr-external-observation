# iCPR External Observation Methods

A reusable methods toolkit for investigating Apple iCloud Private Relay. It
contains four complementary workflows: analysis of Apple egress-catalogue
snapshots, DNS-derived ingress discovery, controlled browser measurements, and
protocol diagnostics.

This is a methods repository. It does not publish the original study findings,
measurement evidence, or result tables. A researcher can verify the code with
synthetic data, apply the analysis to their own inputs, and adapt the collection
workflows to a separately approved environment.

## Quick start

Python 3.12 or newer and `make` are required. `make setup` may download the
pinned Python environment; the tests and demo are offline. None of these
commands starts a measurement, contacts a research endpoint, or changes network
settings.

```sh
make setup
make test
make demo-egress
```

The demo uses two synthetic catalogue snapshots and writes disposable output
to `results/egress-catalogue/generated/demo/`.

To analyse your own dated Apple catalogue snapshots and routing data:

```sh
make analyze-egress \
  SNAPSHOT_DIR=/path/to/snapshots \
  ROUTING_DAT=/path/to/ipasn.dat \
  ASN_NAMES=/path/to/asnames.json
```

Generated tables and figures stay under
`results/egress-catalogue/generated/`, which is excluded from the public source
tree. See [Reusing the methods](docs/reproducibility.md) for input expectations
and provenance guidance.

## Repository map

| Folder | Purpose | Start here |
| --- | --- | --- |
| `egress-catalog-analysis/` | Analyse Apple egress catalogues by country, operator, BGP context, and change | [How to use](egress-catalog-analysis/HOW_TO_USE.md) |
| `ecs-scanner/` | Resumable ECS enumeration of DNS-derived ingress candidates | [How to use](ecs-scanner/HOW_TO_USE.md) |
| `experiment/` | Controlled measurement, evidence pairing, and local reports | [How to use](experiment/HOW_TO_USE.md) |
| `protocol-diagnostic/` | Dual-protocol and HTTP/3-required diagnostic methods | [How to use](protocol-diagnostic/HOW_TO_USE.md) |
| `server/` | Controlled endpoint, capture, and evidence-retention tooling | [How to use](server/HOW_TO_USE.md) |
| `infra/` | Terraform for a researcher-controlled endpoint and retention resources | [How to use](infra/HOW_TO_USE.md) |
| `docs/` | Method reuse, data handling, privacy, and release guidance | [Documentation guide](docs/HOW_TO_USE.md) |
| `results/` | Ignored local output location; no study results are bundled | [How to use](results/HOW_TO_USE.md) |

Each workflow remains in one folder. Short newcomer guides explain the normal
path; detailed operator procedures stay beside the code they describe.

## What a clone supports

| Task | Available from a clone? |
| --- | --- |
| Verify parsers, validators, pairing logic, and analysis code | Yes, with `make test` |
| Exercise the catalogue workflow | Yes, with the synthetic demo |
| Analyse a new catalogue dataset | Yes, after supplying snapshots and routing inputs |
| Run a new network measurement | Only in an authorised environment after adapting the example configuration |
| Rebuild the original study findings | No; findings and campaign evidence are not distributed here |

## Safe use

The live controller, ECS scanner, server deployment, and protocol diagnostics
perform network measurement or privileged local operations. Read the relevant
folder guide and [privacy and ethics guidance](docs/privacy-and-ethics.md)
before using them. Treat every new run as a new measurement with its own scope,
configuration, timestamps, and evidence hashes.

Contributions are described in [CONTRIBUTING.md](CONTRIBUTING.md), sensitive
security reports should follow [SECURITY.md](SECURITY.md), and third-party
input boundaries are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The code is available under
the [MIT License](LICENSE), and citation metadata is provided in
[CITATION.cff](CITATION.cff).
