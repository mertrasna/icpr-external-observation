# How to use the protocol methods

## 1. Verify the software offline

```sh
make setup
make test-protocol
./protocol-diagnostic/protocol-diag --help
./protocol-diagnostic/h3-required-diag --help
```

## 2. Create your study profile

Read [`examples/README.md`](examples/README.md), copy one configuration/plan
pair into the ignored `protocol-diagnostic/local/` workspace, and replace every
documentation value with measurements from your endpoint and access network.
Do not reuse another study's origin addresses, ingress pin, dated DNS snapshot,
routing evidence, or completion attestations.

At minimum, freeze and hash your origin addresses; client and access-network
conditions; selected ingress and dated ASN evidence; bounded DNS candidate
snapshot; fixed slot order; and required readiness attestations.

## 3. Run preflight with explicit paths

```sh
CONFIG=protocol-diagnostic/local/dual-protocol-config.json
PLAN=protocol-diagnostic/local/dual-protocol-plan.json
CANDIDATES=protocol-diagnostic/local/run-day-dns-candidates.json

./protocol-diagnostic/protocol-diag preflight \
  --config "$CONFIG" \
  --plan "$PLAN" \
  --candidate-snapshot "$CANDIDATES"
```

Use `h3-required-diag` and the matching H3 paths for the origin-gated method.
Its additional controls are documented in
[`h3-required/README.md`](h3-required/README.md).

## 4. Preserve and pair observations

Live commands can modify macOS DNS/PF state and, for H3-required, the origin
firewall. Review the CLI help and safety approvals first. After a verified
server archive pull, pair each method into its isolated output root:

```sh
./protocol-diagnostic/protocol-diag pair \
  --config "$CONFIG" \
  --server-root server/recovery-data
```

Raw captures, server logs, local profiles, and derived tables belong in ignored
study storage, not in the public methods repository.
