# Example protocol profiles

These two complete profile pairs show the fields and fixed slot order required
by the controller:

| Method | Configuration | Plan |
| --- | --- | --- |
| Dual protocol | `dual-protocol-config.json` | `dual-protocol-plan.json` |
| HTTP/3 required | `h3-required-config.json` | `h3-required-plan.json` |

They use the reserved documentation hostname `measurement.example.org`, RFC
5737 public addresses, an RFC 1918 private address, and template attestations.
They are safe defaults for inspection and tests, not live measurement inputs.

## Prepare a profile for a new study

1. Copy the selected configuration, plan, and `reference/` files to a private
   study workspace under `protocol-diagnostic/local/`.
2. Replace the origin hostname and public/private addresses with outputs from
   your own controlled endpoint.
3. Record the current Safari version, access-network condition, Private Relay
   location setting, selected ingress, ASN, and bounded routing evidence.
4. Generate a current DNS design snapshot with `snapshot-candidates`; do not
   reuse the documentation addresses or another study's candidates.
5. Replace the campaign-completion and run-day HTTP/3 readiness attestations
   with hash-verified records from your study.
6. Set `example_only` to `false`, freeze the configuration, update its SHA-256
   sidecar, insert that digest and path into the copied plan, then update the
   plan sidecar.
7. Pass both paths explicitly to `preflight` and review every blocker before
   using a live or privileged command.

The repository intentionally does not provide a live destination, ingress, SSH
key, AWS profile, or ready-to-run attestation.
