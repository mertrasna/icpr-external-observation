# Privacy and ethics

This project measures network behaviour and preserves packet, server, DNS, and
configuration evidence. Such evidence can contain personal data or operational
details even when the source code does not contain credentials.

## Release principles

- Keep the public source repository methods-only: do not include findings,
  result artifacts, or original measurement evidence.
- Do not publish raw captures, server logs, private pin lists, real client
  addresses, SSH material, cloud credentials, or researcher-identifying
  location details without explicit review and consent.
- Treat hostnames, IP addresses, timestamps, request identifiers, and routing
  evidence as reviewable data: combinations of otherwise public fields may
  identify a person, network, or controlled service.
- If data or outputs are released separately, include only the smallest reviewed
  package needed for its stated purpose and explain redactions or exclusions.
- Preserve the original evidence and its hashes under the approved retention
  process; a public derivative must not silently replace the original record.

## Measurement conduct

Live collection is deliberately approval-gated. The experiment controller,
ECS scanner, and protocol diagnostics are not permission to scan or interfere
with networks. Run them only within the approved scope, rate limits, and
operator procedures documented in their respective READMEs.

Do not rerun a historical campaign merely to make a repository demonstration.
Current DNS answers, relay routing, client software, and server state may
differ from the original observation period. A new run must be recorded as a
new measurement with its own approvals, evidence, and configuration version.

## Responsible disclosure

This repository studies observable system behaviour. It is not intended to
collect third-party traffic, bypass access controls, or expose operational
weaknesses. If you believe the code or documentation could create a security or
privacy risk, follow `SECURITY.md` rather than opening a public issue with
sensitive details.
