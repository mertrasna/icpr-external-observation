# H3-required origin TCP gate

`icpr-h3-origin-gate` is the root-only server helper for the separate
`h3-required-v1` diagnostic. It creates one transient, session-named nftables
table that drops only inbound IPv4 TCP/443 to the canonical RFC 1918 address
supplied by the hash-verified diagnostic configuration. UDP/443, SSH, TCP/80,
outbound traffic, Caddy, continuous capture, and the AWS security group are not
changed.

The helper must be installed byte-for-byte as
`/usr/local/sbin/icpr-h3-origin-gate`, owned by root and executable, before an
approved live gate session. `arm` creates the table without a target, confirms
an independent 1,800-second systemd rollback timer, and only then inserts the
timeout-bound target. `disarm` snapshots the final counter and deletes only the
session table and matching transient units.

Commands emit one JSON object:

```text
icpr-h3-origin-gate validate SESSION_ID PRIVATE_IPV4
icpr-h3-origin-gate arm SESSION_ID PRIVATE_IPV4
icpr-h3-origin-gate status SESSION_ID PRIVATE_IPV4
icpr-h3-origin-gate disarm SESSION_ID PRIVATE_IPV4
```

Do not run `arm` directly during implementation or non-live verification. The
Mac controller will provide the exact approved command after all controls are
ready.
