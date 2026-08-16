# HTTP/3-required method

This optional method tests a fixed ten-slot sequence while a narrowly scoped
origin gate suppresses new inbound IPv4 TCP/443 connections. UDP/443, SSH,
TCP/80, outbound traffic, Caddy, and packet capture remain available.

Start from `protocol-diagnostic/examples/h3-required-config.json` and its
matching plan. Replace every documentation value and freeze the new hashes
before using a live command. The selected config must bind the same canonical
RFC 1918 address in `server.private_ipv4` and `origin_gate.private_ipv4`; gate
SSH is read from `server.live_caddy_snapshot.ssh_target`.

## Offline checks

```sh
make test-protocol
./protocol-diagnostic/h3-required-diag --help
```

Do not use `gate-arm` as a smoke test. Install and review
`server/h3-required/icpr-h3-origin-gate` on your own origin first.

## Required controls

Before the first slot, preserve and hash:

1. a Safari HTTP/3 discovery warm-up with Private Relay off;
2. an external TCP-only failure with a positive gate-counter delta; and
3. a direct, Private-Relay-off HTTP/3 success with matching Caddy and QUIC
   evidence.

Bind the controls to one gate session with `verify-controls`. The gate has a
1,800-second kernel timeout and independent systemd rollback. Arm it only after
control verification, pass the same session identifier to every slot, preserve
the post-series control, and disarm it promptly. The CLI shows the deliberate
approval tokens required by each live action.

After a verified archive pull, run one pairing pass with the customised config:

```sh
./protocol-diagnostic/h3-required-diag pair \
  --config protocol-diagnostic/local/h3-required-config.json \
  --server-root server/recovery-data
```

This method observes outer connections and destination-facing HTTP/3. It cannot
inspect or identify the encrypted inner relay protocol.
