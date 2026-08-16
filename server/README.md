# Controlled measurement server

This folder installs and verifies the controlled destination used by the iCPR
measurements. It provides an HTTP/1.1, HTTP/2, and HTTP/3 probe endpoint,
narrow packet capture, JSON access logging, and optional evidence retention.

The checked-in Caddy configuration is a reusable template. The installer
requires a public DNS hostname, renders a temporary deployment configuration,
and leaves the source template unchanged. Record the resulting installed
configuration hashes. Do not rewrite historical manifests or evidence to make
them describe a new server.

## Quick check

The following check is offline. It does not contact a server or change the
local machine:

```sh
bash -n \
  server/install.sh \
  server/verify.sh \
  server/retention/icpr-backup \
  server/retention/icpr-health-check \
  server/retention/install.sh \
  server/retention/pull-to-mac.sh \
  server/h3-required/icpr-h3-origin-gate

python3 -m unittest discover -s server/tests -p 'test_*.py'
```

## Requirements

The server installation expects:

- Ubuntu 24.04 with UTC time synchronization;
- at least 20 GiB of free disk space;
- a public DNS hostname pointing to the server;
- inbound TCP/80, TCP/443, and UDP/443;
- SSH restricted to the administrator's IPv4 `/32`; and
- the Terraform resources under `infra/endpoint/`.

The verification client needs Bash, AWS CLI, Terraform, OpenSSL, SSH, `jq`, and
curl. The curl selected through `HTTP3_CURL` must support `--http3-only`.

## Configure

1. Deploy and review `infra/endpoint/` as described in its README.
2. Point a DNS hostname at Terraform's `elastic_public_ipv4` output.
3. Keep the `__ICPR_HOSTNAME__` marker in `server/Caddyfile`; pass the real
   hostname to the installer.
4. Review the SSH key, AWS profile, and retention settings for the new
   environment.
5. Confirm that the server is synchronized to UTC and has enough free space.

The installer obtains Caddy from its official signed Ubuntu repository and
installs `tshark`/`dumpcap`, `jq`, and the required system packages. It also
validates the Caddy and systemd configuration before enabling services.

## Deploy

Installation changes packages, systemd services, and system configuration on
the destination. Run it only on an authorised measurement server after
reviewing the copied files:

```sh
SERVER_HOST="measurement.example.org"
SSH_KEY="${HOME}/.ssh/icpr_measurement"

scp -i "$SSH_KEY" -r server "ubuntu@${SERVER_HOST}:/tmp/icpr-server"
ssh -i "$SSH_KEY" "ubuntu@${SERVER_HOST}" \
  'sudo /tmp/icpr-server/install.sh measurement.example.org'
```

Replace both example hostnames with the same public DNS name. The installer
accepts exactly one lowercase, fully qualified DNS hostname; it rejects IP
literals, URLs, ports, wildcard names, and invalid DNS labels before making
changes. It also refuses to continue unless the server is synchronized to UTC
and has at least 20 GiB free. If `cloud-init` reports an earlier failure, it
requires a valid SSH configuration and an active SSH service.

## Verify

`verify.sh` requires the public hostname as its only positional argument; it
has no built-in destination:

```sh
SSH_KEY="${HOME}/.ssh/icpr_measurement" \
AWS_PROFILE="research" \
HTTP3_CURL="/path/to/http3-capable-curl" \
./server/verify.sh measurement.example.org
```

`SSH_USER` defaults to `ubuntu`. Verification performs live HTTP requests,
connects over SSH, reads the matching Terraform/AWS configuration, and writes
a verification manifest on the server. It checks:

- the Caddy and capture services;
- public TLS, HTTP-to-HTTPS redirection, HTTP/2, and HTTP/3;
- agreement between the probe response and the Caddy JSON record;
- a corresponding QUIC Initial in the packet capture;
- UTC time synchronization; and
- an SSH security-group rule restricted to the configured administrator
  `/32`.

An open UDP port alone is not accepted as HTTP/3 evidence.

## Endpoint and capture behaviour

`GET /healthz` returns a minimal health response. `GET /probe/<run_id>` accepts
1–128 characters from `[A-Za-z0-9._-]` and returns request metadata as JSON.
Other paths return 404, and unsupported methods on known paths return 405.
The endpoint records the direct peer address and does not trust forwarded
identity headers.

The capture service discovers the default-route interface and its primary
private IPv4 at startup. It records only inbound TCP/443 and UDP/443 traffic to
that address and the corresponding server replies. Capture files rotate hourly
in a 72-file ring.

## Outputs

The installed server writes:

| Path | Contents |
| --- | --- |
| `/var/log/icpr/caddy/access.jsonl` | Unsampled Caddy JSON access log |
| `/var/lib/icpr/pcap/` | Restricted hourly packet captures |
| `/var/lib/icpr/manifests/` | Time, installation, hash, and verification records |

Access logs rotate at midnight UTC or 100 MiB and are retained for 31 days by
the Caddy configuration. These files can contain client addresses, timestamps,
and other research evidence. Do not commit them to the source repository.

## Retention and specialised diagnostics

The optional tooling under `server/retention/` hashes and uploads only closed
logs and captures to encrypted, versioned object storage using the instance
role. Its pull script verifies a separate recovery copy under the ignored
`server/recovery-data/` directory. Follow
[`retention/README.md`](retention/README.md) before enabling it.

The temporary origin TCP gate used by the separate H3-required diagnostic is
documented in [`h3-required/README.md`](h3-required/README.md). It is not part
of normal server installation and must not be armed during offline validation.
