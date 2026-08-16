# How to use the controlled server

## Purpose

This folder configures the Ubuntu measurement endpoint, Caddy HTTP/1.1–HTTP/3
probe routes, packet capture, and evidence retention. The checked-in Caddyfile
is a template; installation renders it for an explicitly supplied hostname.

## Choose a task

| Goal | Network or privileged access? | Command |
| --- | --- | --- |
| Check shell syntax | No | `bash -n server/install.sh server/verify.sh server/retention/*.sh` |
| Test hostname rendering | No | `python3 -m unittest discover -s server/tests -p 'test_*.py'` |
| Review the HTTP endpoint | No | Read `server/Caddyfile` |
| Install the endpoint | Yes; root on Ubuntu | `sudo server/install.sh HOSTNAME` |
| Verify HTTP/3 and capture | Yes; AWS and SSH | `./server/verify.sh HOSTNAME` |

## Requirements

- Ubuntu 24.04 server with UTC time synchronization and at least 20 GiB free.
- A DNS name pointing at the instance.
- Restricted SSH access, an SSH key, AWS CLI/profile, Terraform state, and an
  HTTP/3-capable curl for full verification.

## Configuration to review

- Leave `__ICPR_HOSTNAME__` unchanged in `Caddyfile` and pass a lowercase,
  fully qualified hostname to `server/install.sh`.
- Pass the hostname explicitly to `server/verify.sh`.
- Set `SSH_USER`, `SSH_KEY`, `AWS_PROFILE`, and `HTTP3_CURL` as needed.
- Review retention bucket/prefix settings before installing retention jobs.

## Outputs

The server writes Caddy JSON logs under `/var/log/icpr/caddy/`, packet captures
under `/var/lib/icpr/pcap/`, and installation/verification manifests under
`/var/lib/icpr/manifests/`. These contain research evidence and must not be
committed to the source repository.

Installation changes packages, systemd services, and system configuration.
Read the detailed README and retention README before any live operation.
