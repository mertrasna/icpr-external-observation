# Evidence retention and recovery

This optional package hashes and uploads closed Caddy logs, closed packet
captures, and immutable manifests once per day. It never uploads the active log
or currently open capture and never deletes source evidence.

## Before installation

Deploy the endpoint Terraform stack first and obtain its
`measurement_data_bucket_name` output. Review the scripts and confirm that the
server uses the expected instance role. Installation changes systemd services
and may download AWS CLI v2, so it is a live, approval-gated operation.

## Install

Use your own hostname, SSH key, and AWS profile:

```sh
BUCKET="$(AWS_PROFILE=research terraform -chdir=infra/endpoint \
  output -raw measurement_data_bucket_name)"
scp -i ~/.ssh/icpr_measurement -r server/retention \
  ubuntu@measurement.example.org:/tmp/icpr-retention
ssh -i ~/.ssh/icpr_measurement ubuntu@measurement.example.org \
  "sudo /tmp/icpr-retention/install.sh '${BUCKET}'"
```

No AWS access key is copied to the server. The uploader uses the EC2 instance
profile through IMDSv2 and writes content-addressed objects plus adjacent
SHA-256 sidecars beneath `endpoint/archive/`.

## Operation and recovery

`icpr-backup.timer` runs daily at about 02:15 UTC and catches up after downtime.
`icpr-health.timer` checks services, UTC/NTP state, disk space, backup age, the
verification-manifest hash, and the expected instance role.

After the first successful backup, create a verified local recovery copy:

```sh
AWS_PROFILE=research ./server/retention/pull-to-mac.sh
```

The pull writes beneath ignored `server/recovery-data/`, verifies every
sidecar, and builds dated TSV indexes without duplicating evidence. Raw logs
and captures may contain client identifiers; keep them out of the source
repository and follow the privacy/data-release guidance.
