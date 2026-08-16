#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly REGION="eu-central-1"
TEMP_DIR=""
AWS_CLI_INSTALLER_SHA256="not-downloaded"

log() {
  printf '[icpr-retention-install] %s\n' "$*"
}

fail() {
  printf '[icpr-retention-install] ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  [[ -z ${TEMP_DIR} ]] || rm -rf -- "${TEMP_DIR}"
}

install_aws_cli() {
  if command -v aws >/dev/null 2>&1; then
    log "using existing AWS CLI installation"
    AWS_CLI_INSTALLER_SHA256="existing-installation"
    return
  fi

  [[ $(uname -m) == "x86_64" ]] || fail "AWS CLI installer expects x86_64"

  log "installing prerequisites for the official AWS CLI v2 bundle"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl unzip

  TEMP_DIR="$(mktemp -d)"
  curl --proto '=https' --tlsv1.2 --fail --location \
    https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip \
    --output "${TEMP_DIR}/awscliv2.zip"
  AWS_CLI_INSTALLER_SHA256="$(sha256sum "${TEMP_DIR}/awscliv2.zip" | awk '{print $1}')"
  unzip -q "${TEMP_DIR}/awscliv2.zip" -d "${TEMP_DIR}"
  "${TEMP_DIR}/aws/install" \
    --bin-dir /usr/local/bin \
    --install-dir /usr/local/aws-cli
  rm -rf -- "${TEMP_DIR}"
  TEMP_DIR=""

  command -v aws >/dev/null 2>&1 || fail "AWS CLI installation failed"
}

main() {
  [[ ${EUID} -eq 0 ]] || fail "run this script as root"
  [[ $# -eq 1 ]] || fail "usage: install.sh <measurement-data-bucket>"
  trap cleanup EXIT

  local bucket=$1
  [[ ${bucket} =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]] || \
    fail "invalid S3 bucket name"
  [[ -f /var/lib/icpr/manifests/verification.txt ]] || \
    fail "Day-0 verification manifest is missing"

  install_aws_cli

  log "validating retention scripts"
  bash -n \
    "${SCRIPT_DIR}/icpr-backup" \
    "${SCRIPT_DIR}/icpr-health-check"

  log "installing restricted retention configuration"
  install -d -o root -g root -m 0700 \
    /var/lib/icpr/backup-state \
    /var/lib/icpr/backup-state/tmp \
    /var/lib/icpr/backup-state/uploaded
  install -D -o root -g root -m 0750 \
    "${SCRIPT_DIR}/icpr-backup" /usr/local/libexec/icpr-backup
  install -D -o root -g root -m 0750 \
    "${SCRIPT_DIR}/icpr-health-check" /usr/local/libexec/icpr-health-check
  install -D -o root -g root -m 0644 \
    "${SCRIPT_DIR}/README.md" /opt/icpr/retention/README.md

  {
    printf 'AWS_REGION=%s\n' "${REGION}"
    printf 'ICPR_BACKUP_BUCKET=%s\n' "${bucket}"
    printf 'ICPR_BACKUP_PREFIX=endpoint\n'
    printf 'ICPR_BACKUP_STATE_DIR=/var/lib/icpr/backup-state\n'
    printf 'ICPR_LOCK_FILE=/run/icpr/backup.lock\n'
    printf 'ICPR_MIN_FREE_KIB=8388608\n'
    printf 'ICPR_MAX_BACKUP_AGE_SECONDS=108000\n'
  } | install -D -o root -g root -m 0640 /dev/stdin /etc/icpr/backup.env

  log "validating systemd units against installed executables"
  systemd-analyze verify \
    "${SCRIPT_DIR}/systemd/icpr-backup.service" \
    "${SCRIPT_DIR}/systemd/icpr-backup.timer" \
    "${SCRIPT_DIR}/systemd/icpr-health.service" \
    "${SCRIPT_DIR}/systemd/icpr-health.timer"

  install -o root -g root -m 0644 \
    "${SCRIPT_DIR}/systemd/icpr-backup.service" \
    /etc/systemd/system/icpr-backup.service
  install -o root -g root -m 0644 \
    "${SCRIPT_DIR}/systemd/icpr-backup.timer" \
    /etc/systemd/system/icpr-backup.timer
  install -o root -g root -m 0644 \
    "${SCRIPT_DIR}/systemd/icpr-health.service" \
    /etc/systemd/system/icpr-health.service
  install -o root -g root -m 0644 \
    "${SCRIPT_DIR}/systemd/icpr-health.timer" \
    /etc/systemd/system/icpr-health.timer

  if [[ -f /var/lib/icpr/backup-state/day0-verification.sha256 ]]; then
    sha256sum --check --status \
      /var/lib/icpr/backup-state/day0-verification.sha256 || \
      fail "Day-0 verification manifest differs from its recorded baseline"
  else
    sha256sum /var/lib/icpr/manifests/verification.txt \
      >/var/lib/icpr/backup-state/day0-verification.sha256
    chmod 0600 /var/lib/icpr/backup-state/day0-verification.sha256
  fi

  {
    printf 'installed_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'aws_cli_installer_sha256=%s\n' "${AWS_CLI_INSTALLER_SHA256}"
    aws --version 2>&1
    sha256sum \
      /usr/local/libexec/icpr-backup \
      /usr/local/libexec/icpr-health-check \
      /etc/systemd/system/icpr-backup.service \
      /etc/systemd/system/icpr-backup.timer \
      /etc/systemd/system/icpr-health.service \
      /etc/systemd/system/icpr-health.timer
  } | install -o root -g root -m 0640 /dev/stdin \
    /var/lib/icpr/manifests/retention-installation.txt

  systemctl daemon-reload
  systemctl enable --now icpr-backup.timer
  systemctl enable icpr-health.timer

  log "installation complete; run the first backup, then start icpr-health.timer"
}

main "$@"
