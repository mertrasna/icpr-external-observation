#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly MIN_FREE_KIB=$((20 * 1024 * 1024))
readonly CADDY_HOSTNAME_PLACEHOLDER="__ICPR_HOSTNAME__"
TEMP_DIR=""

log() {
  printf '[icpr-install] %s\n' "$*"
}

fail() {
  printf '[icpr-install] ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  [[ -z ${TEMP_DIR} ]] || rm -rf -- "${TEMP_DIR}"
}

usage() {
  cat <<'USAGE'
Usage: install.sh HOSTNAME

Install the controlled measurement endpoint for the given public DNS hostname.
HOSTNAME must be a lowercase, fully qualified DNS name such as
measurement.example.org.
USAGE
}

validate_hostname() {
  local hostname=$1
  local -a labels=()
  local label
  local final_label

  [[ -n ${hostname} ]] || fail "HOSTNAME must not be empty"
  ((${#hostname} <= 253)) || fail "HOSTNAME exceeds 253 characters"
  [[ ${hostname} == *.* ]] || fail "HOSTNAME must be a fully qualified DNS name"
  [[ ${hostname} =~ ^[a-z0-9.-]+$ ]] || \
    fail "HOSTNAME must contain only lowercase ASCII letters, digits, dots, and hyphens"
  [[ ${hostname} != .* && ${hostname} != *. && ${hostname} != *..* ]] || \
    fail "HOSTNAME has an empty DNS label"

  IFS='.' read -r -a labels <<<"${hostname}"
  ((${#labels[@]} >= 2)) || fail "HOSTNAME must contain at least two DNS labels"

  for label in "${labels[@]}"; do
    ((${#label} <= 63)) || fail "HOSTNAME contains a label longer than 63 characters"
    [[ ${label} =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || \
      fail "HOSTNAME contains an invalid DNS label"
  done

  final_label=${labels[${#labels[@]} - 1]}
  [[ ${final_label} =~ [a-z] ]] || \
    fail "HOSTNAME must end in a DNS label containing a letter"
}

render_caddy_configuration() {
  local hostname=$1
  local destination=$2
  local template_content
  local before_placeholder
  local after_placeholder

  validate_hostname "${hostname}"
  [[ ${destination} != "${SCRIPT_DIR}/Caddyfile" ]] || \
    fail "refusing to overwrite the Caddyfile template"

  template_content="$(<"${SCRIPT_DIR}/Caddyfile")"
  [[ ${template_content} == *"${CADDY_HOSTNAME_PLACEHOLDER}"* ]] || \
    fail "Caddyfile is missing the hostname placeholder"

  before_placeholder=${template_content%%"${CADDY_HOSTNAME_PLACEHOLDER}"*}
  after_placeholder=${template_content#*"${CADDY_HOSTNAME_PLACEHOLDER}"}
  [[ ${after_placeholder} != *"${CADDY_HOSTNAME_PLACEHOLDER}"* ]] || \
    fail "Caddyfile contains the hostname placeholder more than once"

  printf '%s%s%s\n' \
    "${before_placeholder}" "${hostname}" "${after_placeholder}" \
    >"${destination}"
}

require_root() {
  [[ ${EUID} -eq 0 ]] || fail "run this script as root"
}

preflight() {
  log "checking cloud-init, timezone, synchronization, and disk space"
  if ! cloud-init status --wait; then
    log "cloud-init retains the documented first-boot SSH reload error"
    /usr/sbin/sshd -t || fail "SSH configuration is invalid after recovery"
    systemctl is-active --quiet ssh.service || \
      fail "SSH service is not active after recovery"
  fi

  local timezone
  timezone="$(timedatectl show --property=Timezone --value)"
  [[ ${timezone} == "UTC" ]] || fail "system timezone is ${timezone}, not UTC"

  local synchronized
  synchronized="$(timedatectl show --property=NTPSynchronized --value)"
  [[ ${synchronized} == "yes" ]] || fail "time synchronization is not healthy"

  local free_kib
  free_kib="$(df -Pk / | awk 'NR == 2 {print $4}')"
  [[ ${free_kib} =~ ^[0-9]+$ ]] || fail "could not determine free disk space"
  ((free_kib >= MIN_FREE_KIB)) || fail "less than 20 GiB is free on /"
}

install_packages() {
  local temp_dir=$1

  log "installing official repository prerequisites"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    debian-archive-keyring \
    debian-keyring \
    gnupg \
    iproute2 \
    jq

  log "configuring the official signed Caddy stable repository"
  curl --proto '=https' --tlsv1.2 -fsSL \
    https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
    -o "${temp_dir}/caddy-stable.gpg.key"
  gpg --batch --yes --dearmor \
    --output "${temp_dir}/caddy-stable-archive-keyring.gpg" \
    "${temp_dir}/caddy-stable.gpg.key"
  install -o root -g root -m 0644 \
    "${temp_dir}/caddy-stable-archive-keyring.gpg" \
    /usr/share/keyrings/caddy-stable-archive-keyring.gpg

  curl --proto '=https' --tlsv1.2 -fsSL \
    https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
    -o "${temp_dir}/caddy-stable.list"
  install -o root -g root -m 0644 \
    "${temp_dir}/caddy-stable.list" \
    /etc/apt/sources.list.d/caddy-stable.list

  printf '%s\n' 'wireshark-common wireshark-common/install-setuid boolean false' | \
    debconf-set-selections
  apt-get update
  apt-get install -y caddy tshark
}

prepare_directories() {
  log "preparing restricted data and log directories"
  install -d -o root -g root -m 0750 /opt/icpr
  install -d -o root -g root -m 0750 /var/lib/icpr
  install -d -o root -g root -m 0700 /var/lib/icpr/pcap
  install -d -o root -g root -m 0750 /var/lib/icpr/manifests
  install -d -o root -g root -m 0711 /var/log/icpr
  install -d -o caddy -g caddy -m 0750 /var/log/icpr/caddy
  install -d -o caddy -g caddy -m 0750 /var/lib/caddy
}

record_time_sync() {
  local temp_dir=$1
  local record="${temp_dir}/time-sync-initial.txt"
  local service="none"

  if systemctl is-active --quiet chrony.service; then
    service="chrony.service"
  elif systemctl is-active --quiet systemd-timesyncd.service; then
    service="systemd-timesyncd.service"
  fi

  {
    printf 'recorded_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'active_sync_service=%s\n' "${service}"
    printf 'ntp_synchronized=%s\n' \
      "$(timedatectl show --property=NTPSynchronized --value)"
    printf '\n[timedatectl]\n'
    timedatectl
    printf '\n[current_utc]\n'
    date -u --iso-8601=ns

    if command -v chronyc >/dev/null 2>&1; then
      printf '\n[chronyc_tracking]\n'
      chronyc tracking || true
      printf '\n[chronyc_sources]\n'
      chronyc sources -v || true
    elif [[ ${service} == "systemd-timesyncd.service" ]]; then
      printf '\n[timesync_status]\n'
      timedatectl timesync-status || true
      printf '\n[timesync_properties]\n'
      timedatectl show-timesync --all || true
    else
      printf '\n[offset]\nunavailable: no supported active synchronization service found\n'
    fi
  } >"${record}"

  install -o root -g root -m 0640 \
    "${record}" /var/lib/icpr/manifests/time-sync-initial.txt
}

install_capture_helper() {
  local temp_dir=$1
  local helper="${temp_dir}/icpr-capture"

  cat >"${helper}" <<'CAPTURE_HELPER'
#!/usr/bin/env bash
set -Eeuo pipefail

interface="$(ip -4 route get 1.1.1.1 | awk 'NR == 1 {for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')"
[[ -n ${interface} ]] || { printf 'could not discover active interface\n' >&2; exit 1; }

private_ipv4="$(ip -4 -o address show dev "${interface}" scope global | awk 'NR == 1 {split($4, address, "/"); print address[1]}')"
[[ -n ${private_ipv4} ]] || { printf 'could not discover primary private IPv4\n' >&2; exit 1; }

capture_filter="((tcp dst port 443 and dst host ${private_ipv4}) or (tcp src port 443 and src host ${private_ipv4}) or (udp dst port 443 and dst host ${private_ipv4}) or (udp src port 443 and src host ${private_ipv4}))"

printf 'capturing interface=%s private_ipv4=%s filter=%s\n' \
  "${interface}" "${private_ipv4}" "${capture_filter}"

exec /usr/bin/dumpcap \
  -q \
  -i "${interface}" \
  -s 0 \
  -b duration:3600 \
  -b files:72 \
  -w /var/lib/icpr/pcap/icpr.pcapng \
  -f "${capture_filter}"
CAPTURE_HELPER

  install -D -o root -g root -m 0750 \
    "${helper}" /usr/local/libexec/icpr-capture
}

install_configuration() {
  local caddy_configuration=$1

  log "validating Caddy and systemd configurations"
  /usr/bin/caddy validate --config "${caddy_configuration}" --adapter caddyfile
  systemd-analyze verify "${SCRIPT_DIR}/systemd/icpr-capture.service"

  # Validation opens the configured log as root. Restore ownership before the
  # packaged service starts as the unprivileged caddy user.
  chown -R caddy:caddy /var/log/icpr/caddy
  if [[ -e /var/log/icpr/caddy/access.jsonl ]]; then
    chmod 0640 /var/log/icpr/caddy/access.jsonl
  fi

  install -o root -g caddy -m 0640 \
    "${caddy_configuration}" /etc/caddy/Caddyfile
  install -o root -g root -m 0644 \
    "${SCRIPT_DIR}/systemd/icpr-capture.service" \
    /etc/systemd/system/icpr-capture.service
  install -o root -g root -m 0644 \
    "${SCRIPT_DIR}/README.md" /opt/icpr/README.md

  systemctl daemon-reload
  systemctl enable caddy.service
  systemctl restart caddy.service
  systemctl enable --now icpr-capture.service
}

record_installation() {
  local temp_dir=$1
  local record="${temp_dir}/installation.txt"

  {
    printf 'installed_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'caddy_version=%s\n' "$(caddy version)"
    dpkg-query -W -f='package=${binary:Package} version=${Version}\n' \
      caddy tshark wireshark-common
    sha256sum \
      /etc/caddy/Caddyfile \
      /etc/systemd/system/icpr-capture.service \
      /usr/local/libexec/icpr-capture
  } >"${record}"

  install -o root -g root -m 0640 \
    "${record}" /var/lib/icpr/manifests/installation.txt
}

main() {
  if (($# == 1)) && [[ $1 == "-h" || $1 == "--help" ]]; then
    usage
    return 0
  fi
  (($# == 1)) || {
    usage >&2
    fail "expected exactly one HOSTNAME argument"
  }

  local hostname=$1
  local rendered_caddy
  validate_hostname "${hostname}"

  require_root
  preflight

  TEMP_DIR="$(mktemp -d)"
  trap cleanup EXIT
  rendered_caddy="${TEMP_DIR}/Caddyfile"
  render_caddy_configuration "${hostname}" "${rendered_caddy}"

  install_packages "${TEMP_DIR}"
  prepare_directories
  record_time_sync "${TEMP_DIR}"
  install_capture_helper "${TEMP_DIR}"
  install_configuration "${rendered_caddy}"
  record_installation "${TEMP_DIR}"

  log "installation complete; run server/verify.sh from an external HTTP/3-capable client"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
