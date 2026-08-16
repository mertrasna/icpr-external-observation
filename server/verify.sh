#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT

usage() {
  printf 'Usage: %s HOSTNAME\n' "${0##*/}"
  printf 'Verify an installed iCPR endpoint using its public DNS hostname.\n'
  printf 'Required environment: SSH_KEY and AWS_PROFILE.\n'
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 2
fi

readonly HOST="$1"
if [[ ! ${HOST} =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]; then
  printf '[icpr-verify] ERROR: HOSTNAME must be a DNS hostname without a scheme, port, or path\n' >&2
  exit 2
fi

readonly SSH_USER="${SSH_USER:-ubuntu}"
readonly SSH_KEY="${SSH_KEY:-}"
readonly AWS_PROFILE_NAME="${AWS_PROFILE:-}"
readonly HTTP3_CURL="${HTTP3_CURL:-curl}"
readonly REMOTE="${SSH_USER}@${HOST}"
TEMP_DIR=""
readonly -a SSH_OPTIONS=(
  -i "${SSH_KEY}"
  -o BatchMode=yes
  -o ConnectTimeout=15
  -o StrictHostKeyChecking=accept-new
)

log() {
  printf '[icpr-verify] %s\n' "$*"
}

fail() {
  printf '[icpr-verify] ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  [[ -z ${TEMP_DIR} ]] || rm -rf -- "${TEMP_DIR}"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

remote() {
  # Arguments are fixed commands or values validated before interpolation.
  # shellcheck disable=SC2029
  ssh "${SSH_OPTIONS[@]}" "${REMOTE}" "$@"
}

main() {
  local command
  [[ -n ${SSH_KEY} ]] || fail "set SSH_KEY to the endpoint SSH private key"
  [[ -n ${AWS_PROFILE_NAME} ]] || fail "set AWS_PROFILE to the reviewed AWS profile"
  for command in aws curl jq openssl ssh terraform; do
    require_command "${command}"
  done

  [[ -f ${SSH_KEY} ]] || fail "SSH key not found: ${SSH_KEY}"
  "${HTTP3_CURL}" --help all | grep -q -- '--http3-only' || \
    fail "${HTTP3_CURL} does not support --http3-only; set HTTP3_CURL to an HTTP/3-capable curl"

  TEMP_DIR="$(mktemp -d)"
  trap cleanup EXIT

  log "checking enabled and active services"
  remote 'systemctl is-enabled --quiet caddy.service && systemctl is-active --quiet caddy.service'
  remote 'systemctl is-enabled --quiet icpr-capture.service && systemctl is-active --quiet icpr-capture.service'

  log "checking publicly trusted TLS and hostname validation"
  openssl s_client \
    -connect "${HOST}:443" \
    -servername "${HOST}" \
    -verify_hostname "${HOST}" \
    -verify_return_error \
    </dev/null >"${TEMP_DIR}/tls.txt" 2>&1 || fail "TLS trust or hostname validation failed"
  grep -q 'Verify return code: 0 (ok)' "${TEMP_DIR}/tls.txt" || fail "TLS chain is not publicly trusted"

  log "checking HTTP-to-HTTPS redirection"
  local redirect_code
  redirect_code="$(curl --silent --show-error \
    --output /dev/null \
    --dump-header "${TEMP_DIR}/redirect-headers.txt" \
    --write-out '%{http_code}' \
    "http://${HOST}/healthz")"
  [[ ${redirect_code} == "308" ]] || fail "HTTP redirect returned ${redirect_code}, expected 308"
  grep -Eiq "^location: https://${HOST}/healthz" "${TEMP_DIR}/redirect-headers.txt" || \
    fail "HTTP redirect location is incorrect"

  log "checking HTTP/2"
  local http2_version
  http2_version="$(curl --http2 --fail --silent --show-error \
    --output /dev/null --write-out '%{http_version}' \
    "https://${HOST}/healthz")"
  [[ ${http2_version} == "2" ]] || fail "HTTP/2 request negotiated ${http2_version}"

  local run_id
  run_id="test-$(date -u +%Y%m%dT%H%M%SZ)"
  log "performing required external HTTP/3 probe ${run_id}"
  local http3_version
  http3_version="$("${HTTP3_CURL}" --http3-only --fail --silent --show-error \
    --dump-header "${TEMP_DIR}/http3-headers.txt" \
    --output "${TEMP_DIR}/probe.json" \
    --write-out '%{http_version}' \
    "https://${HOST}/probe/${run_id}")"
  [[ ${http3_version} == "3" ]] || fail "HTTP/3 request negotiated ${http3_version}"
  grep -Eiq '^alt-svc:.*h3' "${TEMP_DIR}/http3-headers.txt" || fail "Alt-Svc does not advertise HTTP/3"
  jq -e --arg run_id "${run_id}" '.run_id == $run_id and (.request_uuid | type == "string")' \
    "${TEMP_DIR}/probe.json" >/dev/null || fail "probe response JSON is invalid"

  local request_uuid remote_ip remote_port response_protocol
  request_uuid="$(jq -r '.request_uuid' "${TEMP_DIR}/probe.json")"
  remote_ip="$(jq -r '.remote_ip' "${TEMP_DIR}/probe.json")"
  remote_port="$(jq -r '.remote_port' "${TEMP_DIR}/probe.json")"
  response_protocol="$(jq -r '.http_protocol' "${TEMP_DIR}/probe.json")"
  [[ ${request_uuid} =~ ^[0-9a-fA-F-]{16,64}$ ]] || fail "request UUID has an unexpected format"
  [[ ${remote_ip} =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || fail "remote IP is not IPv4"
  if [[ ! ${remote_port} =~ ^[0-9]+$ ]] || \
    ((remote_port < 1 || remote_port > 65535)); then
    fail "remote port is invalid"
  fi
  [[ ${response_protocol} == HTTP/3* ]] || fail "probe response did not report HTTP/3"

  log "matching the request UUID and direct remote IP in Caddy JSON logs"
  remote sudo tail -n 1000 /var/log/icpr/caddy/access.jsonl >"${TEMP_DIR}/access-tail.jsonl"
  jq -c --arg uuid "${request_uuid}" 'select(.request_uuid == $uuid)' \
    "${TEMP_DIR}/access-tail.jsonl" | tail -n 1 >"${TEMP_DIR}/access-entry.json"
  [[ -s ${TEMP_DIR}/access-entry.json ]] || fail "request UUID was not found in the Caddy access log"
  jq -e --arg ip "${remote_ip}" --arg port "${remote_port}" \
    '.request.remote_ip == $ip and .request.remote_port == $port and (.request.proto | startswith("HTTP/3"))' \
    "${TEMP_DIR}/access-entry.json" >/dev/null || \
    fail "Caddy log direct IP or protocol does not match the response"

  log "checking for the corresponding QUIC Initial in the capture ring"
  sleep 2
  local pcap_file
  pcap_file="$(remote "sudo find /var/lib/icpr/pcap -maxdepth 1 -type f -name '*.pcapng' -printf '%T@ %p\\n' | sort -nr | head -n 1 | cut -d' ' -f2-")"
  [[ -n ${pcap_file} ]] || fail "no pcapng file was found"
  remote "sudo tshark -r '${pcap_file}' -Y 'ip.src == ${remote_ip} && udp.srcport == ${remote_port} && udp.dstport == 443 && quic.long.packet_type == 0'" \
    >"${TEMP_DIR}/capture-evidence.txt"
  [[ -s ${TEMP_DIR}/capture-evidence.txt ]] || fail "no corresponding QUIC Initial was found"

  log "checking time synchronization"
  [[ $(remote 'timedatectl show --property=Timezone --value') == "UTC" ]] || fail "server timezone is not UTC"
  [[ $(remote 'timedatectl show --property=NTPSynchronized --value') == "yes" ]] || fail "server time is not synchronized"

  log "checking that SSH remains restricted to the configured administrator /32"
  local security_group_id admin_cidr ssh_rules
  security_group_id="$(AWS_PROFILE="${AWS_PROFILE_NAME}" terraform -chdir="${REPO_ROOT}/infra/endpoint" output -raw security_group_id)"
  admin_cidr="$(AWS_PROFILE="${AWS_PROFILE_NAME}" terraform -chdir="${REPO_ROOT}/infra/endpoint" output -raw ssh_admin_cidr)"
  ssh_rules="$(AWS_PROFILE="${AWS_PROFILE_NAME}" aws ec2 describe-security-group-rules \
    --filters "Name=group-id,Values=${security_group_id}" --output json | \
    jq --arg cidr "${admin_cidr}" '[.SecurityGroupRules[] | select(.IsEgress == false and .IpProtocol == "tcp" and .FromPort == 22 and .ToPort == 22)]')"
  [[ $(jq 'length' <<<"${ssh_rules}") -eq 1 ]] || fail "expected exactly one SSH ingress rule"
  jq -e --arg cidr "${admin_cidr}" \
    '.[0].CidrIpv4 == $cidr and .[0].CidrIpv4 != "0.0.0.0/0"' \
    <<<"${ssh_rules}" >/dev/null || fail "SSH ingress is not restricted to ${admin_cidr}"

  log "recording versions, hashes, and verification UTC time"
  local verification_utc
  verification_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  {
    printf 'verification_utc=%s\n' "${verification_utc}"
    printf 'run_id=%s\n' "${run_id}"
    printf 'request_uuid=%s\n' "${request_uuid}"
    printf 'external_http3=verified\n'
    printf 'direct_remote_ip=%s\n' "${remote_ip}"
    printf 'direct_remote_port=%s\n' "${remote_port}"
    # dpkg expands these package-format placeholders on the remote host.
    # shellcheck disable=SC2016
    remote 'caddy version; dpkg-query -W -f="package=${binary:Package} version=${Version}\\n" caddy tshark wireshark-common'
    remote 'sudo sha256sum /etc/caddy/Caddyfile /etc/systemd/system/icpr-capture.service /usr/local/libexec/icpr-capture'
  } >"${TEMP_DIR}/verification.txt"
  remote sudo install -o root -g root -m 0640 /dev/stdin \
    /var/lib/icpr/manifests/verification.txt <"${TEMP_DIR}/verification.txt"

  log "all required post-install checks passed at ${verification_utc}"
}

main "$@"
