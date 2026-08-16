#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT
readonly AWS_PROFILE_NAME="${AWS_PROFILE:-}"
readonly REGION="eu-central-1"

fail() {
  printf '[icpr-pull] ERROR: %s\n' "$*" >&2
  exit 1
}

artifact_utc_day() {
  local artifact=$1
  local category=$2
  local filename day
  filename="$(basename -- "${artifact}")"

  if [[ ${category} == "pcaps" && \
    ${filename} =~ _([0-9]{4})([0-9]{2})([0-9]{2})[0-9]{6}\.pcapng$ ]]; then
    printf '%s-%s-%s\n' \
      "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
    return
  fi

  if [[ ${category} == "caddy-logs" ]]; then
    if [[ ${filename} == *.gz ]]; then
      day="$(
        gzip -cd -- "${artifact}" 2>/dev/null |
          jq -nr 'first(inputs | select(.ts? != null) | (.ts | floor | strftime("%Y-%m-%d")))' || true
      )"
    else
      day="$(
        jq -nr 'first(inputs | select(.ts? != null) | (.ts | floor | strftime("%Y-%m-%d")))' \
          "${artifact}" 2>/dev/null || true
      )"
    fi
    if [[ ${day} =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
      printf '%s\n' "${day}"
      return
    fi

    if [[ ${filename} =~ ([0-9]{4})-([0-9]{2})-([0-9]{2}) ]]; then
      printf '%s-%s-%s\n' \
        "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
      return
    fi
    if [[ ${filename} =~ ([0-9]{4})([0-9]{2})([0-9]{2})T ]]; then
      printf '%s-%s-%s\n' \
        "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
      return
    fi
  fi

  if [[ ${category} == "manifests" ]]; then
    day="$(LC_ALL=C grep -Eom1 '[0-9]{4}-[0-9]{2}-[0-9]{2}' "${artifact}" || true)"
    if [[ -n ${day} ]]; then
      printf '%s\n' "${day}"
      return
    fi
  fi

  TZ=UTC stat -f '%Sm' -t '%Y-%m-%d' "${artifact}"
}

build_daily_indexes() {
  local destination=$1
  local sidecar artifact relative category expected day index count
  local index_dir="${destination}/daily-index"

  mkdir -p "${index_dir}"
  rm -f -- "${index_dir}/"*.tsv

  while IFS= read -r -d '' sidecar; do
    artifact=${sidecar%.sha256}
    relative=${artifact#"${destination}/archive/"}
    category=${relative%%/*}
    expected="$(awk 'NR == 1 {print $1}' "${sidecar}")"
    day="$(artifact_utc_day "${artifact}" "${category}")"
    [[ ${day} =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || \
      fail "could not determine UTC day for ${artifact}"
    printf '%s\t%s\tarchive/%s\n' "${expected}" "${category}" "${relative}" \
      >>"${index_dir}/${day}.tsv"
  done < <(find "${destination}/archive" -type f -name '*.sha256' -print0)

  for index in "${index_dir}/"*.tsv; do
    [[ -e ${index} ]] || continue
    sort -u -o "${index}" "${index}"
    count="$(wc -l <"${index}" | tr -d ' ')"
    printf '[icpr-pull] daily index %s: %s artifacts\n' \
      "$(basename "${index}" .tsv)" "${count}"
  done
}

main() {
  [[ -n ${AWS_PROFILE_NAME} ]] || fail "set AWS_PROFILE to the reviewed AWS profile"
  command -v aws >/dev/null 2>&1 || fail "AWS CLI is required"
  command -v gzip >/dev/null 2>&1 || fail "gzip is required"
  command -v jq >/dev/null 2>&1 || fail "jq is required"
  command -v shasum >/dev/null 2>&1 || fail "shasum is required"

  local bucket=${1:-}
  local destination=${2:-"${REPO_ROOT}/server/recovery-data"}

  if [[ -z ${bucket} ]]; then
    command -v terraform >/dev/null 2>&1 || fail "Terraform is required to discover the bucket"
    bucket="$(AWS_PROFILE="${AWS_PROFILE_NAME}" \
      terraform -chdir="${REPO_ROOT}/infra/endpoint" \
      output -raw measurement_data_bucket_name)"
  fi

  mkdir -p "${destination}/archive"
  printf '[icpr-pull] downloading s3://%s/endpoint/archive/ to %s\n' \
    "${bucket}" "${destination}/archive"
  AWS_PROFILE="${AWS_PROFILE_NAME}" aws s3 sync \
    "s3://${bucket}/endpoint/archive/" \
    "${destination}/archive/" \
    --region "${REGION}" \
    --only-show-errors

  local sidecar artifact expected actual verified=0
  while IFS= read -r -d '' sidecar; do
    artifact=${sidecar%.sha256}
    [[ -f ${artifact} ]] || fail "artifact missing for ${sidecar}"
    expected="$(awk 'NR == 1 {print $1}' "${sidecar}")"
    actual="$(shasum -a 256 "${artifact}" | awk '{print $1}')"
    [[ ${actual} == "${expected}" ]] || fail "hash mismatch: ${artifact}"
    printf '[icpr-pull] verified %s\n' "${artifact#"${destination}/"}"
    verified=$((verified + 1))
  done < <(find "${destination}/archive" -type f -name '*.sha256' -print0)

  ((verified > 0)) || fail "no SHA-256 sidecars were downloaded"
  build_daily_indexes "${destination}"
  printf 'pulled_utc=%s\nverified_artifacts=%d\nbucket=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${verified}" "${bucket}" \
    >"${destination}/last-pull.txt"
  printf '[icpr-pull] verified %d artifacts\n' "${verified}"
}

main "$@"
