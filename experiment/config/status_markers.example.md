# Status-marker schemas

These are safe schemas, not claims that a gate has passed. Create a real marker in
`experiment/manifests/` only after every named check is true. Replace every angle-bracketed
placeholder with current evidence. Do not put IP addresses, credentials, keys, or raw runtime
evidence in a marker.

Every marker must have a filename-bound SHA-256 sidecar. For example:

```sh
(cd experiment/manifests && \
  shasum -a 256 synthetic-tests-v1.json > synthetic-tests-v1.json.sha256)
```

The sidecar's recorded filename must be only the basename. A marker is invalid after the
controller or selected configuration changes; recompute hashes only after rerunning the
underlying checks.

## `synthetic-tests-v1.json`

```json
{
  "schema_version": "v1",
  "document_type": "synthetic_tests",
  "status": "passed",
  "recorded_utc": "<UTC timestamp>",
  "controller_sha256": "<SHA-256 of experiment/controller.py>",
  "config_sha256": "<SHA-256 of experiment/config/experiment_config.yaml>",
  "checks": {
    "synthetic_suite_passed": true
  }
}
```

## `privileged-smoke-v1.json`

This marker is allowed only after separately approved live validation. It is not produced by
the non-invasive test suite.

```json
{
  "schema_version": "v1",
  "document_type": "privileged_smoke",
  "status": "passed",
  "recorded_utc": "<UTC timestamp>",
  "controller_sha256": "<SHA-256 of experiment/controller.py>",
  "config_sha256": "<SHA-256 of the frozen experiment configuration>",
  "checks": {
    "capture_start_stop": true,
    "dns_pin_restore": true,
    "targeted_pf_restore": true
  }
}
```

## `smoke-reconstruction-v1.json`

The checks summarize reconstruction of exactly five live runs: direct off, unpinned MGL,
Akamai-pinned MGL, AS714-pinned MGL, and unpinned CTZ.

```json
{
  "schema_version": "v1",
  "document_type": "smoke_reconstruction",
  "status": "passed",
  "recorded_utc": "<UTC timestamp>",
  "controller_sha256": "<SHA-256 of experiment/controller.py>",
  "config_sha256": "<SHA-256 of the frozen experiment configuration>",
  "checks": {
    "direct_off_control": true,
    "direct_off_http3_capability_recorded": true,
    "relay_on_unpinned": true,
    "inner_protocol_outcome_classified": true,
    "akamai_pinned": true,
    "targeted_outer_fallback_classified": true,
    "apple_as714_pinned": true,
    "both_location_settings": true,
    "hash_verified_reconstruction": true
  }
}
```

## `rehearsal-completion-v1.json`

The named execution-plan file must be a single basename in `experiment/manifests/`, must have
its own valid sidecar, and must hash to `execution_plan_sha256`.

```json
{
  "schema_version": "v1",
  "document_type": "rehearsal_completion",
  "status": "passed",
  "recorded_utc": "<UTC timestamp>",
  "controller_sha256": "<SHA-256 of experiment/controller.py>",
  "config_sha256": "<SHA-256 of the frozen experiment configuration>",
  "execution_plan_file": "rehearsal-plan-YYYY-MM-DD-morning-v1.json",
  "execution_plan_sha256": "<SHA-256 of the verified frozen execution plan>",
  "checks": {
    "six_hour_limit_observed": true,
    "all_attempts_accounted": true,
    "cleanup_verified": true,
    "hashes_verified": true
  }
}
```

## `final-campaign-freeze-v1.json`

`rehearsal_completion_sha256` must equal the hash of the verified
`rehearsal-completion-v1.json` marker. This marker belongs after rehearsal review and does not
authorize the controller to bypass G1-G4.

```json
{
  "schema_version": "v1",
  "document_type": "final_campaign_freeze",
  "status": "frozen",
  "recorded_utc": "<UTC timestamp>",
  "controller_sha256": "<SHA-256 of experiment/controller.py>",
  "config_sha256": "<SHA-256 of the frozen experiment configuration>",
  "rehearsal_completion_sha256": "<SHA-256 of rehearsal-completion-v1.json>",
  "checks": {
    "configuration_frozen": true,
    "script_hashes_frozen": true,
    "rehearsal_approved": true
  }
}
```
