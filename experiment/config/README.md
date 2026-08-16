# Configure a new study

`experiment_config.example.yaml` is a neutral, JSON-compatible YAML template.
It uses `example.org`, RFC1918/documentation values, private example ASNs, and a
`template` status. It is intentionally not launch-ready.

Create the ignored working file:

```bash
cp experiment/config/experiment_config.example.yaml \
  experiment/config/experiment_config.yaml
```

Review every section; do not search-and-replace only the endpoint. In
particular:

1. Set a researcher-controlled FQDN, the exact
   `https://HOST/probe/{run_id}` URL, and the endpoint's private IPv4 address.
2. Declare the true country/time zone and an explicit general-location
   boundary appropriate to the client location.
3. Freeze observation blocks, alternation anchor, retry ceiling and the
   freshness method supported by a pilot.
4. Record actual client, server and tool versions.
5. Select dated Apple-feed, routing, and operator-map inputs without viewing
   outcomes first.
6. Replace every `REPLACE_`, `RECORD_`, `example.org`, `ZZ`, example city, and
   private example ASN value.
7. Set `configuration_status` to `frozen` only after review.

The controller validates structural and methodological invariants, but it
cannot decide whether a hostname, geographic boundary, schedule, or approval
is scientifically appropriate for your research question.

## Private ingress pins

Create `ingress_pins.yaml` from `ingress_pins.example.yaml`. Populate only
manually reviewed IPv4 addresses in the declared groups, set a version and UTC
verification time, and make the groups non-overlapping. Then create a
filename-bound sidecar:

```bash
(cd experiment/config && \
  shasum -a 256 ingress_pins.yaml > ingress_pins.yaml.sha256)
```

The local configuration, pins, and sidecars are ignored by Git. Do not place
credentials, the researcher's public IP, or unrelated capture targets in them.

## Gate markers

`status_markers.example.md` contains marker schemas. A marker is created only
after every named check actually passed, must bind to the selected config and
controller hashes, and becomes stale when either changes.
