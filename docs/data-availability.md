# Data availability and repository boundary

This methods repository distributes reusable code, parameterised examples,
synthetic test cases, and a small set of reviewed reference fixtures needed by
offline validation. It does not distribute study findings, generated result
tables or figures, or the original measurement evidence.

## Bring your own research data

Researchers using these methods collect and manage their own inputs. Depending
on the workflow, those inputs can include:

- dated Apple egress-catalogue CSV snapshots;
- routing databases and ASN-name mappings for the relevant dates;
- DNS-derived candidates and scanner output;
- client attempt metadata and packet captures;
- server request logs and closed captures; and
- frozen configurations, plans, sidecars, and evidence manifests.

The source tree provides the expected layouts and commands. It does not imply
permission to collect, redistribute, or publish any of these artifacts.

## Deliberately excluded

This repository deliberately omits:

- original campaign findings and result artifacts;
- raw and derived client/server evidence;
- same-day feed copies and study-specific input inventories;
- private ingress pins and researcher network details;
- credentials, Terraform state, recovery archives, and runtime files; and
- generated demo or analysis output.

The hash-pinned DNS/routing records and campaign-completion record required by
the protocol profile tests are synthetic method fixtures. They use reserved
addresses and replacement markers rather than observations from the original
study.

## Preparing your own data package

Keep research data outside Git or in a separately controlled package. A useful
package contains:

- a `MANIFEST.sha256` binding every included filename and digest;
- an inventory describing the role, source, collection time, and format of each
  file;
- the matching source revision and configuration/plan hashes;
- collection and analysis instructions; and
- any redaction, exclusion, access, retention, or licence conditions.

If a third-party source cannot be redistributed, provide a lawful fetch and
conversion recipe plus the expected digest instead of copying it into the
source repository.

## Third-party inputs

Apple catalogue data, RIPEstat/RIS records, RouteViews/CAIDA material, and
derived pyasn databases have separate provenance and potential redistribution
conditions. Record source URLs, retrieval dates, attribution, conversion
commands, and hashes. An open-source code licence does not grant rights over
those inputs.

## Verification

The generic manifest helper can verify researcher-supplied snapshot and routing
manifests:

```sh
python3 scripts/verify_data.py \
  --snapshot-manifest /path/to/snapshot_manifest.csv \
  --routing-manifest /path/to/MANIFEST.sha256
```

A missing file, unexpected size, hash mismatch, or malformed path should stop
analysis. Preserve the original inputs rather than replacing a mismatching file
with a newer download.
