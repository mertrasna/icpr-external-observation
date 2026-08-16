# Maintainer release checklist

Run these checks before publishing a release or changing repository visibility.

## Ownership and metadata

- Confirm code ownership and that `LICENSE` contains the approved terms.
- Update `CITATION.cff` with the author, optional ORCID, repository URL, and
  release version.
- Review third-party dependency and research-input attribution.
- Review Git author names, email addresses, history, and retained metadata.

## Methods-only boundary

- Keep findings, result artifacts, generated tables and figures, and
  study-specific input inventories out of the repository.
- Keep packet captures, request and response files, server logs, private pins,
  recovery archives, Terraform state, cloud variables, SSH material, and
  operator notes out of the repository.
- Include only synthetic examples and the smallest reviewed reference fixtures
  required for offline tests.
- Confirm that retained hostnames, IP addresses, locations, and timestamps are
  intentional and safe.

## Automated checks

From a clean checkout, run the tree check before setup creates local tooling
files:

```sh
make check-public-tree
make setup
make test
make demo-egress
```

Inspect tracked files and Git history for credentials, private paths, and
research evidence. Do not run the live controller, scanner, deployment,
pairing rebuild, or protocol diagnostic as a routine release check.

## Usability check

Ask a researcher unfamiliar with the project to follow the root quick start and
one folder HOW-TO. They should be able to run the offline checks, understand the
required inputs, see where local outputs go, and identify which commands require
an approved live environment.
