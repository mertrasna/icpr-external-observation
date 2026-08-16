# How to use the helper scripts

## `verify_data.py`

Checks one or both researcher-supplied manifests without modifying their data:

```sh
python3 scripts/verify_data.py \
  --snapshot-manifest /path/to/snapshot_manifest.csv \
  --routing-manifest /path/to/MANIFEST.sha256
```

The snapshot CSV needs `path`, `bytes`, and `sha256` columns. A SHA-256 manifest
uses the common `<digest>  <relative-filename>` form. Exit status is `0` when
all supplied files match, `1` for a missing or mismatching file, and `2` for
invalid arguments or a malformed/unsafe manifest.

## `check_public_tree.py`

Checks that a repository tree contains the required methods and guides while
excluding known findings, results, private evidence, runtime state, and internal
paths:

```sh
python3 scripts/check_public_tree.py .
```

Run it from a clean checkout before publishing a release or changing repository
visibility. The checker examines ignored files too, so run it before `make
setup` creates `.venv`. A pass is a layout check, not a substitute for manual
privacy, licence, secret, and Git-history review.
