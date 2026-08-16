#!/usr/bin/env python3
"""Check a methods-only iCPR repository tree without modifying it."""

from __future__ import annotations

import argparse
import fnmatch
import os
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


REQUIRED_FILES = {
    "README.md": "top-level project introduction",
    "LICENSE": "code licence approved by the owner",
    "CITATION.cff": "public citation metadata",
    "CONTRIBUTING.md": "contribution guidance",
    "SECURITY.md": "private security-reporting guidance",
    "THIRD_PARTY_NOTICES.md": "dependency and research-input notices",
    "Makefile": "common setup, test, demo, and own-data analysis commands",
    "requirements.txt": "pinned Python environment",
    ".github/workflows/tests.yml": "offline continuous-integration workflow",
    "experiment/config/experiment_config.example.yaml": (
        "neutral experiment configuration template"
    ),
    "protocol-diagnostic/examples/dual-protocol-config.json": (
        "neutral dual-protocol configuration"
    ),
    "protocol-diagnostic/examples/dual-protocol-config.json.sha256": (
        "dual-protocol configuration digest"
    ),
    "protocol-diagnostic/examples/dual-protocol-plan.json": (
        "neutral dual-protocol plan"
    ),
    "protocol-diagnostic/examples/dual-protocol-plan.json.sha256": (
        "dual-protocol plan digest"
    ),
    "protocol-diagnostic/examples/h3-required-config.json": (
        "neutral HTTP/3-required configuration"
    ),
    "protocol-diagnostic/examples/h3-required-config.json.sha256": (
        "HTTP/3-required configuration digest"
    ),
    "protocol-diagnostic/examples/h3-required-plan.json": (
        "neutral HTTP/3-required plan"
    ),
    "protocol-diagnostic/examples/h3-required-plan.json.sha256": (
        "HTTP/3-required plan digest"
    ),
}

REQUIRED_FOLDER_GUIDES = (
    "docs/README.md",
    "ecs-scanner/README.md",
    "egress-catalog-analysis/README.md",
    "egress-catalog-analysis/data/README.md",
    "experiment/README.md",
    "experiment/config/README.md",
    "experiment/reference/asn/README.md",
    "infra/README.md",
    "infra/bootstrap-state/README.md",
    "infra/endpoint/README.md",
    "protocol-diagnostic/README.md",
    "protocol-diagnostic/h3-required/README.md",
    "results/README.md",
    "results/egress-catalogue/README.md",
    "scripts/README.md",
    "server/README.md",
    "server/h3-required/README.md",
    "server/retention/README.md",
)

# These directories are working state, tooling state, or internal notes. They
# should not occur anywhere in the checked repository tree. `.git` is skipped
# separately because the checker is expected to run inside a new Git checkout.
FORBIDDEN_DIRECTORY_NAMES = {
    ".agents",
    ".cache",
    ".claude",
    ".codex",
    ".mypy_cache",
    ".pytest_cache",
    ".superpowers",
    ".terraform",
    ".venv",
    "__pycache__",
}

FORBIDDEN_EXACT_DIRECTORIES = {
    PurePosixPath("docs/superpowers"),
    PurePosixPath("ecs-scanner/prototypes"),
    PurePosixPath("egress_snapshots"),
    PurePosixPath("server/recovery-data"),
    PurePosixPath("protocol-diagnostic/h3-response-probe"),
    PurePosixPath("protocol-diagnostic/config"),
    PurePosixPath("protocol-diagnostic/local"),
    PurePosixPath("protocol-diagnostic/manifests"),
    PurePosixPath("protocol-diagnostic/reference"),
    PurePosixPath("protocol-diagnostic/h3-required/config"),
    PurePosixPath("protocol-diagnostic/h3-required/manifests"),
    PurePosixPath("results/egress-catalogue/demo"),
    PurePosixPath("results/egress-catalogue/generated"),
}

# These are valid runtime or evidence locations in the source layout, so an
# empty placeholder is allowed. Any other file beneath them requires deliberate
# privacy review and belongs outside the source repository by default. Campaign
# execution manifests are protected here. Reusable protocol profiles live
# under protocol-diagnostic/examples; frozen study profiles are forbidden.
PROTECTED_DATA_DIRECTORIES = {
    PurePosixPath("ecs-scanner/full_results"),
    PurePosixPath("ecs-scanner/validation_results"),
    PurePosixPath("ecs-scanner/validation_streaming_results"),
    PurePosixPath("egress-catalog-analysis/data"),
    PurePosixPath("egress-catalog-analysis/snapshots"),
    PurePosixPath("experiment/client"),
    PurePosixPath("experiment/derived"),
    PurePosixPath("experiment/feeds"),
    PurePosixPath("experiment/manifests"),
    PurePosixPath("experiment/reports"),
    PurePosixPath("experiment/runtime"),
    PurePosixPath("experiment/server"),
    PurePosixPath("experiment/reference/asn"),
    PurePosixPath("protocol-diagnostic/client"),
    PurePosixPath("protocol-diagnostic/derived"),
    PurePosixPath("protocol-diagnostic/reports"),
    PurePosixPath("protocol-diagnostic/runtime"),
    PurePosixPath("protocol-diagnostic/server"),
    PurePosixPath("protocol-diagnostic/h3-required/client"),
    PurePosixPath("protocol-diagnostic/h3-required/derived"),
    PurePosixPath("protocol-diagnostic/h3-required/reports"),
    PurePosixPath("protocol-diagnostic/h3-required/runtime"),
    PurePosixPath("protocol-diagnostic/h3-required/server"),
    PurePosixPath("protocol-diagnostic/h3-required/reference"),
    PurePosixPath("results"),
}

ALLOWED_PLACEHOLDERS = {".gitignore", ".gitkeep", "README.md"}

# A campaign manifest can disclose frozen execution details even when it has a
# generic manifest filename. Keep only source-layout placeholders in this one
# protected directory.
PROTECTED_PLACEHOLDERS = {
    PurePosixPath("experiment/manifests"): {".gitignore", ".gitkeep", "README.md"},
    PurePosixPath("results"): {"README.md", "HOW_TO_USE.md"},
}

ALLOWED_PROTECTED_FILES = {
    PurePosixPath("experiment/reference/asn"): {
        PurePosixPath("apply_historical_bgp_reconstruction.py"),
        PurePosixPath("operator_map.example.csv"),
        PurePosixPath("origin_prefixes.example.csv"),
    },
}

FORBIDDEN_FILE_NAMES = {
    ".DS_Store",
    "AGENTS.md",
    "HANDOFF.md",
    "OPERATOR_RUNBOOK.md",
    "OPERATOR_RUNBOOK_V1.md",
    "backend.hcl",
    "dissertation-methodology-draft.txt",
    "implementation-status-and-remaining-work.txt",
    "experiment_configuration_v1.md",
    "FALLBACK_PIN_NOTE.md",
    "FINDINGS.md",
    "terraform.tfvars",
    "tfplan",
    "verify_results.py",
}

FORBIDDEN_FILE_PATTERNS = (
    "*.key",
    "*.log",
    "*.pcap",
    "*.pcapng",
    "*.pem",
    "*.stderr",
    "*.stdout",
    "*.tfplan",
    "*.tfstate",
    "*.tfstate.*",
    "response.json",
    "response.json.sha256",
)

FORBIDDEN_PROJECT_PATTERNS = (
    "ecs-scanner/ecs_sources.txt",
    "ecs-scanner/routeviews-*.pfx2as.gz",
    "egress-catalog-analysis/bgp_series.csv",
    "egress-catalog-analysis/catalogue_changes.csv",
    "egress-catalog-analysis/catalogue_churn_timeline.*",
    "egress-catalog-analysis/churn.pdf",
    "egress-catalog-analysis/churn_series.csv",
    "egress-catalog-analysis/churn_transitions.csv",
    "egress-catalog-analysis/country_series.csv",
    "egress-catalog-analysis/data/MANIFEST.sha256",
    "egress-catalog-analysis/operator_series.csv",
    "egress-catalog-analysis/snapshot_manifest.csv",
    "egress-catalog-analysis/snapshot_series.csv",
    "protocol-diagnostic/egress-*.csv",
    "protocol-diagnostic/h3-response-probe-diag",
    "protocol-diagnostic/tests/test_h3_response_probe.py",
)


@dataclass(frozen=True, order=True)
class Finding:
    category: str
    path: str
    detail: str


def relative_path(root: Path, value: Path) -> PurePosixPath:
    return PurePosixPath(value.relative_to(root).as_posix())


def protected_contents(
    path: Path, protected_path: PurePosixPath
) -> list[PurePosixPath]:
    """Return non-placeholder files below one protected data directory."""
    if not path.exists():
        return []
    if not path.is_dir():
        return [PurePosixPath(path.name)]

    found: list[PurePosixPath] = []
    allowed_placeholders = PROTECTED_PLACEHOLDERS.get(
        protected_path, ALLOWED_PLACEHOLDERS
    )
    for current, directories, files in os.walk(path, followlinks=False):
        directories[:] = sorted(
            name for name in directories if name not in {".git", "__pycache__"}
        )
        current_path = Path(current)
        for name in sorted(files):
            relative = relative_path(path, current_path / name)
            if (
                name not in allowed_placeholders
                and relative not in ALLOWED_PROTECTED_FILES.get(protected_path, set())
            ):
                found.append(relative)
    return found


def summarize_protected(path: PurePosixPath, files: list[PurePosixPath]) -> Finding:
    samples = ", ".join(str(item) for item in files[:3])
    if len(files) > 3:
        samples += f", and {len(files) - 3} more"
    return Finding(
        "protected data",
        str(path),
        f"contains {len(files)} non-placeholder file(s): {samples}",
    )


def check_required_files(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for name, purpose in REQUIRED_FILES.items():
        if not (root / name).is_file():
            detail = f"missing {purpose}"
            if name == "LICENSE":
                detail += "; choose it only after code ownership is confirmed"
            elif name == "CITATION.cff":
                detail += "; add final author, repository, and release metadata"
            findings.append(Finding("missing essential", name, detail))
    for name in REQUIRED_FOLDER_GUIDES:
        if not (root / name).is_file():
            findings.append(
                Finding("missing guide", name, "functional folder needs a plain README")
            )
    return findings


def file_name_is_forbidden(name: str) -> bool:
    return name in FORBIDDEN_FILE_NAMES or any(
        fnmatch.fnmatchcase(name, pattern) for pattern in FORBIDDEN_FILE_PATTERNS
    )


def project_path_is_forbidden(path: PurePosixPath) -> bool:
    text = str(path)
    return any(fnmatch.fnmatchcase(text, pattern) for pattern in FORBIDDEN_PROJECT_PATTERNS)


def check_tree(root: Path) -> list[Finding]:
    findings = check_required_files(root)
    protected = set(PROTECTED_DATA_DIRECTORIES)

    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        current_relative = relative_path(root, current_path)
        kept_directories: list[str] = []

        for name in sorted(directories):
            child = current_path / name
            child_relative = (
                PurePosixPath(name)
                if str(current_relative) == "."
                else current_relative / name
            )

            if name == ".git":
                continue
            if name in FORBIDDEN_DIRECTORY_NAMES:
                findings.append(
                    Finding(
                        "internal/runtime directory",
                        str(child_relative),
                        "must not be included in the public source tree",
                    )
                )
                continue
            if child_relative in FORBIDDEN_EXACT_DIRECTORIES:
                findings.append(
                    Finding(
                        "private directory",
                        str(child_relative),
                        "must not be included in the public source tree",
                    )
                )
                continue
            if child_relative in protected:
                contents = protected_contents(child, child_relative)
                if contents:
                    findings.append(summarize_protected(child_relative, contents))
                continue
            kept_directories.append(name)

        directories[:] = kept_directories

        for name in sorted(files):
            path = current_path / name
            path_relative = (
                PurePosixPath(name)
                if str(current_relative) == "."
                else current_relative / name
            )
            if file_name_is_forbidden(name):
                findings.append(
                    Finding(
                        "private/internal file",
                        str(path_relative),
                        "name matches a known non-public artifact",
                    )
                )
            elif project_path_is_forbidden(path_relative):
                findings.append(
                    Finding(
                        "downloaded/generated input",
                        str(path_relative),
                        "belongs in a separately reviewed data package",
                    )
                )

    return sorted(set(findings))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        type=Path,
        help="repository tree to inspect (default: current directory)",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    root = args.path.expanduser().resolve()
    if not root.is_dir():
        print(f"public-tree check error: not a directory: {root}", file=sys.stderr)
        return 2

    findings = check_tree(root)
    print(f"Public-tree check: {root}")
    if findings:
        print(f"FAIL: {len(findings)} repository issue(s) found")
        for finding in findings:
            print(f"- [{finding.category}] {finding.path}: {finding.detail}")
        print()
        print("Resolve these issues before publishing a release.")
        print("See docs/release-checklist.md for the complete maintainer checklist.")
        return 1

    print("PASS: the methods and folder guides are present, and no known findings,")
    print("results, private evidence, runtime state, or internal paths were found.")
    print("This is a layout guardrail, not a privacy, licence, secret, or Git-history audit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
