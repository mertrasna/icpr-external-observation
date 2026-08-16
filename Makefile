SHELL := /bin/sh

PYTHON ?= python3
VENV ?= .venv
VENV_PYTHON := $(VENV)/bin/python
RESULTS_DIR ?= results/egress-catalogue/generated
SNAPSHOT_DIR ?=
ROUTING_DAT ?=
ASN_NAMES ?=
PUBLIC_TREE ?= .
MPLCONFIGDIR ?= $(CURDIR)/.cache/matplotlib

export MPLCONFIGDIR
export PYTHONDONTWRITEBYTECODE := 1

.PHONY: help setup ensure-venv test test-egress test-ecs test-experiment test-protocol test-server \
	demo-egress analyze-egress check-public-tree

help:
	@echo "iCPR methods-toolkit commands"
	@echo "  make setup          Create .venv and install pinned dependencies"
	@echo "  make test           Run all offline test suites"
	@echo "  make demo-egress    Run a tiny synthetic catalogue demonstration"
	@echo "  make analyze-egress Analyse researcher-supplied catalogue inputs"
	@echo "  make check-public-tree Validate the methods-only repository layout"

setup:
	$(PYTHON) -m venv "$(VENV)"
	"$(VENV_PYTHON)" -m pip install --disable-pip-version-check -r requirements.txt
	"$(VENV_PYTHON)" -m pip check

ensure-venv:
	@test -x "$(VENV_PYTHON)" || { echo "Missing $(VENV_PYTHON); run 'make setup' first." >&2; exit 2; }

test: test-egress test-ecs test-experiment test-protocol test-server

test-egress: ensure-venv
	mkdir -p "$(MPLCONFIGDIR)"
	"$(VENV_PYTHON)" egress-catalog-analysis/tests/test_churn.py
	"$(VENV_PYTHON)" egress-catalog-analysis/tests/test_churn_plot.py

test-ecs: ensure-venv
	"$(VENV_PYTHON)" -m unittest discover -s ecs-scanner/tests -p 'test_scanner.py'

test-experiment: ensure-venv
	"$(VENV_PYTHON)" -m unittest discover -s experiment/tests -p 'test_*.py'

test-protocol: ensure-venv
	"$(VENV_PYTHON)" -m unittest discover -s protocol-diagnostic/tests -p 'test_*.py'

test-server: ensure-venv
	"$(VENV_PYTHON)" -m unittest discover -s server/tests -p 'test_*.py'

demo-egress: ensure-venv
	mkdir -p "$(RESULTS_DIR)/demo" "$(MPLCONFIGDIR)"
	"$(VENV_PYTHON)" egress-catalog-analysis/churn_series.py \
		--dir egress-catalog-analysis/examples/snapshots \
		--out "$(RESULTS_DIR)/demo/churn_series.csv"
	"$(VENV_PYTHON)" egress-catalog-analysis/churn_plot.py \
		--csv "$(RESULTS_DIR)/demo/churn_series.csv" \
		--pdf "$(RESULTS_DIR)/demo/catalogue_churn_timeline.pdf" \
		--png "$(RESULTS_DIR)/demo/catalogue_churn_timeline.png"

analyze-egress: ensure-venv
	@test -n "$(SNAPSHOT_DIR)" || { echo "Set SNAPSHOT_DIR to a directory of dated Apple CSV snapshots." >&2; exit 2; }
	@test -n "$(ROUTING_DAT)" || { echo "Set ROUTING_DAT to a pyasn IP-to-ASN database." >&2; exit 2; }
	@test -n "$(ASN_NAMES)" || { echo "Set ASN_NAMES to an ASN-name JSON file." >&2; exit 2; }
	mkdir -p "$(RESULTS_DIR)" "$(MPLCONFIGDIR)"
	"$(VENV_PYTHON)" egress-catalog-analysis/catalogue_audit.py \
		--dir "$(SNAPSHOT_DIR)" \
		--dat "$(ROUTING_DAT)" \
		--names "$(ASN_NAMES)" \
		--output-dir "$(RESULTS_DIR)"
	"$(VENV_PYTHON)" egress-catalog-analysis/churn_series.py \
		--dir "$(SNAPSHOT_DIR)" \
		--out "$(RESULTS_DIR)/churn_series.csv"
	"$(VENV_PYTHON)" egress-catalog-analysis/churn_plot.py \
		--csv "$(RESULTS_DIR)/churn_series.csv" \
		--pdf "$(RESULTS_DIR)/catalogue_churn_timeline.pdf" \
		--png "$(RESULTS_DIR)/catalogue_churn_timeline.png"

check-public-tree:
	$(PYTHON) scripts/check_public_tree.py "$(PUBLIC_TREE)"
