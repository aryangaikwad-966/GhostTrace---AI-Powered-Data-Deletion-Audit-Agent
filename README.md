# GhostTrace — AI-Powered Data Deletion Audit Agent

> HackerRank Orchestrate (October 2026) — *Ghost Data Still Exists*

GhostTrace is a deterministic deletion-audit agent that processes every deletion request in `dataset/deletion_requests.csv`, reconstructs the subject's current and historical identifiers, searches global activity and evidence, applies the supplied deletion policy, and decides whether the deletion is complete. When incomplete, it reports remaining records and recreation risks with an ordered remediation plan and verification checks.

## Features

- **Multilingual authorization detection** — recognizes deletion requests across 20+ languages and rejects access/correction/export/marketing opt-out requests.
- **Identifier reconstruction** — resolves stable `user_id` from current and historical emails via `user_identities.csv` and `user_audit_log.csv`.
- **Evidence-driven state** — parses JSON, CSV, SQL snapshots, logs, PDFs, and screenshots into observations.
- **Policy application** — honors `deletion_rules.csv` (delete / redact / anonymize / retain / tombstone).
- **Deterministic output** — produces `output.csv` with `case_id,deletion_status,steps_json` for all 518 cases, sorted by `case_id`.

## Architecture

```
code/
├── main.py                # Entry point: parses evidence, audits each case, writes output.csv
├── run_sample.py          # Run on sample_deletion_requests.csv
├── evaluate.py            # Evaluation helpers
├── evaluation/
│   ├── main.py            # Public sample + team-authored case evaluation
│   ├── evaluation_report.md
│   └── usage_report.md
└── tests/
    └── test_ghosttrace.py
```

## Setup

Requirements: Python 3.9+ and the Tesseract OCR executable (used for screenshots).

```sh
brew install tesseract            # macOS
# or: sudo apt-get install tesseract-ocr   # Debian/Ubuntu
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r code/requirements.txt
```

## Run

Process all 518 evaluation requests and write `output.csv` at the repository root:

```sh
python3 code/main.py
```

Run on the public sample (32 cases):

```sh
python3 code/run_sample.py
```

## Evaluate and Test

```sh
python3 code/evaluation/main.py
python3 -B -m unittest discover -s code/tests -v
```

The evaluator runs the public 32-case sample, reports status/step/field/sequence metrics, checks output invariants, and runs six team-authored authorization/identity cases.

## Package for Submission

Run from the repository root after the pipeline and checks:

```sh
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/node_modules/*" "*/.git/*" "*/.DS_Store"
```

The ZIP intentionally omits `dataset/`, `output.csv`, `log.txt`, environments, caches, and credentials. Submit `code.zip`, root `output.csv`, and root `log.txt` separately.

## Output Contract

`output.csv` columns (exact order):

```
case_id,deletion_status,steps_json
```

- Exactly 518 data rows, one per `case_id` in `dataset/deletion_requests.csv`, sorted by `case_id`.
- `deletion_status` ∈ {`COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE`}.
- `steps_json` is a valid JSON array of steps with phases `FINDING` → `REMEDIATION` → `VERIFICATION`.
- `NOT_APPLICABLE` cases use `steps_json=[]`.

## Notes

- No external model or network service is called; the pipeline is fully deterministic.
- Secrets are read from environment variables only (`.env` not committed).
- Uses only participant-facing files under `dataset/`.
