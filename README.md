# GhostTrace

Deterministic Python deletion-audit pipeline. It reads the 518 requests and participant-facing identity, policy, activity, and evidence files under `dataset/`, then writes root `output.csv`. No external model or service is called.

## Setup and run

Requirements: Python 3.9+ and the Tesseract OCR executable (used for screenshots). On macOS:

```sh
brew install tesseract
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r code/requirements.txt
python3 code/main.py
```

## Evaluate and test

```sh
python3 code/evaluation/main.py
python3 -B -m unittest discover -s code/tests -v
```

The evaluator runs the public 32-case sample, reports status/step/field/sequence metrics and checks output invariants. It also runs six team-authored authorization/identity cases. Full-run accounting and sample results are in `code/evaluation/`.

## Package

Run from the repository root after the pipeline and checks:

```sh
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/node_modules/*" "*/.git/*" "*/.DS_Store"
```

The ZIP intentionally omits `dataset/`, `output.csv`, `log.txt`, environments, caches, and credentials. Submit `code.zip`, root `output.csv`, and root `log.txt` separately.
