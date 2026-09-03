# COMP 5700 Fall 2026 Project

## Project Overview

This project detects changes between versions of the CIS Docker Benchmark security requirements and uses those changes to determine which Hadolint static-analysis rules should be executed against Dockerfiles.

The project has four parts:

1. **Extractor** — Extract key data elements (KDEs) and associated security requirements using `google/gemma-3-1b-it`.
2. **Comparator** — Compare KDE names and requirements between document versions.
3. **Executor** — Map detected changes to Hadolint rules, run Hadolint, and export summarized results to CSV.
4. **Project Packaging** — Provide pinned dependencies, documentation, automated testing, and a PyInstaller executable.

## Team Member

| Name | BannerID | Auburn Email |
|---|---|---|
| Holly Castor | 904240325 | hec0059@auburn.edu |

## Required LLM

Task 1 uses `google/gemma-3-1b-it`.

## Project Structure

- `src/extractor.py` — Task 1 Extractor
- `src/comparator.py` — Task 2 Comparator
- `src/executor.py` — Task 3 Executor
- `tests/` — unit tests
- `PROMPT.md` — zero-shot, few-shot, and chain-of-thought prompts
- `requirements.txt` — pinned Python dependencies
- `outputs/task1/` — Task 1 YAML and LLM outputs
- `outputs/task2/` — Task 2 comparison TEXT outputs
- `outputs/task3/` — Task 3 Hadolint/CSV outputs
- `data/input/` — local CIS Benchmark PDFs

## Task 1 — Extractor

The extractor validates two PDF inputs, creates zero-shot, few-shot, and chain-of-thought prompts, uses `google/gemma-3-1b-it` to identify KDEs, stores KDE-to-requirement mappings in YAML, and records the LLM prompts and outputs.

Required document combinations:

- v0 + v1
- v0 + v2
- v1 + v2
- v1 + v1
- v2 + v2

## Task 2 — Comparator

The comparator loads two KDE YAML files, compares KDE names, and compares the requirements associated with KDEs.

The required no-difference messages are:

`NO DIFFERENCES IN REGARDS TO ELEMENT NAMES`

`NO DIFFERENCES IN REGARDS TO ELEMENT REQUIREMENTS`

## Task 3 — Executor

The executor loads Task 2 TEXT outputs, maps detected changes to Hadolint rules, runs Hadolint on the supplied Dockerfiles, returns a pandas DataFrame, and exports CSV results.

Required CSV columns:

`FilePath,DefaultSeverity,RULEID,COUNT`

If Task 2 reports no differences, Task 3 uses:

`NO DIFFERENCES FOUND`

## Installation

This project uses Python 3.12.

Create and activate a virtual environment:

`python3.12 -m venv comp5700-venv`

`source comp5700-venv/bin/activate`

Install Python dependencies:

`python -m pip install -r requirements.txt`

Hadolint must also be installed and available on the system PATH.

On macOS with Homebrew:

`brew install hadolint`

## Tests

Run all project tests from the repository root with:

`python -m pytest -q`

The project currently contains 13 unit tests:

- 6 Extractor tests
- 3 Comparator tests
- 4 Executor tests

Task 1 tests use mocked model generation so automated testing does not require downloading the CIS PDFs or Gemma model.

## Local CIS Benchmark Inputs

The CIS Docker Benchmark PDFs are local project inputs and are excluded from version control.

Expected local files:

- `data/input/docker-cis-v0.pdf` — CIS Docker Benchmark v1.6.0
- `data/input/docker-cis-v1.pdf` — CIS Docker Benchmark v1.7.0
- `data/input/docker-cis-v2.pdf` — CIS Docker Benchmark v1.8.0

## Hadolint

The project was developed with Hadolint 2.15.1.

## Dependencies

Exact Python package versions are pinned in `requirements.txt`.

## Notes

- The required Gemma model is gated on Hugging Face and may require authenticated access.
- Final Task 1 outputs were generated using real Gemma inference.
- CIS Benchmark PDFs are intentionally excluded from the public repository.

- Generated Task 1 and Task 2 outputs are retained locally and are not published in the public repository because they contain CIS-derived requirement text.
- The course-provided Dockerfiles archive is required for the final real Task 3 Hadolint CSV.
