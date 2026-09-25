# MITRE ATT&CK Coverage Gap Analyzer

A command-line tool that compares your detection coverage map against the
official MITRE ATT&CK Enterprise dataset, reports which techniques are
uncovered, and generates a prioritized backlog with Markdown/HTML/JSON
reports.

## What it actually does

- Parses a MITRE ATT&CK Enterprise STIX 2.1 bundle (`attack-pattern`,
  `x-mitre-tactic`, and `subtechnique-of` relationship objects), skipping
  revoked/deprecated techniques.
- Loads a coverage map from **CSV**, **JSON**, or **YAML**, matching each
  entry's `technique_id` (e.g. `T1078`) against the STIX data.
- Computes, per tactic and overall, how many techniques are covered vs.
  uncovered.
- Scores every uncovered technique 0–100 and labels it
  `INFO`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL` (see [Scoring methodology](#scoring-methodology-and-its-limits)
  below for what the score is actually based on).
- Renders a report (executive summary, gap matrix by tactic, priority
  backlog, Sigma/Elasticsearch/Splunk detection-rule *stubs* you still have
  to fill in) as Markdown, HTML, or JSON.
- Ships a `mitre-gap-analyzer` CLI with four commands: `analyze`, `report`,
  `export`, `version`.

## Installation

Requires Python 3.8+.

```bash
git clone https://github.com/chessarisilvio/mitre-att-ck-coverage-gap-analyzer.git
cd mitre-att-ck-coverage-gap-analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install .
```

For local development (editable install + test dependencies):

```bash
pip install -e ".[dev]"
```

Both commands were verified in a clean virtual environment as part of this
fix; `pip install .` previously failed outright with a `HeaderParseError`
because of an invalid placeholder email in `pyproject.toml`.

## Getting MITRE ATT&CK data

The tool needs an Enterprise ATT&CK STIX 2.1 JSON bundle. Download the
current one from the official MITRE repository:

```bash
curl -L -o data/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

This file is not included in the repo (it's tens of MB and MITRE updates it
regularly); `data/sources.json` lists this and the Mobile/ICS ATT&CK URLs.

## Usage

### Run a gap analysis

```bash
mitre-gap-analyzer analyze \
    --mitre-path ./data/enterprise-attack.json \
    --coverage-path ./data/coverage.csv \
    --output-dir ./output \
    --format md
```

`--mitre-path` and `--coverage-path` default to
`./data/enterprise-attack.json` and `./data/coverage.csv` if omitted;
`--output-dir` defaults to `./output`; `--format` defaults to `md`
(`md`, `json`, `html`).

Your coverage map needs at minimum a `technique_id` column/field and a
`tactic` column/field:

```csv
technique_id,tactic,technique_name,status,source
T1078,initial-access,Valid Accounts,covered,Sigma
T1078.001,initial-access,Default Accounts,covered,Sigma
```

JSON accepts either a list of `{"technique_id": ..., "tactic": ...}`
objects or a `{"tactic": ["T1078", ...]}` mapping; YAML follows the same
two shapes.

### Regenerate a report from a previous run

```bash
mitre-gap-analyzer report ./output/gap_analysis_report.json --format html --output-dir ./output
```

### Export to all formats at once

```bash
mitre-gap-analyzer export ./output/gap_analysis_report.json --format all --output-dir ./exports
```

### Show the version

```bash
mitre-gap-analyzer version
```

Every command above (including a full `analyze` run against the real,
freshly downloaded `enterprise-attack.json`) was executed against this
codebase while preparing this fix.

## Scoring methodology and its limits

Each uncovered technique gets a score built from three factors:

- **Exploitability (0–30):** heuristic based on external references that
  look like exploit databases, plus kill-chain phases suggesting
  exploitation/privilege-escalation. This is the only factor that varies
  meaningfully in practice.
- **Prevalence (0–30)** and **data-source availability (0–40)**: intended
  to read `x_mitre_prevalence` and `x_mitre_data_sources` from the STIX
  data. **Neither field exists in the official MITRE ATT&CK STIX bundle**
  (verified against the current `enterprise-attack.json`), so both factors
  silently fall back to a fixed default for every technique. Treat the
  resulting score as a rough exploitability-driven ranking, not a
  calibrated risk score.

## Output formats

- **Markdown (`.md`)** — for sharing/archiving in a repo or wiki.
- **HTML (`.html`)** — a single self-contained styled page.
- **JSON (`.json`)** — machine-readable; also the input format `report`/`export` expect.

## Limitations

- The scoring engine's prevalence and data-source factors are constant
  defaults against real MITRE data, as explained above — only the
  exploitability heuristic differentiates uncovered techniques.
- "Total techniques" is a **sum across tactics**, not a count of unique
  ATT&CK technique IDs: a technique mapped to four tactics (e.g. Valid
  Accounts / T1078) is counted four times. Use the per-tactic table for
  per-tactic figures.
- Sigma/Elasticsearch/Splunk sections are unfilled templates (placeholder
  IDs and a fixed date), meant as a starting point, not ready-to-deploy
  rules.
- No CSV/JSON/YAML schema validation beyond the required `technique_id`/
  `tactic` fields; malformed rows are skipped with a logged warning.
- The repository also contains `monitor.py`, `optimizer.py`, and
  `config.yaml` — a GPU/CPU auto-tuning module left over from the initial
  scaffold. It has its own unit tests but is **not** wired into the CLI and
  is unrelated to ATT&CK gap analysis; earlier versions of this README
  incorrectly advertised it as `monitor`/`check-gpu` commands, which never
  existed.
- Only the Enterprise ATT&CK matrix has been exercised end-to-end; Mobile
  and ICS STIX bundles use the same object types and should work, but are
  untested here.

## Data Sources

- MITRE ATT&CK STIX 2.1 JSON — download from
  [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
  (see `data/sources.json` for direct URLs). Licensed under the MITRE
  ATT&CK® terms (non-commercial use).
- Coverage map: CSV, JSON, or YAML with `technique_id` (required, e.g.
  `T1059`) and `tactic` (required, e.g. `initial-access`); `technique_name`,
  `status`, `source` are read but not required.

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

42 tests cover the STIX/coverage loaders (including the JSON/YAML formats
and revoked/deprecated-technique filtering), the gap and scoring engines,
report generation, and the CLI end-to-end via `typer.testing.CliRunner`.
None of them require a GPU; the monitor/optimizer tests mock `nvidia-smi`
and `/proc` reads. A GitHub Actions workflow
(`.github/workflows/tests.yml`) runs this suite on Python 3.10 and 3.12 on
every push and pull request.

## License

MIT License — see [LICENSE](LICENSE).

## Contributing

Issues and pull requests are welcome, particularly for:
- Deriving real prevalence/data-source signals (e.g. from ATT&CK's
  procedure examples or data-component relationships) instead of the
  current constant defaults.
- Additional output formats or SIEM integrations.
- Mobile/ICS ATT&CK matrix testing.
