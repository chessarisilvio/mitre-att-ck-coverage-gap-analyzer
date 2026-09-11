# MITRE ATT&CK Coverage Gap Analyzer

A professional tool for analyzing gaps between MITRE ATT&CK framework and your security coverage map. Identify uncovered techniques, prioritize them based on risk, and generate actionable reports for security teams and consultants.

## Features

- **Parse MITRE ATT&CK STIX 2.1 JSON** - Official enterprise-attack data from MITRE
- **Load coverage maps** - Support for CSV, JSON, and YAML formats
- **Gap analysis engine** - Compares MITRE techniques against your coverage
- **Scoring engine** - Prioritizes uncovered techniques using prevalence, exploitability, and data source factors
- **Professional reports** - Generate Markdown, HTML, and JSON reports with:
  - Executive summary
  - Gap matrix by tactic
  - Priority backlog of uncovered techniques
  - Detection rule stubs (Sigma, Elastic, Splunk templates)
- **CLI interface** - Easy-to-use command line with Rich formatting
- **Python package** - Installable via pip with console script
- **System monitoring** - Real-time GPU/CPU metrics for performance optimization

## Installation

```bash
# Install from source
pip install .

# Or install the wheel
pip install dist/mitre_gap_analyzer-0.1.0-py3-none-any.whl
```

## Usage

### Basic Analysis

```bash
# Run gap analysis with default paths
mitre-gap-analyzer analyze

# Or specify custom paths
mitre-gap-analyzer analyze \
    --mitre-path ./data/enterprise-attack.json \
    --coverage-path ./data/coverage.csv \
    --output-dir ./reports \
    --format md
```

### Generate Report from Existing Results

```bash
mitre-gap-analyzer report \
    ./reports/gap_analysis_report.json \
    --format html \
    --output-dir ./reports
```

### Monitor System Resources

```bash
# Real-time monitoring with custom interval
mitre-gap-analyzer monitor --interval 2.0 --duration 60

# Check GPU availability
mitre-gap-analyzer check-gpu
```

### Show Version

```bash
mitre-gap-analyzer version
```

## Output Formats

- **Markdown (.md)** - Human-readable, ideal for sharing and archiving
- **HTML (.html)** - Professional styling with responsive design
- **JSON (.json)** - Machine-readable for integration with other tools

## Report Sections

1. **Executive Summary** - High-level coverage metrics and risk assessment
2. **Gap Matrix** - Coverage breakdown by MITRE tactic with visual indicators
3. **Priority Backlog** - Top uncovered techniques with risk scores
4. **Detection Rule Stubs** - Ready-to-customize rule templates (Sigma, Elasticsearch, Splunk)

## Data Sources

The tool expects:
- MITRE ATT&CK STIX 2.1 JSON (download from [mitre/cti](https://github.com/mitre/cti))
- Coverage map in CSV, JSON, or YAML format with columns:
  - `technique_id` (e.g., T1059)
  - `technique_name` (optional)
  - `data_sources` (optional, comma-separated)
  - `notes` (optional)

## System Requirements

- Python 3.8+
- For GPU monitoring: NVIDIA GPU with nvidia-smi
- Optional: Rich, PyYAML for enhanced output

## License

MIT License - see [LICENSE](LICENSE) file

## Contributing

This project is designed for security professionals and consultants. Contributions welcome for:
- Additional output formats
- Enhanced scoring algorithms
- Integration with SIEM platforms
- Documentation improvements

## Contact

For commercial inquiries or support:
- GitHub: https://github.com/[REDACTED]/mitre-attck-coverage-gap-analyzer