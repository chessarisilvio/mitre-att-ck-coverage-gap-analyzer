"""End-to-end tests for the CLI interface."""

import json
import tempfile
from pathlib import Path

from typer.testing import CliRunner
from mitre_gap_analyzer.cli import app


runner = CliRunner()


def test_cli_analyze_json_output():
    """Test CLI analyze command with JSON output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir) / "output"

        result = runner.invoke(
            app,
            [
                "analyze",
                "--mitre-path", "tests/test_mitre_sample.json",
                "--coverage-path", "tests/test_coverage.csv",
                "--format", "json",
                "--output-dir", str(output_dir),
            ],
        )

        assert result.exit_code == 0
        assert output_dir.exists()

        # Check output file was created
        output_file = output_dir / "gap_analysis_report.json"
        assert output_file.exists()

        # Verify JSON structure
        with open(output_file) as f:
            data = json.load(f)

        assert "overall_coverage" in data
        assert "total_techniques" in data
        assert "covered_techniques" in data
        assert "uncovered_techniques" in data
        assert data["total_techniques"] > 0


def test_cli_analyze_markdown_output():
    """Test CLI analyze command with Markdown output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir) / "output"

        result = runner.invoke(
            app,
            [
                "analyze",
                "--mitre-path", "tests/test_mitre_sample.json",
                "--coverage-path", "tests/test_coverage.csv",
                "--format", "md",
                "--output-dir", str(output_dir),
            ],
        )

        assert result.exit_code == 0

        # Check output file was created
        output_file = output_dir / "gap_analysis_report.md"
        assert output_file.exists()

        # Verify markdown content
        content = output_file.read_text()
        assert "# MITRE ATT&CK Coverage Gap Analysis Report" in content


def test_cli_analyze_html_output():
    """Test CLI analyze command with HTML output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir) / "output"

        result = runner.invoke(
            app,
            [
                "analyze",
                "--mitre-path", "tests/test_mitre_sample.json",
                "--coverage-path", "tests/test_coverage.csv",
                "--format", "html",
                "--output-dir", str(output_dir),
            ],
        )

        assert result.exit_code == 0

        # Check output file was created
        output_file = output_dir / "gap_analysis_report.html"
        assert output_file.exists()

        # Verify HTML content
        content = output_file.read_text()
        assert "<!DOCTYPE html>" in content or "<html" in content


def test_cli_version():
    """Test CLI version command."""
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "MITRE ATT&CK Coverage Gap Analyzer" in result.output


def test_cli_help():
    """Test CLI help command."""
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "analyze" in result.output
    assert "report" in result.output
    assert "export" in result.output


def test_cli_analyze_missing_file():
    """Test CLI analyze with missing input file."""
    result = runner.invoke(
        app,
        [
            "analyze",
            "--mitre-path", "nonexistent.json",
            "--coverage-path", "tests/test_coverage.csv",
        ],
    )

    assert result.exit_code == 1


def test_cli_export_all_formats():
    """Test CLI export command with all formats."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # First create a results file
        output_dir = Path(tmpdir) / "output"
        analyze_result = runner.invoke(
            app,
            [
                "analyze",
                "--mitre-path", "tests/test_mitre_sample.json",
                "--coverage-path", "tests/test_coverage.csv",
                "--format", "json",
                "--output-dir", str(output_dir),
            ],
        )

        assert analyze_result.exit_code == 0

        # Now export
        results_file = output_dir / "gap_analysis_report.json"
        export_dir = Path(tmpdir) / "exports"

        export_result = runner.invoke(
            app,
            [
                "export",
                str(results_file),
                "--format", "all",
                "--output-dir", str(export_dir),
            ],
        )

        assert export_result.exit_code == 0

        # Check all formats were exported
        assert (export_dir / "gap_analysis_report.md").exists()
        assert (export_dir / "gap_analysis_report.json").exists()
        assert (export_dir / "gap_analysis_report.html").exists()


if __name__ == "__main__":
    test_cli_analyze_json_output()
    test_cli_analyze_markdown_output()
    test_cli_analyze_html_output()
    test_cli_version()
    test_cli_help()
    test_cli_analyze_missing_file()
    test_cli_export_all_formats()
    print("\n✅ All CLI tests passed!")