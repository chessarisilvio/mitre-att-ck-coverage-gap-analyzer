"""CLI interface for MITRE ATT&CK Coverage Gap Analyzer."""

import json
import logging
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.logging import RichHandler

from .mitre_loader import MITRELoader
from .coverage_loader import CoverageLoader
from .gap_engine import GapEngine
from .scoring_engine import ScoringEngine
from .report_generator import ReportGenerator

app = typer.Typer(
    name="mitre-gap-analyzer",
    help="MITRE ATT&CK Coverage Gap Analyzer",
    add_completion=False,
)
console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)


def _setup_logging(verbose: bool, quiet: bool) -> None:
    """Setup logging level based on flags."""
    if quiet:
        logging.getLogger().setLevel(logging.ERROR)
    elif verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)


@app.command()
def analyze(
    mitre_path: Optional[Path] = typer.Option(
        None,
        "--mitre-path",
        help="Path to MITRE ATT&CK STIX JSON file (default: ./data/enterprise-attack.json)",
    ),
    coverage_path: Optional[Path] = typer.Option(
        None,
        "--coverage-path",
        help="Path to coverage map file (CSV/JSON/YAML) (default: ./data/coverage.csv)",
    ),
    output_dir: Path = typer.Option(
        "./output",
        "--output-dir",
        help="Directory for output reports (default: ./output)",
    ),
    format: str = typer.Option(
        "md",
        "--format",
        help="Output format (md, json, html) (default: md)",
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Enable verbose logging"),
    quiet: bool = typer.Option(False, "--quiet", help="Only show errors"),
):
    """
    Execute gap analysis between MITRE ATT&CK and coverage map.
    """
    _setup_logging(verbose, quiet)

    try:
        # Initialize loaders
        mitre_loader = MITRELoader(mitre_path)
        coverage_loader = CoverageLoader(coverage_path)

        # Load data
        mitre_loader.load()
        coverage_loader.load(mitre_loader)

        # Run gap analysis
        gap_engine = GapEngine(mitre_loader, coverage_loader)
        results = gap_engine.analyze()

        # Score uncovered techniques
        scoring_engine = ScoringEngine(mitre_loader, gap_engine)
        results['scored_techniques'] = scoring_engine.score_uncovered_techniques()

        # Generate report
        report_generator = ReportGenerator(results)
        if format == "md":
            content = report_generator.generate_markdown()
        elif format == "json":
            content = report_generator.generate_json()
        elif format == "html":
            content = report_generator.generate_html()
        else:
            logger.error(f"Unsupported format: {format}")
            raise typer.Exit(code=1)

        # Save report
        output_dir.mkdir(parents=True, exist_ok=True)
        report_file = output_dir / f"gap_analysis_report.{format}"
        report_generator.save_report(content, report_file, format)

        # Print summary to console
        console.print(f"[green]Analysis complete![/green]")
        console.print(f"Overall Coverage: {results['overall_coverage']}%")
        console.print(f"Total Techniques: {results['total_techniques']}")
        console.print(f"Covered Techniques: {results['covered_techniques']}")
        console.print(f"Uncovered Techniques: {results['uncovered_techniques']}")
        console.print(f"Report saved to: [bold]{report_file}[/bold]")

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        if verbose:
            logger.exception("Detailed error:")
        raise typer.Exit(code=1)


@app.command()
def report(
    input_file: Path = typer.Argument(
        ..., help="Path to previous analysis results JSON file"
    ),
    format: str = typer.Option(
        "md",
        "--format",
        help="Output format (md, json, html) (default: md)",
    ),
    output_dir: Path = typer.Option(
        "./output",
        "--output-dir",
        help="Directory for output reports (default: ./output)",
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Enable verbose logging"),
    quiet: bool = typer.Option(False, "--quiet", help="Only show errors"),
):
    """
    Generate report from previously saved analysis results.
    """
    _setup_logging(verbose, quiet)

    try:
        if not input_file.exists():
            logger.error(f"Input file not found: {input_file}")
            raise typer.Exit(code=1)

        # Load results
        with open(input_file, "r", encoding="utf-8") as f:
            results = json.load(f)

        # Generate report
        report_generator = ReportGenerator(results)
        if format == "md":
            content = report_generator.generate_markdown()
        elif format == "json":
            content = report_generator.generate_json()
        elif format == "html":
            content = report_generator.generate_html()
        else:
            logger.error(f"Unsupported format: {format}")
            raise typer.Exit(code=1)

        # Save report
        output_dir.mkdir(parents=True, exist_ok=True)
        report_file = output_dir / f"report.{format}"
        report_generator.save_report(content, report_file, format)

        console.print(f"[green]Report generated![/green]")
        console.print(f"Report saved to: [bold]{report_file}[/bold]")

    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        if verbose:
            logger.exception("Detailed error:")
        raise typer.Exit(code=1)


@app.command()
def version():
    """Show version information."""
    from mitre_gap_analyzer import __version__

    console.print(f"MITRE ATT&CK Coverage Gap Analyzer v{__version__}")


@app.command()
def export(
    input_file: Path = typer.Argument(
        ..., help="Path to analysis results JSON file"
    ),
    output_format: str = typer.Option(
        "all",
        "--format",
        help="Export format (md, json, html, all) (default: all)",
    ),
    output_dir: Path = typer.Option(
        "./exports",
        "--output-dir",
        help="Directory for exported reports (default: ./exports)",
    ),
    include_metadata: bool = typer.Option(
        True,
        "--include-metadata/--no-include-metadata",
        help="Include analysis metadata (timestamp, tool version) (default: True)",
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Enable verbose logging"),
    quiet: bool = typer.Option(False, "--quiet", help="Only show errors"),
):
    """
    Export analysis results to various formats.
    """
    _setup_logging(verbose, quiet)

    try:
        if not input_file.exists():
            logger.error(f"Input file not found: {input_file}")
            raise typer.Exit(code=1)

        # Load results
        with open(input_file, "r", encoding="utf-8") as f:
            results = json.load(f)

        # Add metadata if requested
        if include_metadata:
            from datetime import datetime
            from mitre_gap_analyzer import __version__
            results['_metadata'] = {
                'exported_at': datetime.now().isoformat(),
                'tool_version': __version__,
                'source_file': str(input_file.name)
            }

        # Generate reports
        report_generator = ReportGenerator(results)
        output_dir.mkdir(parents=True, exist_ok=True)

        formats_to_export = []
        if output_format == "all":
            formats_to_export = ["md", "json", "html"]
        else:
            formats_to_export = [output_format]

        exported_files = []
        for fmt in formats_to_export:
            if fmt == "md":
                content = report_generator.generate_markdown()
                report_file = output_dir / "gap_analysis_report.md"
            elif fmt == "json":
                content = report_generator.generate_json()
                report_file = output_dir / "gap_analysis_report.json"
            elif fmt == "html":
                content = report_generator.generate_html()
                report_file = output_dir / "gap_analysis_report.html"
            else:
                logger.error(f"Unsupported format: {fmt}")
                continue

            report_generator.save_report(content, report_file, fmt)
            exported_files.append(str(report_file))

        console.print(f"[green]Export complete![/green]")
        for f in exported_files:
            console.print(f"  - {f}")

    except Exception as e:
        logger.error(f"Export failed: {e}")
        if verbose:
            logger.exception("Detailed error:")
        raise typer.Exit(code=1)


def main():
    """Main entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()