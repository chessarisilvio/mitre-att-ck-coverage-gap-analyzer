"""MITRE ATT&CK Coverage Gap Analyzer."""

__version__ = "0.1.0"
__author__ = "[REDACTED]"


def main():
    """Main entry point for the CLI."""
    from .cli import app
    app()