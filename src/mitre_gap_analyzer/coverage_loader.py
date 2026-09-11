"""Coverage map loader supporting CSV, JSON, and YAML formats."""

import csv
import json
import logging
from pathlib import Path
from typing import Dict, List, Set, Any, Optional

import yaml

from .mitre_loader import MITRELoader

logger = logging.getLogger(__name__)


class CoverageLoader:
    """Loads coverage maps from various formats."""

    def __init__(self, coverage_path: Optional[Path] = None):
        """
        Initialize the loader.

        Args:
            coverage_path: Path to the coverage map file.
                          If None, uses the default path ./data/coverage.csv
                          relative to the current working directory.
        """
        if coverage_path is None:
            coverage_path = Path("./data/coverage.csv")
        self.coverage_path = coverage_path
        self._coverage: Dict[str, Dict[str, Any]] = {}
        self._is_loaded = False

    def load(self, mitre_loader: MITRELoader) -> Dict[str, Set[str]]:
        """
        Load and parse the coverage map.

        Args:
            mitre_loader: MITRELoader instance for cross-referencing technique IDs to STIX IDs.

        Returns:
            A dictionary mapping tactic shortname to a set of technique IDs (STIX IDs)
            that are covered by the coverage map.
        """
        if self._is_loaded:
            return self._build_internal_structure()

        logger.info(f"Loading coverage map from {self.coverage_path}")
        if not self.coverage_path.exists():
            raise FileNotFoundError(f"Coverage map file not found: {self.coverage_path}")

        # Detect format from file extension
        suffix = self.coverage_path.suffix.lower()
        if suffix == ".csv":
            self._load_csv(mitre_loader)
        elif suffix in [".json", ".jsonl"]:
            self._load_json(mitre_loader)
        elif suffix == ".yaml" or suffix == ".yml":
            self._load_yaml(mitre_loader)
        else:
            raise ValueError(
                f"Unsupported coverage map format: {suffix}. "
                "Supported formats: CSV, JSON, YAML"
            )

        self._is_loaded = True
        return self._build_internal_structure()

    def _load_csv(self, mitre_loader: MITRELoader) -> None:
        """Load coverage map from CSV format."""
        logger.debug("Loading CSV coverage map")
        with open(self.coverage_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                technique_id = row.get("technique_id", "").strip()
                if not technique_id:
                    continue
                tactic = row.get("tactic", "").strip()
                if not tactic:
                    continue
                # Convert technique_id (e.g., T1078) to STIX ID (e.g., attack-pattern--1)
                stix_id = mitre_loader.get_technique_stix_id(technique_id)
                if stix_id is None:
                    logger.warning(f"Technique ID {technique_id} not found in MITRE data, skipping")
                    continue
                if tactic not in self._coverage:
                    self._coverage[tactic] = set()
                self._coverage[tactic].add(stix_id)
        logger.info(f"Loaded {len(self._coverage)} tactics from CSV")

    def _load_json(self) -> None:
        """Load coverage map from JSON format."""
        logger.debug("Loading JSON coverage map")
        with open(self.coverage_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            # Array of objects
            for item in data:
                technique_id = item.get("technique_id", "").strip()
                if not technique_id:
                    continue
                tactic = item.get("tactic", "").strip()
                if not tactic:
                    continue
                if tactic not in self._coverage:
                    self._coverage[tactic] = set()
                self._coverage[tactic].add(technique_id)
        elif isinstance(data, dict):
            # Dict mapping tactic -> list of technique IDs
            for tactic, technique_ids in data.items():
                if isinstance(technique_ids, list):
                    self._coverage[tactic] = set(technique_ids)
        logger.info(f"Loaded {len(self._coverage)} tactics from JSON")

    def _load_yaml(self) -> None:
        """Load coverage map from YAML format."""
        logger.debug("Loading YAML coverage map")
        with open(self.coverage_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, list):
            for item in data:
                technique_id = item.get("technique_id", "").strip()
                if not technique_id:
                    continue
                tactic = item.get("tactic", "").strip()
                if not tactic:
                    continue
                if tactic not in self._coverage:
                    self._coverage[tactic] = set()
                self._coverage[tactic].add(technique_id)
        elif isinstance(data, dict):
            for tactic, technique_ids in data.items():
                if isinstance(technique_ids, list):
                    self._coverage[tactic] = set(technique_ids)
        logger.info(f"Loaded {len(self._coverage)} tactics from YAML")

    def _build_internal_structure(self) -> Dict[str, Set[str]]:
        """
        Build the internal structure:
        {tactic: set(covered_technique_ids)}
        """
        return self._coverage.copy()

    def get_coverage_for_tactic(self, tactic_shortname: str) -> Set[str]:
        """Get covered technique IDs for a specific tactic."""
        return self._coverage.get(tactic_shortname, set())

    def get_all_covered_technique_ids(self) -> Set[str]:
        """Get all covered technique IDs across all tactics."""
        covered = set()
        for tactic, technique_ids in self._coverage.items():
            covered.update(technique_ids)
        return covered

    def get_all_tactics(self) -> Set[str]:
        """Get all tactic shortnames."""
        return set(self._coverage.keys())