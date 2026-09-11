"""Gap analysis engine comparing MITRE ATT&CK with coverage map."""

import logging
from typing import Dict, List, Set, Any, Optional

from .mitre_loader import MITRELoader
from .coverage_loader import CoverageLoader

logger = logging.getLogger(__name__)


class GapEngine:
    """Analyzes gaps between MITRE ATT&CK and coverage map."""

    def __init__(self, mitre_loader: MITRELoader, coverage_loader: CoverageLoader):
        """
        Initialize the gap engine.

        Args:
            mitre_loader: MITRELoader instance.
            coverage_loader: CoverageLoader instance.
        """
        self.mitre_loader = mitre_loader
        self.coverage_loader = coverage_loader
        self._results: Dict[str, Any] = {}

    def analyze(self) -> Dict[str, Any]:
        """
        Perform gap analysis.

        Returns:
            Dictionary containing:
                - tactics: List of tactic analysis results
                - overall_coverage: Overall coverage percentage
                - total_techniques: Total number of techniques
                - covered_techniques: Number of covered techniques
                - uncovered_techniques: Number of uncovered techniques
        """
        logger.info("Starting gap analysis")

        # Get MITRE tactics and techniques
        mitre_tactics = self.mitre_loader.get_all_tactic_shortnames()
        mitre_techniques = self.mitre_loader.get_all_technique_ids()

        # Get covered techniques from coverage map
        covered_techniques = self.coverage_loader.get_all_covered_technique_ids()

        # Calculate gaps per tactic
        tactic_results = []
        total_techniques = 0
        covered_count = 0

        for tactic_shortname in sorted(mitre_tactics):
            tactic_info = self.mitre_loader.get_tactic_info(tactic_shortname)
            if not tactic_info:
                continue

            # Get all technique IDs for this tactic
            technique_ids = tactic_info.get("technique_ids", set())
            total_techniques += len(technique_ids)

            # Get covered technique IDs for this tactic
            covered_ids = self.coverage_loader.get_coverage_for_tactic(tactic_shortname)
            uncovered_ids = technique_ids - covered_ids

            # Calculate coverage percentage for this tactic
            coverage_pct = 0.0
            if technique_ids:
                coverage_pct = (len(covered_ids) / len(technique_ids)) * 100

            tactic_result = {
                "tactic_shortname": tactic_shortname,
                "tactic_name": tactic_info.get("name", ""),
                "total_techniques": len(technique_ids),
                "covered_techniques": len(covered_ids),
                "uncovered_techniques": len(uncovered_ids),
                "coverage_percentage": round(coverage_pct, 2),
                "covered_technique_ids": sorted(list(covered_ids)),
                "uncovered_technique_ids": sorted(list(uncovered_ids)),
            }
            tactic_results.append(tactic_result)

            covered_count += len(covered_ids)

        # Calculate overall coverage
        overall_coverage = 0.0
        if total_techniques > 0:
            overall_coverage = (covered_count / total_techniques) * 100

        # Build results
        self._results = {
            "tactics": tactic_results,
            "overall_coverage": round(overall_coverage, 2),
            "total_techniques": total_techniques,
            "covered_techniques": covered_count,
            "uncovered_techniques": total_techniques - covered_count,
        }

        logger.info(
            f"Gap analysis complete: {covered_count}/{total_techniques} techniques covered "
            f"({overall_coverage:.2f}%)"
        )

        return self._results

    def get_results(self) -> Dict[str, Any]:
        """Get the analysis results."""
        return self._results

    def get_uncovered_techniques(self) -> List[Dict[str, Any]]:
        """
        Get all uncovered techniques across all tactics.

        Returns:
            List of technique info dicts with additional fields:
                - tactic_shortname
                - tactic_name
                - technique_id
                - technique_name
                - sub_technique_ids
        """
        results = self.get_results()
        uncovered_list = []

        for tactic_result in results["tactics"]:
            tactic_shortname = tactic_result["tactic_shortname"]
            tactic_name = tactic_result["tactic_name"]

            for tech_id in tactic_result["uncovered_technique_ids"]:
                tech_info = self.mitre_loader.get_technique_info(tech_id)
                if not tech_info:
                    continue

                uncovered_list.append(
                    {
                        "tactic_shortname": tactic_shortname,
                        "tactic_name": tactic_name,
                        "technique_id": tech_id,
                        "technique_name": tech_info["name"],
                        "is_subtechnique": tech_info["is_subtechnique"],
                        "parent": tech_info.get("parent"),
                    }
                )

        return uncovered_list

    def get_tactic_coverage_report(self, tactic_shortname: str) -> Optional[Dict[str, Any]]:
        """
        Get coverage report for a specific tactic.

        Args:
            tactic_shortname: Tactic shortname (e.g., "initial-access").

        Returns:
            Tactic coverage dict or None if tactic not found.
        """
        results = self.get_results()
        for tactic_result in results["tactics"]:
            if tactic_result["tactic_shortname"] == tactic_shortname:
                return tactic_result
        return None