"""Scoring engine for prioritizing uncovered techniques."""

import logging
from typing import Dict, List, Any, Optional

from .mitre_loader import MITRELoader
from .gap_engine import GapEngine

logger = logging.getLogger(__name__)


class ScoringEngine:
    """Scores uncovered techniques based on prevalence, exploitability, and data source availability."""

    def __init__(self, mitre_loader: MITRELoader, gap_engine: GapEngine):
        """
        Initialize the scoring engine.

        Args:
            mitre_loader: MITRELoader instance.
            gap_engine: GapEngine instance with analysis results.
        """
        self.mitre_loader = mitre_loader
        self.gap_engine = gap_engine

    def score_uncovered_techniques(self) -> List[Dict[str, Any]]:
        """
        Score all uncovered techniques.

        Returns:
            List of uncovered technique dicts with added 'score' and 'priority' fields,
            sorted by score descending.
        """
        uncovered = self.gap_engine.get_uncovered_techniques()
        scored_techniques = []

        for tech in uncovered:
            score = self._calculate_score(tech)
            tech_with_score = tech.copy()
            tech_with_score["score"] = round(score, 2)
            tech_with_score["priority"] = self._get_priority_label(score)
            scored_techniques.append(tech_with_score)

        # Sort by score descending
        scored_techniques.sort(key=lambda x: x["score"], reverse=True)
        return scored_techniques

    def _calculate_score(self, technique: Dict[str, Any]) -> float:
        """
        Calculate a priority score for an uncovered technique.

        Args:
            technique: Technique dict from get_uncovered_techniques()

        Returns:
            Score between 0 and 100 (higher = higher priority)
        """
        score = 0.0
        technique_id = technique["technique_id"]

        # Get technique info for additional fields
        tech_info = self.mitre_loader.get_technique_info(technique_id)
        if not tech_info:
            logger.warning(f"Could not find technique info for {technique_id}")
            return 0.0

        # Factor 1: Prevalence (0-30 points)
        prevalence = tech_info.get("x_mitre_prevalence")
        if prevalence is not None:
            # Normalize prevalence (typically 0-100) to 0-30 points
            prevalence_score = min(30.0, (prevalence / 100.0) * 30.0)
            score += prevalence_score
            logger.debug(f"Prevalence score for {technique_id}: {prevalence_score}")
        else:
            # Default prevalence score if not available
            score += 15.0  # Middle value
            logger.debug(f"No prevalence data for {technique_id}, using default: 15.0")

        # Factor 2: Exploitability (0-30 points)
        # Check for exploit references or common exploitability indicators
        exploit_score = self._calculate_exploitability_score(tech_info)
        score += exploit_score
        logger.debug(f"Exploitability score for {technique_id}: {exploit_score}")

        # Factor 3: Data Source Availability (0-40 points)
        # Techniques requiring fewer/common data sources are easier to detect = lower priority
        # Techniques requiring many/specialized data sources are harder to detect = higher priority
        ds_score = self._calculate_data_source_score(tech_info)
        score += ds_score
        logger.debug(f"Data source score for {technique_id}: {ds_score}")

        # Ensure score is within 0-100 range
        score = max(0.0, min(100.0, score))
        return score

    def _calculate_exploitability_score(self, tech_info: Dict[str, Any]) -> float:
        """
        Calculate exploitability score based on available exploit information.

        Args:
            tech_info: Technique info dict from MITRE loader

        Returns:
            Score between 0-30
        """
        # Check for external references that might indicate exploits
        external_refs = tech_info.get("external_references", [])
        exploit_indicators = 0

        for ref in external_refs:
            source_name = ref.get("source_name", "").lower()
            url = ref.get("url", "").lower()
            # Look for common exploit databases
            if any(
                keyword in source_name or keyword in url
                for keyword in ["exploit", "metasploit", "exploit-db", "packetstorm"]
            ):
                exploit_indicators += 1

        # Also check for kill chain phases that might indicate exploitability
        kill_chain_phases = tech_info.get("kill_chain_phases", [])
        exploit_phases = [
            phase
            for phase in kill_chain_phases
            if phase.get("phase_name", "").lower() in ["exploitation", "privilege-escalation"]
        ]
        exploit_indicators += len(exploit_phases)

        # Convert to 0-30 scale (assuming max 3 indicators for full score)
        return min(30.0, exploit_indicators * 10.0)

    def _calculate_data_source_score(self, tech_info: Dict[str, Any]) -> float:
        """
        Calculate data source availability score.

        Args:
            tech_info: Technique info dict from MITRE loader

        Returns:
            Score between 0-40 (higher = harder to detect = higher priority)
        """
        # Get data sources required for detection
        data_sources = tech_info.get("x_mitre_data_sources", [])
        if not data_sources:
            # If no data sources specified, assume medium difficulty
            return 20.0

        # Count and evaluate data sources
        # Common/easy data sources get lower weight, specialized/hard get higher weight
        easy_sources = [
            "process", "process_command_line", "process_id", "parent_process",
            "file", "file_name", "file_path", "registry", "registry_key",
            "network_traffic", "network_connection", "dns_query",
            "authentication_log", "user_account", "user_session"
        ]

        hard_sources = [
            "memory", "memory_dump", "api_call", "instruction", "cpu_instruction",
            "hypervisor_introspection", "container_runtime", "virtual_machine_introspection",
            "firmware", "boot_record", "microcode", "tpm", "secure_boot"
        ]

        weight_sum = 0.0
        for ds in data_sources:
            ds_lower = ds.lower()
            if any(easy in ds_lower for easy in easy_sources):
                weight_sum += 1.0  # Easy to monitor
            elif any(hard in ds_lower for hard in hard_sources):
                weight_sum += 3.0  # Hard to monitor
            else:
                weight_sum += 2.0  # Medium difficulty

        # Normalize to 0-40 scale
        # Assume max reasonable weight per data source is 3, and max 10 data sources
        max_possible_weight = len(data_sources) * 3.0
        if max_possible_weight > 0:
            normalized = (weight_sum / max_possible_weight) * 40.0
        else:
            normalized = 20.0  # Default medium

        return min(40.0, normalized)

    def _get_priority_label(self, score: float) -> str:
        """
        Convert numeric score to priority label.

        Args:
            score: Numeric score (0-100)

        Returns:
            Priority label string
        """
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "INFO"