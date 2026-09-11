"""MITRE ATT&CK STIX JSON loader."""

import json
import logging
from pathlib import Path
from typing import Dict, List, Set, Any, Optional

logger = logging.getLogger(__name__)


class MITRELoader:
    """Loads and parses MITRE ATT&CK STIX 2.1 JSON."""

    def __init__(self, mitre_path: Optional[Path] = None):
        """
        Initialize the loader.

        Args:
            mitre_path: Path to the MITRE ATT&CK STIX JSON file.
                        If None, uses the default path ./data/enterprise-attack.json
                        relative to the current working directory.
        """
        if mitre_path is None:
            mitre_path = Path("./data/enterprise-attack.json")
        self.mitre_path = mitre_path
        self._techniques: Dict[str, Dict[str, Any]] = {}
        self._tactics: Dict[str, Dict[str, Any]] = {}
        self._external_id_to_stix: Dict[str, str] = {}
        self._is_loaded = False

    def load(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Load and parse the MITRE ATT&CK STIX JSON.

        Returns:
            A dictionary mapping tactic shortname to a list of techniques,
            where each technique is a dict with:
                - technique_id: str
                - technique_name: str
                - sub_technique_ids: List[str]
        """
        if self._is_loaded:
            return self._build_internal_structure()

        logger.info(f"Loading MITRE ATT&CK data from {self.mitre_path}")
        if not self.mitre_path.exists():
            raise FileNotFoundError(f"MITRE ATT&CK file not found: {self.mitre_path}")

        with open(self.mitre_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Parse objects
        for obj in data.get("objects", []):
            obj_type = obj.get("type")
            if obj_type == "x-mitre-tactic":
                self._parse_tactic(obj)
            elif obj_type == "attack-pattern":
                self._parse_technique(obj)

        # Ensure all tactics referenced in techniques are present in self._tactics
        self._ensure_all_referenced_tactics()

        # Build tactic -> technique_ids mapping
        self._map_techniques_to_tactics()

        self._is_loaded = True
        return self._build_internal_structure()

    def _parse_tactic(self, tactic: Dict[str, Any]) -> None:
        """Parse a tactic object."""
        tactic_id = tactic.get("id")
        name = tactic.get("name", "")
        shortname = tactic.get("shortname", "")
        if not shortname:
            # Fallback to id if shortname missing
            shortname = tactic_id
        self._tactics[shortname] = {
            "id": tactic_id,
            "name": name,
            "shortname": shortname,
            "technique_ids": set(),
        }
        logger.debug(f"Parsed tactic: {shortname} ({name})")

    def _parse_technique(self, technique: Dict[str, Any]) -> None:
        """Parse a technique or sub-technique object."""
        tech_id = technique.get("id")
        name = technique.get("name", "")
        is_subtechnique = technique.get("x_mitre_is_subtechnique", False)
        parent = technique.get("x_mitre_parent")
        tactics = technique.get("x_mitre_tactic", [])

        self._techniques[tech_id] = {
            "id": tech_id,
            "name": name,
            "is_subtechnique": is_subtechnique,
            "parent": parent,
            "tactics": tactics,
        }
        # Map from external_id (e.g., T1078) to STIX ID for easy lookup by coverage maps
        for ref in technique.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                external_id = ref.get("external_id")
                if external_id:
                    self._external_id_to_stix[external_id] = tech_id

        logger.debug(
            f"Parsed {'sub-technique' if is_subtechnique else 'technique'}: {tech_id} ({name})"
        )

    def _ensure_all_referenced_tactics(self) -> None:
        """Ensure that all tactics referenced in techniques are present in self._tactics."""
        referenced_tactics = set()
        for tech in self._techniques.values():
            for tactic in tech.get("tactics", []):
                referenced_tactics.add(tactic)
        for tactic_shortname in referenced_tactics:
            if tactic_shortname not in self._tactics:
                # Create a minimal tactic entry
                self._tactics[tactic_shortname] = {
                    "id": f"x-mitre-tactic--{len(self._tactics)+1}",  # dummy ID
                    "name": tactic_shortname.replace("-", " ").title(),
                    "shortname": tactic_shortname,
                    "technique_ids": set(),
                }
                logger.warning(
                    f"Created missing tactic: {tactic_shortname}"
                )

    def get_technique_stix_id(self, external_id: str) -> Optional[str]:
        """
        Get the STIX ID for a given external ID (e.g., T1078).

        Args:
            external_id: The external ID (e.g., T1078).

        Returns:
            The STIX ID (e.g., attack-pattern--1) if found, else None.
        """
        return self._external_id_to_stix.get(external_id)

    def _map_techniques_to_tactics(self) -> None:
        """Map each technique to its tactics."""
        for tech_id, tech in self._techniques.items():
            for tactic_shortname in tech["tactics"]:
                if tactic_shortname in self._tactics:
                    self._tactics[tactic_shortname]["technique_ids"].add(tech_id)
                else:
                    logger.warning(
                        f"Tactic {tactic_shortname} referenced by technique {tech_id} not found"
                    )

    def _build_internal_structure(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Build the internal structure as per SPEC:
        {tactic: [{technique_id, technique_name, sub_technique_ids...}]}
        """
        internal: Dict[str, List[Dict[str, Any]]] = {}
        for tactic_shortname, tactic_info in self._tactics.items():
            technique_list = []
            for tech_id in tactic_info["technique_ids"]:
                tech = self._techniques[tech_id]
                # Find sub-techniques of this technique that are under this tactic
                sub_technique_ids = []
                for sub_id, sub_tech in self._techniques.items():
                    if (
                        sub_tech.get("parent") == tech_id
                        and tactic_shortname in sub_tech["tactics"]
                    ):
                        sub_technique_ids.append(sub_id)
                technique_list.append(
                    {
                        "technique_id": tech_id,
                        "technique_name": tech["name"],
                        "sub_technique_ids": sub_technique_ids,
                    }
                )
            internal[tactic_shortname] = technique_list
        return internal

    def get_technique_info(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific technique."""
        return self._techniques.get(technique_id)

    def get_tactic_info(self, tactic_shortname: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific tactic."""
        return self._tactics.get(tactic_shortname)

    def get_all_technique_ids(self) -> Set[str]:
        """Get all technique IDs (including sub-techniques)."""
        return set(self._techniques.keys())

    def get_all_tactic_shortnames(self) -> Set[str]:
        """Get all tactic shortnames."""
        return set(self._tactics.keys())