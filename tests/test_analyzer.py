"""Unit tests for the MITRE ATT&CK Coverage Gap Analyzer."""

import json
import tempfile
from pathlib import Path

from mitre_gap_analyzer.mitre_loader import MITRELoader
from mitre_gap_analyzer.coverage_loader import CoverageLoader
from mitre_gap_analyzer.gap_engine import GapEngine
from mitre_gap_analyzer.scoring_engine import ScoringEngine


def test_mitre_loader():
    """Test MITRE loader with sample data."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        # Copy test data to temp file
        test_data = Path("tests/test_mitre_sample.json").read_text()
        f.write(test_data)
        temp_path = Path(f.name)

    try:
        loader = MITRELoader(temp_path)
        data = loader.load()

        # Check that we have tactics
        assert "initial-access" in data
        assert "execution" in data
        assert "persistence" in data
        assert "privilege-escalation" in data

        # Check technique counts
        initial_access = data["initial-access"]
        # Should have T1078 (parent) and its sub-techniques T1078.001, T1078.002
        technique_ids = [t["technique_id"] for t in initial_access]
        assert "attack-pattern--1" in technique_ids  # T1078
        assert "attack-pattern--2" in technique_ids  # T1078.001
        assert "attack-pattern--3" in technique_ids  # T1078.002

        # Check sub-technique mapping
        t1078 = next(t for t in initial_access if t["technique_id"] == "attack-pattern--1")
        assert set(t1078["sub_technique_ids"]) == {"attack-pattern--2", "attack-pattern--3"}

        print("✓ MITRE loader test passed")
    finally:
        temp_path.unlink()


def test_coverage_loader():
    """Test coverage loader with CSV data."""
    # Need MITRE loader to map technique IDs to STIX IDs
    mitre_loader = MITRELoader(Path("tests/test_mitre_sample.json"))
    mitre_loader.load()

    loader = CoverageLoader(Path("tests/test_coverage.csv"))
    coverage = loader.load(mitre_loader)

    # Check that we have the expected tactics
    assert "initial-access" in coverage
    assert "persistence" in coverage

    # Check covered techniques
    initial_access_covered = coverage["initial-access"]
    assert "attack-pattern--1" in initial_access_covered  # T1078
    assert "attack-pattern--2" in initial_access_covered  # T1078.001
    assert "attack-pattern--3" in initial_access_covered  # T1078.002

    persistence_covered = coverage["persistence"]
    assert "attack-pattern--4" in persistence_covered  # T1547.001
    # T1547 (attack-pattern--5) is not covered in the test CSV

    print("✓ Coverage loader test passed")


def test_gap_engine():
    """Test gap engine with sample data."""
    # Load MITRE data
    mitre_loader = MITRELoader(Path("tests/test_mitre_sample.json"))
    mitre_data = mitre_loader.load()

    # Load coverage data
    coverage_loader = CoverageLoader(Path("tests/test_coverage.csv"))
    coverage_data = coverage_loader.load(mitre_loader)

    # Run gap analysis
    gap_engine = GapEngine(mitre_loader, coverage_loader)
    results = gap_engine.analyze()

    # Check overall results
    assert results["total_techniques"] > 0
    assert results["covered_techniques"] >= 0
    assert results["uncovered_techniques"] >= 0
    assert results["overall_coverage"] >= 0.0
    assert results["overall_coverage"] <= 100.0

    # Check tactic results
    assert len(results["tactics"]) == 4  # initial-access, execution, persistence, privilege-escalation

    # Find initial-access tactic result
    ia_result = next(t for t in results["tactics"] if t["tactic_shortname"] == "initial-access")
    # Should have 3 techniques total (T1078 + 2 sub-techniques)
    assert ia_result["total_techniques"] == 3
    # Should have all 3 covered based on our coverage data
    assert ia_result["covered_techniques"] == 3
    assert ia_result["uncovered_techniques"] == 0
    assert ia_result["coverage_percentage"] == 100.0

    # Find persistence tactic result
    pers_result = next(t for t in results["tactics"] if t["tactic_shortname"] == "persistence")
    # Should have 5 techniques total (T1078 + 2 sub-techniques + T1547 + 1 sub-technique)
    assert pers_result["total_techniques"] == 5
    # Should have 1 covered (T1547.001) based on our coverage data
    assert pers_result["covered_techniques"] == 1
    assert pers_result["uncovered_techniques"] == 4
    assert pers_result["coverage_percentage"] == 20.0  # 1/5 * 100

    print("✓ Gap engine test passed")


def test_scoring_engine():
    """Test scoring engine with sample data."""
    # Load data
    mitre_loader = MITRELoader(Path("tests/test_mitre_sample.json"))
    mitre_loader.load()

    coverage_loader = CoverageLoader(Path("tests/test_coverage.csv"))
    coverage_loader.load(mitre_loader)

    # Run gap analysis
    gap_engine = GapEngine(mitre_loader, coverage_loader)
    results = gap_engine.analyze()

    # Score uncovered techniques
    scoring_engine = ScoringEngine(mitre_loader, gap_engine)
    scored = scoring_engine.score_uncovered_techniques()

    # With our test data, we expect 12 uncovered techniques
    # initial-access: 3/3 covered (0 uncovered)
    # execution: 0/3 covered (3 uncovered: T1078, T1078.001, T1078.002)
    # persistence: 1/5 covered (4 uncovered: T1078, T1078.001, T1078.002, T1547)
    # privilege-escalation: 0/5 covered (5 uncovered: T1078, T1078.001, T1078.002, T1547, T1547.001)
    assert len(scored) == 12

    # Verify all scored techniques have scores and priorities
    for tech in scored:
        assert "score" in tech
        assert 0 <= tech["score"] <= 100
        assert "priority" in tech
        assert tech["priority"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    print("✓ Scoring engine test passed")


if __name__ == "__main__":
    test_mitre_loader()
    test_coverage_loader()
    test_gap_engine()
    test_scoring_engine()
    print("\n✅ All tests passed!")