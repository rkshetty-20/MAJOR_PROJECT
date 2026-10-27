"""Unit tests for the versioned scenario specification schema (Milestone 1).

These validate the strict contract the LLM/deterministic generator must satisfy
before any telemetry is compiled. No DB or provider dependency.
"""

import pytest
from pydantic import ValidationError

from app.services.scenario_simulator.spec import (
    SCENARIO_SPEC_SCHEMA_VERSION,
    AttackCategory,
    EventCategory,
    GroundTruthSource,
    ScenarioSpec,
    is_supported_category,
)


def _provenance():
    return {
        "generator_version": "test-1.0",
        "source": "deterministic",
    }


def _valid_spec(**overrides):
    base = {
        "schema_version": SCENARIO_SPEC_SCHEMA_VERSION,
        "scenario_id": "scn_port_scan_001",
        "title": "Port scan with benign baseline",
        "description": "Recon port scan preceded by normal traffic.",
        "attack_category": "port_scan",
        "intensity": "medium",
        "duration_seconds": 60,
        "event_count": 20,
        "seed": 42,
        "stages": [
            {
                "stage_id": "s1",
                "stage_type": "benign_baseline",
                "description": "Normal host traffic",
                "expected_observable_behavior": "low port diversity",
            },
            {
                "stage_id": "s2",
                "stage_type": "recon",
                "description": "Port scan burst",
                "depends_on": ["s1"],
                "expected_observable_behavior": "many distinct dest ports",
            },
        ],
        "entity_templates": [
            {"entity_id": "src1", "kind": "source_ip", "value": "10.0.0.50"},
            {"entity_id": "dst1", "kind": "dest_ip", "value": "10.0.0.10"},
        ],
        "event_templates": [
            {
                "template_id": "et_benign",
                "stage_id": "s1",
                "event_category": "network",
                "time_offset_seconds": 0,
                "source_ref": "src1",
                "target_ref": "dst1",
                "features": {"distinct_dest_ports": 2},
                "ground_truth_label": 0,
                "ground_truth_source": "ids_signature",
                "repetition": 4,
            },
            {
                "template_id": "et_scan",
                "stage_id": "s2",
                "event_category": "network",
                "time_offset_seconds": 5,
                "source_ref": "src1",
                "target_ref": "dst1",
                "features": {"distinct_dest_ports": 20},
                "ground_truth_label": 1,
                "ground_truth_source": "ids_signature",
                "repetition": 16,
            },
        ],
        "expected_outcomes": [
            {
                "expected_detection_labels": ["port_scan_detected"],
                "is_malicious": True,
                "rationale": "20 distinct ports within window should trip the scan rule.",
            }
        ],
        "evaluation_objective": "Confirm detector catches high port-diversity scan.",
        "generation_provenance": _provenance(),
    }
    base.update(overrides)
    return base


def test_valid_spec_accepted():
    spec = ScenarioSpec(**_valid_spec())
    assert spec.attack_category == AttackCategory.PORT_SCAN
    assert is_supported_category("port_scan")


def test_unknown_attack_category_rejected():
    with pytest.raises(ValidationError):
        ScenarioSpec(**_valid_spec(attack_category="ddos"))


def test_excessive_event_count_rejected():
    with pytest.raises(ValidationError):
        ScenarioSpec(**_valid_spec(event_count=5000))


def test_missing_required_field_rejected():
    bad = _valid_spec()
    del bad["evaluation_objective"]
    with pytest.raises(ValidationError):
        ScenarioSpec(**bad)


def test_unknown_field_rejected_strict():
    bad = _valid_spec()
    bad["shell_payload"] = "rm -rf /"
    with pytest.raises(ValidationError):
        ScenarioSpec(**bad)


def test_invalid_entity_reference_rejected():
    bad = _valid_spec()
    bad["event_templates"][1]["source_ref"] = "does_not_exist"
    with pytest.raises(ValidationError):
        ScenarioSpec(**bad)


def test_invalid_stage_reference_rejected():
    bad = _valid_spec()
    bad["event_templates"][0]["stage_id"] = "ghost_stage"
    with pytest.raises(ValidationError):
        ScenarioSpec(**bad)


def test_cyclic_stage_dependency_rejected():
    bad = _valid_spec()
    bad["stages"] = [
        {"stage_id": "a", "stage_type": "recon", "description": "d",
         "depends_on": ["b"], "expected_observable_behavior": "x"},
        {"stage_id": "b", "stage_type": "recon", "description": "d",
         "depends_on": ["a"], "expected_observable_behavior": "x"},
    ]
    # Repoint event templates at an existing stage to isolate the cycle check.
    with pytest.raises(ValidationError):
        ScenarioSpec(**bad)


def test_misrouted_event_category_rejected():
    """Phishing events must not be emitted by a port_scan scenario."""
    bad = _valid_spec()
    bad["event_templates"][0]["event_category"] = EventCategory.PHISHING.value
    with pytest.raises(ValidationError):
        ScenarioSpec(**bad)


def test_repetition_exceeding_event_count_rejected():
    bad = _valid_spec(event_count=5)
    # template repetitions still total 20 (>5)
    with pytest.raises(ValidationError):
        ScenarioSpec(**bad)


def test_training_role_rejects_unverified_ground_truth():
    bad = _valid_spec(dataset_role="training")
    bad["event_templates"][0]["ground_truth_source"] = GroundTruthSource.UNVERIFIED.value
    with pytest.raises(ValidationError):
        ScenarioSpec(**bad)


def test_wrong_schema_version_rejected():
    with pytest.raises(ValidationError):
        ScenarioSpec(**_valid_spec(schema_version="9.9"))
