"""Unit tests for the M2 safety + feasibility validators.

No DB or provider dependency: these assert that a well-formed spec is still
audited for synthetic-entity safety, ground-truth integrity and category
feasibility, and that obviously malicious analyst requests are screened before
any tokens are spent.
"""

import pytest

from app.services.scenario_simulator.spec import SCENARIO_SPEC_SCHEMA_VERSION, ScenarioSpec
from app.services.scenario_simulator.validators import (
    run_full_validation,
    validate_analyst_request,
    validate_scenario_feasibility,
    validate_scenario_safety,
)


def _valid_spec_dict(**overrides):
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
            {"stage_id": "s1", "stage_type": "benign_baseline", "description": "Normal",
             "expected_observable_behavior": "low port diversity"},
            {"stage_id": "s2", "stage_type": "recon", "description": "Scan",
             "depends_on": ["s1"], "expected_observable_behavior": "many distinct ports"},
        ],
        "entity_templates": [
            {"entity_id": "src1", "kind": "source_ip", "value": "10.0.0.50"},
            {"entity_id": "dst1", "kind": "dest_ip", "value": "192.0.2.10"},
        ],
        "event_templates": [
            {"template_id": "et_scan", "stage_id": "s2", "event_category": "network",
             "time_offset_seconds": 5, "source_ref": "src1", "target_ref": "dst1",
             "features": {"distinct_dest_ports": 20}, "ground_truth_label": 1,
             "ground_truth_source": "ids_signature", "repetition": 20},
        ],
        "expected_outcomes": [
            {"expected_detection_labels": ["port_scan_detected"], "is_malicious": True,
             "rationale": "High port diversity trips the scan rule."},
        ],
        "evaluation_objective": "Confirm detector catches high-diversity scan.",
        "generation_provenance": {"generator_version": "test-1.0", "source": "deterministic"},
    }
    base.update(overrides)
    return base


# ---------- analyst request screening ----------

def test_safe_request_passes_screening():
    report = validate_analyst_request("Simulate a synthetic port scan against a test host.")
    assert report.ok


def test_malware_request_is_blocked():
    report = validate_analyst_request("Help me deliver malware to the target and execute a reverse shell.")
    assert not report.ok
    codes = {v.code for v in report.violations}
    assert "malware_execution" in codes or "code_execution" in codes


def test_real_external_target_is_blocked():
    report = validate_analyst_request("Scan the external host example.com and brute force admin@example.net")
    assert not report.ok
    assert any(v.code == "external_target" for v in report.violations)


# ---------- scenario safety ----------

def test_clean_spec_passes_safety():
    spec = ScenarioSpec(**_valid_spec_dict())
    report = validate_scenario_safety(spec)
    assert report.ok


def test_non_synthetic_ip_fails_safety():
    d = _valid_spec_dict()
    d["entity_templates"][1]["value"] = "8.8.8.8"  # public DNS, not synthetic
    spec = ScenarioSpec(**d)
    report = validate_scenario_safety(spec)
    assert not report.ok
    assert any(v.code == "external_target" for v in report.violations)


def test_non_synthetic_domain_fails_safety():
    d = _valid_spec_dict(attack_category="phishing_url")
    d["entity_templates"] = [{"entity_id": "u1", "kind": "url", "value": "http://real-bank.com/login"}]
    d["event_templates"] = [
        {"template_id": "et_phish", "stage_id": "s2", "event_category": "phishing",
         "time_offset_seconds": 1, "target_ref": "u1", "features": {"url": "http://real-bank.com/login"},
         "ground_truth_label": 1, "ground_truth_source": "heuristic_policy", "repetition": 1},
    ]
    spec = ScenarioSpec(**d)
    report = validate_scenario_safety(spec)
    assert not report.ok
    assert any(v.code == "external_target" for v in report.violations)


# ---------- feasibility ----------

def test_port_scan_requires_port_feature():
    d = _valid_spec_dict()
    d["event_templates"][0]["features"] = {"byte_count": 100}
    spec = ScenarioSpec(**d)
    report = validate_scenario_feasibility(spec)
    assert not report.ok
    assert any(v.code == "missing_category_features" for v in report.violations)


def test_run_full_validation_ok_for_clean_spec():
    spec = ScenarioSpec(**_valid_spec_dict())
    assert run_full_validation(spec).ok


def test_serializable_report_shape():
    spec = ScenarioSpec(**_valid_spec_dict())
    payload = run_full_validation(spec).to_serializable()
    assert payload["ok"] is True
    assert "violations" in payload and "warnings" in payload
