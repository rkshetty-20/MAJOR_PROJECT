"""Tests for the M4 Studio replay + expected-vs-actual evaluation.

Exercises the real detection engines end-to-end on compiled datasets:
compiled telemetry -> correct event tables -> rule/ML detections -> comparison
against the spec's trusted expected labels. No LLM, no network.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import Base, SessionLocal, engine
from app.models import Dataset, EvaluationRun
from app.services.scenario_simulator.compiler import compile_scenario_to_dataset
from app.services.scenario_simulator.evaluator import ReplayError, replay_studio_dataset
from app.services.scenario_simulator.spec import SCENARIO_SPEC_SCHEMA_VERSION, ScenarioSpec


@pytest.fixture(scope="module", autouse=True)
def _create_tables():
    Base.metadata.create_all(bind=engine)
    yield


def _prov():
    return {"generator_version": "scenario-studio-1.0", "source": "deterministic"}


def _port_scan_spec():
    return ScenarioSpec(**{
        "schema_version": SCENARIO_SPEC_SCHEMA_VERSION, "scenario_id": "scn_ev_ps",
        "title": "PS eval", "description": "port scan eval", "attack_category": "port_scan",
        "intensity": "high", "duration_seconds": 30, "event_count": 20, "seed": 11,
        "stages": [{"stage_id": "s1", "stage_type": "recon", "description": "scan",
                    "expected_observable_behavior": "many ports"}],
        "entity_templates": [
            {"entity_id": "src1", "kind": "source_ip", "value": "10.0.0.50"},
            {"entity_id": "dst1", "kind": "dest_ip", "value": "192.0.2.10"},
        ],
        "event_templates": [
            {"template_id": "et", "stage_id": "s1", "event_category": "network",
             "time_offset_seconds": 2, "source_ref": "src1", "target_ref": "dst1",
             "features": {"distinct_dest_ports": 18}, "ground_truth_label": 1,
             "ground_truth_source": "ids_signature", "repetition": 18},
        ],
        "expected_outcomes": [
            {"expected_detection_labels": ["port_scan_detected"], "is_malicious": True,
             "rationale": "distinct ports in window"}],
        "evaluation_objective": "detect scan", "generation_provenance": _prov(),
    })


def _credential_stuffing_spec():
    return ScenarioSpec(**{
        "schema_version": SCENARIO_SPEC_SCHEMA_VERSION, "scenario_id": "scn_ev_cs",
        "title": "CS eval", "description": "credential stuffing eval", "attack_category": "credential_stuffing",
        "intensity": "high", "duration_seconds": 60, "event_count": 8, "seed": 22,
        "stages": [{"stage_id": "s1", "stage_type": "initial_access", "description": "spray",
                    "expected_observable_behavior": "many accounts"}],
        "entity_templates": [{"entity_id": "src1", "kind": "source_ip", "value": "203.0.113.88"}],
        "event_templates": [
            {"template_id": "et", "stage_id": "s1", "event_category": "auth",
             "time_offset_seconds": 10, "source_ref": "src1",
             "features": {"event_type": "failed_authentication"}, "ground_truth_label": 1,
             "ground_truth_source": "scenario_design", "repetition": 8},
        ],
        "expected_outcomes": [
            {"expected_detection_labels": ["credential_stuffing_detected"], "is_malicious": True,
             "rationale": "many accounts one source"}],
        "evaluation_objective": "detect stuffing", "generation_provenance": _prov(),
    })


def _brute_force_spec():
    return ScenarioSpec(**{
        "schema_version": SCENARIO_SPEC_SCHEMA_VERSION, "scenario_id": "scn_ev_bf",
        "title": "BF eval", "description": "brute force eval", "attack_category": "brute_force",
        "intensity": "high", "duration_seconds": 60, "event_count": 8, "seed": 33,
        "stages": [{"stage_id": "s1", "stage_type": "initial_access", "description": "guess",
                    "expected_observable_behavior": "fail burst then success"}],
        "entity_templates": [
            {"entity_id": "src1", "kind": "source_ip", "value": "198.51.100.25"},
            {"entity_id": "acct", "kind": "target_account", "value": "svc_account"},
        ],
        "event_templates": [
            {"template_id": "et_fail", "stage_id": "s1", "event_category": "auth",
             "time_offset_seconds": 0, "source_ref": "src1", "target_ref": "acct",
             "features": {"event_type": "failed_login"}, "ground_truth_label": 1,
             "ground_truth_source": "scenario_design", "repetition": 6},
            {"template_id": "et_ok", "stage_id": "s1", "event_category": "auth",
             "time_offset_seconds": 12, "source_ref": "src1", "target_ref": "acct",
             "features": {"event_type": "successful_login"}, "ground_truth_label": 1,
             "ground_truth_source": "scenario_design", "repetition": 1},
        ],
        "expected_outcomes": [
            {"expected_detection_labels": ["brute_force_detected"], "is_malicious": True,
             "rationale": "fail burst then success on same account"}],
        "evaluation_objective": "detect brute force", "generation_provenance": _prov(),
    })


def _phishing_spec():
    return ScenarioSpec(**{
        "schema_version": SCENARIO_SPEC_SCHEMA_VERSION, "scenario_id": "scn_ev_ph",
        "title": "PH eval", "description": "phishing eval", "attack_category": "phishing_url",
        "intensity": "medium", "duration_seconds": 60, "event_count": 2, "seed": 44,
        "stages": [{"stage_id": "s1", "stage_type": "initial_access", "description": "click",
                    "expected_observable_behavior": "suspicious url"}],
        "entity_templates": [
            {"entity_id": "u1", "kind": "url",
             "value": "http://portal-verify.internal-update.invalid/auth/login"},
        ],
        "event_templates": [
            {"template_id": "et", "stage_id": "s1", "event_category": "phishing",
             "time_offset_seconds": 1, "target_ref": "u1",
             "features": {"url": "http://portal-verify.internal-update.invalid/auth/login"},
             "ground_truth_label": 1, "ground_truth_source": "heuristic_policy", "repetition": 1},
        ],
        "expected_outcomes": [
            {"expected_detection_labels": ["phishing_url_detected"], "is_malicious": True,
             "rationale": "deceptive domain"}],
        "evaluation_objective": "detect phishing", "generation_provenance": _prov(),
    })


def _false_negative_spec():
    spec = _port_scan_spec()
    # Same scan, but claim an expected label that no detector will ever emit,
    # under a distinct scenario_id so it does not collide with the real scan row.
    object.__setattr__(spec, "scenario_id", "scn_ev_fn")
    object.__setattr__(spec, "seed", 999)
    object.__setattr__(spec.expected_outcomes[0], "expected_detection_labels", ["totally_unexpected_label"])
    return spec


@pytest.mark.parametrize(
    "factory,expected_label",
    [
        (_port_scan_spec, "port_scan_detected"),
        (_credential_stuffing_spec, "credential_stuffing_detected"),
        (_brute_force_spec, "brute_force_detected"),
        (_phishing_spec, "phishing_url_detected"),
    ],
)
def test_replay_detects_expected(factory, expected_label):
    db = SessionLocal()
    try:
        ds = compile_scenario_to_dataset(factory(), db=db, persist=True)
        result = replay_studio_dataset(ds.id, db)
        assert expected_label in result["actual_labels"], result
        assert expected_label in result["true_positive_labels"]
        assert result["metrics"]["recall"] == 1.0
        run = db.query(EvaluationRun).filter(EvaluationRun.id == result["eval_run_id"]).first()
        assert run.status == "completed"
    finally:
        db.query(Dataset).filter(Dataset.scenario_id.like("scn_ev_%")).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_replay_records_false_negative():
    db = SessionLocal()
    try:
        ds = compile_scenario_to_dataset(_port_scan_spec(), db=db, persist=True)
        # Recompile using a spec whose expectation cannot be satisfied.
        ds2 = compile_scenario_to_dataset(_false_negative_spec(), db=db, persist=True)
        result = replay_studio_dataset(ds2.id, db)
        # port_scan still detected (true scan), but the bogus expectation is a miss.
        assert "totally_unexpected_label" in result["false_negative_labels"]
        assert "port_scan_detected" in result["actual_labels"]
    finally:
        db.query(Dataset).filter(Dataset.scenario_id.like("scn_ev_%")).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_replay_rejects_non_studio_dataset():
    db = SessionLocal()
    try:
        ds = Dataset(id="ds_legacy_probe", schema_version="1.0", scenario_category="port_scan",
                     events_count=0, payload_json="[]", scenario_spec_json=None)
        db.add(ds)
        db.commit()
        with pytest.raises(ReplayError):
            replay_studio_dataset(ds.id, db)
    finally:
        db.query(Dataset).filter(Dataset.id == "ds_legacy_probe").delete(synchronize_session=False)
        db.commit()
        db.close()
