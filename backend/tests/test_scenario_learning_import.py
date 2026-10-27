"""Tests for M6: safe Studio -> Adaptive Learning integration.

Verifies the guarded bridge that appends trusted LearningExample rows for an
evaluated ``training`` dataset while enforcing dataset-role protection, feature-
schema compatibility (phishing stays heuristic-only), trusted ground truth, an
evaluated-first requirement, cross-partition campaign isolation and duplicate
protection. It never trains or activates a model. No LLM, no network.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import Base, SessionLocal, engine
from app.models import Dataset, LearningExample
from app.services.scenario_simulator.compiler import compile_scenario_to_dataset
from app.services.scenario_simulator.evaluator import replay_studio_dataset
from app.services.scenario_simulator.learning_import import (
    LearningImportError,
    evaluate_learning_eligibility,
    import_dataset_learning_examples,
)
from app.services.scenario_simulator.spec import SCENARIO_SPEC_SCHEMA_VERSION, ScenarioSpec


@pytest.fixture(scope="module", autouse=True)
def _create_tables():
    Base.metadata.create_all(bind=engine)
    yield


def _prov():
    return {"generator_version": "scenario-studio-1.0", "source": "deterministic"}


def _port_scan_spec(scenario_id="scn_li_ps", seed=11, role="training"):
    return ScenarioSpec(**{
        "schema_version": SCENARIO_SPEC_SCHEMA_VERSION, "scenario_id": scenario_id,
        "title": "PS learn", "description": "port scan learn", "attack_category": "port_scan",
        "intensity": "high", "duration_seconds": 30, "event_count": 20, "seed": seed,
        "stages": [{"stage_id": "s1", "stage_type": "recon", "description": "scan",
                    "expected_observable_behavior": "many ports"}],
        "entity_templates": [
            {"entity_id": "src1", "kind": "source_ip", "value": "10.0.0.50"},
            {"entity_id": "srcbenign", "kind": "source_ip", "value": "10.0.0.51"},
            {"entity_id": "dst1", "kind": "dest_ip", "value": "192.0.2.10"},
        ],
        "event_templates": [
            {"template_id": "et_atk", "stage_id": "s1", "event_category": "network",
             "time_offset_seconds": 2, "source_ref": "src1", "target_ref": "dst1",
             "features": {"distinct_dest_ports": 18}, "ground_truth_label": 1,
             "ground_truth_source": "ids_signature", "repetition": 18},
            {"template_id": "et_ben", "stage_id": "s1", "event_category": "network",
             "time_offset_seconds": 40, "source_ref": "srcbenign", "target_ref": "dst1",
             "features": {"dest_port": 443, "protocol": "TCP", "severity": 1,
                          "raw_signature": "ET POLICY TLS handshake"},
             "ground_truth_label": 0, "ground_truth_source": "scenario_design", "repetition": 2},
        ],
        "expected_outcomes": [
            {"expected_detection_labels": ["port_scan_detected"], "is_malicious": True,
             "rationale": "distinct ports in window"}],
        "evaluation_objective": "learn scan", "dataset_role": role,
        "generation_provenance": _prov(),
    })


def _phishing_spec(scenario_id="scn_li_ph", seed=44, role="training"):
    return ScenarioSpec(**{
        "schema_version": SCENARIO_SPEC_SCHEMA_VERSION, "scenario_id": scenario_id,
        "title": "PH learn", "description": "phishing learn", "attack_category": "phishing_url",
        "intensity": "medium", "duration_seconds": 60, "event_count": 2, "seed": seed,
        "stages": [{"stage_id": "s1", "stage_type": "initial_access", "description": "click",
                    "expected_observable_behavior": "suspicious url"}],
        "entity_templates": [
            {"entity_id": "src1", "kind": "source_ip", "value": "10.0.0.99"},
            {"entity_id": "u1", "kind": "url", "value": "http://portal-verify.internal-update.invalid/auth"},
        ],
        "event_templates": [
            {"template_id": "et", "stage_id": "s1", "event_category": "phishing",
             "time_offset_seconds": 1, "source_ref": "src1", "target_ref": "u1",
             "features": {"url": "http://portal-verify.internal-update.invalid/auth"},
             "ground_truth_label": 1, "ground_truth_source": "heuristic_policy", "repetition": 1},
        ],
        "expected_outcomes": [
            {"expected_detection_labels": ["phishing_url_detected"], "is_malicious": True,
             "rationale": "deceptive domain"}],
        "evaluation_objective": "learn phishing", "dataset_role": role,
        "generation_provenance": _prov(),
    })


def _cleanup(db):
    ids = [d.id for d in db.query(Dataset).filter(Dataset.scenario_id.like("scn_li_%")).all()]
    if ids:
        db.query(LearningExample).filter(LearningExample.source_simulation.in_(ids)).delete(
            synchronize_session=False
        )
    db.query(Dataset).filter(Dataset.scenario_id.like("scn_li_%")).delete(synchronize_session=False)
    db.commit()


def test_eligible_after_evaluation_and_imports_trusted_examples():
    db = SessionLocal()
    try:
        ds = compile_scenario_to_dataset(_port_scan_spec(), db=db, persist=True)
        replay_studio_dataset(ds.id, db)

        report = evaluate_learning_eligibility(ds.id, db)
        assert report["eligible"] is True, report
        assert report["task_name"] == "port_scan"
        assert report["reasons"] == []

        result = import_dataset_learning_examples(ds.id, db)
        assert result["status"] == "IMPORTED"
        assert result["imported"] >= 1

        rows = db.query(LearningExample).filter(LearningExample.source_simulation == ds.id).all()
        assert rows, "expected learning examples to be created"
        # Labels are trusted design-time values (attack group + benign group both present).
        labels = {r.label for r in rows}
        assert 1 in labels
        assert all(r.task_name == "port_scan" for r in rows)
        assert all(r.trusted_label_source in {"ids_signature", "scenario_design"} for r in rows)
    finally:
        _cleanup(db)
        db.close()


def test_validation_role_is_protected_from_training_import():
    db = SessionLocal()
    try:
        ds = compile_scenario_to_dataset(_port_scan_spec(scenario_id="scn_li_val", role="validation"), db=db, persist=True)
        replay_studio_dataset(ds.id, db)

        report = evaluate_learning_eligibility(ds.id, db)
        assert report["eligible"] is False
        assert any("protected" in r for r in report["reasons"])
        with pytest.raises(LearningImportError):
            import_dataset_learning_examples(ds.id, db)
    finally:
        _cleanup(db)
        db.close()


def test_phishing_is_heuristic_only_and_not_eligible():
    db = SessionLocal()
    try:
        ds = compile_scenario_to_dataset(_phishing_spec(), db=db, persist=True)
        replay_studio_dataset(ds.id, db)

        report = evaluate_learning_eligibility(ds.id, db)
        assert report["eligible"] is False
        assert report["task_name"] is None
        assert any("heuristic-only" in r for r in report["reasons"])
    finally:
        _cleanup(db)
        db.close()


def test_requires_evaluation_before_import():
    db = SessionLocal()
    try:
        ds = compile_scenario_to_dataset(_port_scan_spec(scenario_id="scn_li_noeval"), db=db, persist=True)
        report = evaluate_learning_eligibility(ds.id, db)
        assert report["eligible"] is False
        assert any("not been successfully replayed" in r for r in report["reasons"])
    finally:
        _cleanup(db)
        db.close()


def test_import_is_idempotent():
    db = SessionLocal()
    try:
        ds = compile_scenario_to_dataset(_port_scan_spec(scenario_id="scn_li_dup"), db=db, persist=True)
        replay_studio_dataset(ds.id, db)

        first = import_dataset_learning_examples(ds.id, db)
        assert first["status"] == "IMPORTED"
        count_after_first = db.query(LearningExample).filter(LearningExample.source_simulation == ds.id).count()

        second = import_dataset_learning_examples(ds.id, db)
        assert second["status"] == "ALREADY_IMPORTED"
        assert second["imported"] == 0
        count_after_second = db.query(LearningExample).filter(LearningExample.source_simulation == ds.id).count()
        assert count_after_second == count_after_first
    finally:
        _cleanup(db)
        db.close()


def test_cross_partition_campaign_leakage_is_blocked():
    db = SessionLocal()
    try:
        # Import a training dataset for a campaign (scenario_id).
        train = compile_scenario_to_dataset(
            _port_scan_spec(scenario_id="scn_li_camp", seed=101, role="training"), db=db, persist=True
        )
        replay_studio_dataset(train.id, db)
        import_dataset_learning_examples(train.id, db)

        # A sibling hold-out for the SAME campaign must never be importable.
        held_out = compile_scenario_to_dataset(
            _port_scan_spec(scenario_id="scn_li_camp", seed=202, role="test"), db=db, persist=True
        )
        replay_studio_dataset(held_out.id, db)
        report = evaluate_learning_eligibility(held_out.id, db)
        assert report["eligible"] is False
        assert any("conflicting" in r or "protected" in r for r in report["reasons"])
    finally:
        _cleanup(db)
        db.close()
