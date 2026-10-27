"""End-to-end regression for the Attack Scenario Studio (Milestone 7).

Walks the full "LLM proposes; deterministic services execute" chain over real
HTTP routes with a mocked provider (no network/key), proving every milestone
connects:

    propose -> validate -> compile -> replay -> lifecycle -> learning eligibility
    -> import -> adaptive status.

It asserts the contract guarantees that matter at the seams:
    * the LLM output is only ever a *plan* (a proposal), never written directly;
    * ground truth stays out of observable telemetry;
    * expected-vs-actual comes from trusted design-time labels;
    * only an eligible, evaluated, ML-compatible *training* dataset can import;
    * import feeds the existing adaptive engine without auto-training/activation.
"""

import json
import os
import sys
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database import Base, SessionLocal, engine
from app.models import Dataset, LearningExample
from app.services.scenario_simulator import generator
from app.services.scenario_simulator.spec import SCENARIO_SPEC_SCHEMA_VERSION

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def _create_tables():
    Base.metadata.create_all(bind=engine)
    yield
    db = SessionLocal()
    try:
        ids = [d.id for d in db.query(Dataset).filter(Dataset.scenario_id.like("scn_e2e_%")).all()]
        if ids:
            db.query(LearningExample).filter(LearningExample.source_simulation.in_(ids)).delete(
                synchronize_session=False
            )
        db.query(Dataset).filter(Dataset.scenario_id.like("scn_e2e_%")).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _e2e_spec_dict():
    return {
        "schema_version": SCENARIO_SPEC_SCHEMA_VERSION,
        "scenario_id": "scn_e2e_ps",
        "title": "E2E port scan",
        "description": "Synthetic port scan for the full workflow.",
        "attack_category": "port_scan",
        "intensity": "high",
        "duration_seconds": 30,
        "event_count": 20,
        "seed": 4242,
        "stages": [
            {"stage_id": "s1", "stage_type": "recon", "description": "Scan",
             "expected_observable_behavior": "many distinct ports"},
        ],
        "entity_templates": [
            {"entity_id": "src1", "kind": "source_ip", "value": "10.0.0.50"},
            {"entity_id": "srcbenign", "kind": "source_ip", "value": "10.0.0.51"},
            {"entity_id": "dst1", "kind": "dest_ip", "value": "192.0.2.10"},
        ],
        "event_templates": [
            {"template_id": "et_scan", "stage_id": "s1", "event_category": "network",
             "time_offset_seconds": 5, "source_ref": "src1", "target_ref": "dst1",
             "features": {"distinct_dest_ports": 20}, "ground_truth_label": 1,
             "ground_truth_source": "ids_signature", "repetition": 18},
            {"template_id": "et_ben", "stage_id": "s1", "event_category": "network",
             "time_offset_seconds": 40, "source_ref": "srcbenign", "target_ref": "dst1",
             "features": {"dest_port": 443, "protocol": "TCP", "severity": 1,
                          "raw_signature": "ET POLICY TLS handshake"},
             "ground_truth_label": 0, "ground_truth_source": "scenario_design", "repetition": 2},
        ],
        "expected_outcomes": [
            {"expected_detection_labels": ["port_scan_detected"], "is_malicious": True,
             "rationale": "High port diversity inside the window."},
        ],
        "evaluation_objective": "Confirm scan detection and trusted learning import.",
        "dataset_role": "training",
        "generation_provenance": {"generator_version": "x", "source": "llm"},
    }


def test_full_studio_workflow_end_to_end():
    spec = _e2e_spec_dict()

    # 1. LLM proposes (mocked) -> a validated *plan*, not persisted.
    with patch.object(
        generator, "query_openrouter_messages",
        new=AsyncMock(return_value={"text": json.dumps(spec), "model": "mock"}),
    ):
        prop = client.post(
            "/api/scenario-studio/propose",
            json={"request": "Simulate a synthetic port scan.", "controls": {"dataset_role": "training"}},
        )
    assert prop.status_code == 200
    assert prop.json()["status"] == "ready"
    proposed = prop.json()["spec"]
    assert proposed["dataset_role"] == "training"

    # 2. Validate the (possibly edited) plan again before any persistence.
    val = client.post("/api/scenario-studio/validate", json={"spec": proposed})
    assert val.status_code == 200
    assert val.json()["valid"] is True

    # 3. Compile the validated plan into a persisted, replayable dataset.
    comp = client.post("/api/scenario-studio/compile", json={"spec": proposed})
    assert comp.status_code == 200
    dataset_id = comp.json()["dataset_id"]
    assert comp.json()["dataset_role"] == "training"
    assert comp.json()["ground_truth_available"] is True

    # 4. Replay through the real detectors and score expected vs actual.
    rep = client.post(f"/api/scenario-studio/datasets/{dataset_id}/replay")
    assert rep.status_code == 200
    body = rep.json()
    assert "port_scan_detected" in body["true_positive_labels"]
    assert body["metrics"]["recall"] == 1.0

    # 5. Lifecycle explorer: five separated layers, no label leak into telemetry.
    lc = client.get(f"/api/scenario-studio/datasets/{dataset_id}/lifecycle")
    assert lc.status_code == 200
    life = lc.json()
    for key in ("provenance", "layer_plan", "layer_telemetry", "layer_ground_truth", "layer_detections", "layer_evaluation"):
        assert key in life
    for ev in life["layer_telemetry"]["events"]:
        assert "ground_truth_label" not in ev and "expected_detection_labels" not in ev

    # 6. Learning eligibility: an evaluated, trusted, ML-compatible training set.
    elig = client.get(f"/api/scenario-studio/datasets/{dataset_id}/learning-eligibility")
    assert elig.status_code == 200
    assert elig.json()["eligible"] is True, elig.json()
    assert elig.json()["task_name"] == "port_scan"

    # 7. Adaptive status baseline (before import).
    status_before = client.get("/api/ml/status", params={"task_name": "port_scan"}).json()
    total_before = status_before["total_examples"]

    # 8. Import trusted examples into the existing learning pool.
    imp = client.post(f"/api/scenario-studio/datasets/{dataset_id}/import-learning")
    assert imp.status_code == 200
    assert imp.json()["status"] == "IMPORTED"
    assert imp.json()["imported"] >= 1

    # 9. Adaptive status now reflects the newly imported examples (no auto-train).
    status_after = client.get("/api/ml/status", params={"task_name": "port_scan"}).json()
    assert status_after["total_examples"] > total_before
    assert status_after["status"] in {"NOT_READY", "INSUFFICIENT_CLASSES", "NEW_DATA_AVAILABLE", "READY_FOR_TRAINING", "NO_NEW_DATA"}

    # 10. Imported rows carry trusted design-time label sources, never detector output.
    db = SessionLocal()
    try:
        rows = db.query(LearningExample).filter(LearningExample.source_simulation == dataset_id).all()
        assert rows
        assert {r.trusted_label_source for r in rows} <= {"ids_signature", "scenario_design"}
        assert 1 in {r.label for r in rows}
    finally:
        db.close()


def test_import_rejects_validation_role_dataset_end_to_end():
    spec = _e2e_spec_dict()
    spec["scenario_id"] = "scn_e2e_val"
    spec["dataset_role"] = "validation"

    comp = client.post("/api/scenario-studio/compile", json={"spec": spec})
    assert comp.status_code == 200
    dataset_id = comp.json()["dataset_id"]
    client.post(f"/api/scenario-studio/datasets/{dataset_id}/replay")

    elig = client.get(f"/api/scenario-studio/datasets/{dataset_id}/learning-eligibility")
    assert elig.json()["eligible"] is False
    assert any("protected" in r for r in elig.json()["reasons"])

    imp = client.post(f"/api/scenario-studio/datasets/{dataset_id}/import-learning")
    assert imp.status_code == 409
