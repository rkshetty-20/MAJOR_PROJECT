"""HTTP contract tests for the Attack Scenario Studio router (M2).

Uses TestClient with a mocked provider so no network/key is required. Verifies:
    * GET /categories lists the supported detector routing;
    * POST /propose screens an unsafe request without calling the provider;
    * POST /propose returns a validated spec on a good proposal;
    * POST /propose maps provider failure to an honest 503 + fallback hint;
    * POST /validate re-checks an analyst-edited spec.
"""

import json
import os
import sys
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database import Base, engine
from app.services.scenario_simulator import generator
from app.services.scenario_simulator.generator import ProviderUnavailableError
from app.services.scenario_simulator.spec import SCENARIO_SPEC_SCHEMA_VERSION

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def _create_tables():
    Base.metadata.create_all(bind=engine)
    yield
    from app.models import Dataset
    db = None
    try:
        from app.database import SessionLocal
        db = SessionLocal()
        db.query(Dataset).filter(Dataset.scenario_id.like("scn_api_%")).delete(synchronize_session=False)
        db.commit()
    finally:
        if db is not None:
            db.close()


def _valid_spec_dict():
    return {
        "schema_version": SCENARIO_SPEC_SCHEMA_VERSION,
        "scenario_id": "scn_api_001",
        "title": "API port scan",
        "description": "Synthetic port scan.",
        "attack_category": "port_scan",
        "intensity": "medium",
        "duration_seconds": 60,
        "event_count": 20,
        "seed": 7,
        "stages": [
            {"stage_id": "s1", "stage_type": "recon", "description": "Scan",
             "expected_observable_behavior": "many ports"},
        ],
        "entity_templates": [
            {"entity_id": "src1", "kind": "source_ip", "value": "10.0.0.50"},
            {"entity_id": "dst1", "kind": "dest_ip", "value": "192.0.2.10"},
        ],
        "event_templates": [
            {"template_id": "et_scan", "stage_id": "s1", "event_category": "network",
             "time_offset_seconds": 5, "source_ref": "src1", "target_ref": "dst1",
             "features": {"distinct_dest_ports": 20}, "ground_truth_label": 1,
             "ground_truth_source": "ids_signature", "repetition": 20},
        ],
        "expected_outcomes": [
            {"expected_detection_labels": ["port_scan_detected"], "is_malicious": True,
             "rationale": "High port diversity."},
        ],
        "evaluation_objective": "Confirm scan detection.",
        "generation_provenance": {"generator_version": "x", "source": "llm"},
    }


def test_categories_endpoint():
    res = client.get("/api/scenario-studio/categories")
    assert res.status_code == 200
    cats = {item["attack_category"] for item in res.json()}
    assert {"port_scan", "brute_force", "credential_stuffing", "phishing_url"} <= cats


def test_propose_rejects_unsafe_request_without_provider():
    mock = AsyncMock()
    with patch.object(generator, "query_openrouter_messages", new=mock):
        res = client.post(
            "/api/scenario-studio/propose",
            json={"request": "Deliver malware and execute a reverse shell."},
        )
    assert res.status_code == 200
    assert res.json()["status"] == "unsafe_request"
    mock.assert_not_called()


def test_propose_returns_validated_spec():
    payload = _valid_spec_dict()
    with patch.object(
        generator, "query_openrouter_messages",
        new=AsyncMock(return_value={"text": json.dumps(payload), "model": "mock"}),
    ):
        res = client.post(
            "/api/scenario-studio/propose",
            json={"request": "Simulate a synthetic port scan.", "controls": {"seed": 99}},
        )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ready"
    assert body["spec"]["seed"] == 99


def test_propose_provider_unavailable_is_503():
    with patch.object(generator, "query_openrouter_messages", new=AsyncMock(side_effect=ProviderUnavailableError("down"))):
        res = client.post("/api/scenario-studio/propose", json={"request": "Simulate a synthetic port scan."})
    assert res.status_code == 503
    detail = res.json()["detail"]
    assert detail["fallback_available"] is True


def test_propose_deadline_returns_honest_503():
    """A hanging provider must yield an honest 503 before the client times out.

    Guards against regressing to the old behavior where the backend's 45s+ LLM
    budget let the frontend's 15s axios timeout fire first, so the fallback the
    UI depends on never reached the analyst.
    """
    import asyncio

    from app.routers import scenario_studio as studio_router

    async def _hang(*args, **kwargs):
        await asyncio.sleep(5)
        return {"text": "{}", "model": "mock"}

    with patch.object(studio_router, "PROPOSE_DEADLINE_SECONDS", 0.2), patch.object(
        generator, "query_openrouter_messages", new=_hang
    ):
        res = client.post(
            "/api/scenario-studio/propose", json={"request": "Simulate a synthetic port scan."}
        )
    assert res.status_code == 503
    detail = res.json()["detail"]
    assert detail["fallback_available"] is True
    assert "did not respond" in detail["error"]


def test_validate_endpoint_replays_validation():
    res = client.post("/api/scenario-studio/validate", json={"spec": _valid_spec_dict()})
    assert res.status_code == 200
    assert res.json()["valid"] is True


def test_validate_endpoint_rejects_bad_spec():
    bad = _valid_spec_dict()
    bad["attack_category"] = "ddos"
    res = client.post("/api/scenario-studio/validate", json={"spec": bad})
    assert res.status_code == 422


def test_compile_persists_dataset():
    res = client.post("/api/scenario-studio/compile", json={"spec": _valid_spec_dict()})
    assert res.status_code == 200
    body = res.json()
    assert body["scenario_id"] == "scn_api_001"
    assert body["scenario_category"] == "port_scan"
    assert body["events_count"] == 20
    assert body["ground_truth_available"] is True
    assert body["provenance"]["source"] == "llm"


def test_compile_rejects_unsafe_spec():
    bad = _valid_spec_dict()
    bad["entity_templates"][1]["value"] = "8.8.8.8"  # real, non-synthetic IP
    res = client.post("/api/scenario-studio/compile", json={"spec": bad})
    assert res.status_code == 422
    assert "validation" in res.json()["detail"]


def test_compile_rejects_schema_invalid_spec():
    bad = _valid_spec_dict()
    bad["attack_category"] = "ddos"
    res = client.post("/api/scenario-studio/compile", json={"spec": bad})
    assert res.status_code == 422


def test_replay_endpoint_scores_expected_vs_actual():
    comp = client.post("/api/scenario-studio/compile", json={"spec": _valid_spec_dict()})
    assert comp.status_code == 200
    dataset_id = comp.json()["dataset_id"]

    rep = client.post(f"/api/scenario-studio/datasets/{dataset_id}/replay")
    assert rep.status_code == 200
    body = rep.json()
    assert body["dataset_id"] == dataset_id
    assert body["detector_type"] == "network"
    assert "port_scan_detected" in body["expected_labels"]
    # The compiled high-diversity scan should trigger the port-scan rule.
    assert "port_scan_detected" in body["true_positive_labels"]
    assert body["metrics"]["recall"] == 1.0


def test_replay_endpoint_unknown_dataset_is_404():
    rep = client.post("/api/scenario-studio/datasets/does_not_exist/replay")
    assert rep.status_code == 404


def test_lifecycle_endpoint_returns_separated_layers():
    comp = client.post("/api/scenario-studio/compile", json={"spec": _valid_spec_dict()})
    dataset_id = comp.json()["dataset_id"]
    client.post(f"/api/scenario-studio/datasets/{dataset_id}/replay")

    res = client.get(f"/api/scenario-studio/datasets/{dataset_id}/lifecycle")
    assert res.status_code == 200
    body = res.json()

    # All five layers present, plus provenance.
    for key in ("provenance", "layer_plan", "layer_telemetry", "layer_ground_truth", "layer_detections", "layer_evaluation"):
        assert key in body

    # Telemetry is observable-only: no label leaks into the events layer.
    for ev in body["layer_telemetry"]["events"]:
        assert "ground_truth_label" not in ev

    # Ground truth lives in its own layer and is traceable per template.
    assert body["layer_ground_truth"]["per_template"][0]["template_id"] == "et_scan"
    assert body["layer_ground_truth"]["is_verified"] is True

    # Evaluation layer reflects the replay comparison.
    assert body["layer_evaluation"]["comparison"] is not None
    assert "port_scan_detected" in body["layer_evaluation"]["comparison"]["expected_labels"]

    # Provenance is attached to the dataset.
    assert body["provenance"]["scenario_id"] == "scn_api_001"
    assert body["provenance"]["generator_version"]


def test_lifecycle_endpoint_404_unknown():
    res = client.get("/api/scenario-studio/datasets/nope/lifecycle")
    assert res.status_code == 404
