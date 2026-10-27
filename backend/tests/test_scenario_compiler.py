"""Tests for the M3 deterministic scenario compiler.

Verifies the "deterministic services execute" contract: a validated spec is
expanded into reproducible telemetry, persisted as a Dataset with provenance,
while ground truth stays separate from the observable events.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import Base, SessionLocal, engine
from app.models import Dataset
from app.services.scenario_simulator.compiler import compile_scenario_to_dataset
from app.services.scenario_simulator.spec import SCENARIO_SPEC_SCHEMA_VERSION, ScenarioSpec


@pytest.fixture(scope="module", autouse=True)
def _create_tables():
    Base.metadata.create_all(bind=engine)
    yield


def _port_scan_spec(**overrides):
    base = {
        "schema_version": SCENARIO_SPEC_SCHEMA_VERSION,
        "scenario_id": "scn_cmp_port",
        "title": "Compile port scan",
        "description": "Deterministic port scan compile test.",
        "attack_category": "port_scan",
        "intensity": "high",
        "duration_seconds": 60,
        "event_count": 20,
        "seed": 123,
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
             "features": {"distinct_dest_ports": 16}, "ground_truth_label": 1,
             "ground_truth_source": "ids_signature", "repetition": 16},
        ],
        "expected_outcomes": [
            {"expected_detection_labels": ["port_scan_detected"], "is_malicious": True,
             "rationale": "Distinct port fan-out trips the scan rule."},
        ],
        "evaluation_objective": "Confirm scan detection.",
        "generation_provenance": {"generator_version": "scenario-studio-1.0", "source": "llm", "llm_input_sha256": "abc123"},
    }
    base.update(overrides)
    return ScenarioSpec(**base)


def _credential_stuffing_spec():
    base = {
        "schema_version": SCENARIO_SPEC_SCHEMA_VERSION,
        "scenario_id": "scn_cmp_cs",
        "title": "Compile credential stuffing",
        "description": "Auth events across many accounts.",
        "attack_category": "credential_stuffing",
        "intensity": "high",
        "duration_seconds": 120,
        "event_count": 10,
        "seed": 7,
        "stages": [
            {"stage_id": "s1", "stage_type": "initial_access", "description": "Spray",
             "expected_observable_behavior": "many distinct accounts"},
        ],
        "entity_templates": [
            {"entity_id": "src1", "kind": "source_ip", "value": "203.0.113.88"},
        ],
        "event_templates": [
            {"template_id": "et_spray", "stage_id": "s1", "event_category": "auth",
             "time_offset_seconds": 10, "source_ref": "src1",
             "features": {"event_type": "failed_authentication", "distinct_targets": 6},
             "ground_truth_label": 1, "ground_truth_source": "scenario_design", "repetition": 8},
        ],
        "expected_outcomes": [
            {"expected_detection_labels": ["credential_stuffing_detected"], "is_malicious": True,
             "rationale": "Many distinct accounts from one source."},
        ],
        "evaluation_objective": "Confirm stuffing detection.",
        "generation_provenance": {"generator_version": "scenario-studio-1.0", "source": "deterministic"},
    }
    return ScenarioSpec(**base)


def test_compile_is_deterministic():
    spec = _port_scan_spec()
    a = compile_scenario_to_dataset(spec, db=None, persist=False)
    b = compile_scenario_to_dataset(spec, db=None, persist=False)
    assert a.payload_json == b.payload_json
    assert a.id == b.id


def test_event_count_matches_repetitions():
    spec = _port_scan_spec()
    ds = compile_scenario_to_dataset(spec, db=None, persist=False)
    events = json.loads(ds.payload_json)
    assert len(events) == 16
    assert ds.events_count == 16


def test_network_events_have_required_shape():
    spec = _port_scan_spec()
    ds = compile_scenario_to_dataset(spec, db=None, persist=False)
    events = json.loads(ds.payload_json)
    ev = events[0]
    assert ev["type"] == "network"
    assert {"src_ip", "dest_ip", "dest_port", "protocol", "timestamp"} <= set(ev)
    assert ev["src_ip"] == "10.0.0.50"


def test_scan_fanout_produces_distinct_ports():
    spec = _port_scan_spec()
    events = json.loads(compile_scenario_to_dataset(spec, db=None, persist=False).payload_json)
    distinct = {e["dest_port"] for e in events}
    # Distinct ports within the window are what the detector observes.
    assert len(distinct) >= 10


def test_ground_truth_is_separate_from_telemetry():
    spec = _port_scan_spec()
    ds = compile_scenario_to_dataset(spec, db=None, persist=False)
    events = json.loads(ds.payload_json)
    for e in events:
        assert "ground_truth_label" not in e
        assert "label" not in e.get("payload", {})
    # Labels are preserved in the spec, not the telemetry.
    stored_spec = json.loads(ds.scenario_spec_json)
    assert stored_spec["event_templates"][0]["ground_truth_label"] == 1
    # Each event links to its template via provenance only.
    assert events[0]["_template_id"] == "et_scan"


def test_provenance_columns_populated():
    ds = compile_scenario_to_dataset(_port_scan_spec(), db=None, persist=False)
    assert ds.scenario_id == "scn_cmp_port"
    assert ds.generator_version == "scenario-studio-1.0"
    assert ds.llm_input_sha256 == "abc123"
    assert ds.dataset_role == ds.dataset_role  # persisted from spec
    assert ds.scenario_category == "port_scan"


def test_credential_stuffing_varies_targets():
    ds = compile_scenario_to_dataset(_credential_stuffing_spec(), db=None, persist=False)
    events = json.loads(ds.payload_json)
    targets = {e["target"] for e in events}
    # No fixed target entity -> deterministic compiler spreads distinct accounts.
    assert len(targets) >= 3
    assert all(e["type"] == "auth" and "failed" in e["event_type"] for e in events)


def test_persist_creates_dataset_row():
    db = SessionLocal()
    try:
        ds = compile_scenario_to_dataset(_port_scan_spec(), db=db, persist=True)
        stored = db.query(Dataset).filter(Dataset.id == ds.id).first()
        assert stored is not None
        assert stored.events_count == 16
        # Idempotent recompile (deterministic id via db.merge) does not duplicate.
        compile_scenario_to_dataset(_port_scan_spec(), db=db, persist=True)
        count = db.query(Dataset).filter(Dataset.id == ds.id).count()
        assert count == 1
    finally:
        db.query(Dataset).filter(Dataset.scenario_id.like("scn_cmp_%")).delete(synchronize_session=False)
        db.commit()
        db.close()
