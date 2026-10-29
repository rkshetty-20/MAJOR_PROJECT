"""Section A contract: controlled synthetic telemetry.

Five properties are proved here, because each is a claim the project makes and each
can rot silently:

1. **Determinism** - the same spec compiles to the same bytes, in this process and in
   a fresh interpreter with a different hash seed, and timestamps come from a fixed
   epoch rather than the wall clock.
2. **Label independence** - flipping ``ground_truth_label`` changes no observable
   byte; the label source cannot be a detector output; and a feature key that names
   the label is rejected.
3. **Schema validation** - strict field sets, reference integrity, bounded counts,
   and a repairable violation (not a crash) when an observable is left to inference.
4. **Provenance** - generator version, dataset role and a hashed (never raw) prompt on
   the dataset row, and provenance fields the model cannot overwrite.
5. **Documentation-only identifiers** - every emitted IP, host and URL is RFC5737,
   RFC1918 or a reserved TLD, for every category and several seeds.

The replay lock (``tests/data/scenario_telemetry_golden.json``) is produced from
``tests/telemetry_corpus.py`` by ``tests/regenerate_scenario_telemetry_golden.py`` -
deliberately not named ``test_*``, so a test run can never rewrite the lock.
"""

from __future__ import annotations

import hashlib
import importlib.util
import ipaddress
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest
from pydantic import ValidationError

from app.services.scenario_simulator.compiler import (
    SYNTHETIC_NO_SIGNATURE,
    CompilationError,
    compile_scenario_to_dataset,
)
from app.services.scenario_simulator.evaluator import ReplayError, _expected_labels, _parse_ts
from app.services.scenario_simulator.generator import (
    GENERATOR_VERSION,
    _normalize_provenance,
)
from app.services.scenario_simulator.spec import (
    MAX_EVENT_COUNT,
    SCENARIO_SPEC_SCHEMA_VERSION,
    GroundTruthSource,
    ScenarioSpec,
)
from app.services.scenario_simulator.validators import run_full_validation

TESTS_DIR = Path(__file__).parent
BACKEND_DIR = TESTS_DIR.parent
DATA_DIR = TESTS_DIR / "data"
GOLDEN_PATH = DATA_DIR / "scenario_telemetry_golden.json"

_SPEC = importlib.util.spec_from_file_location("telemetry_corpus", TESTS_DIR / "telemetry_corpus.py")
corpus = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(corpus)

CORPUS: Dict[str, ScenarioSpec] = corpus.build_corpus()
golden: Dict[str, Any] = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))

RESERVED_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),     # RFC5737 TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # RFC5737 TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # RFC5737 TEST-NET-3
    ipaddress.ip_network("10.0.0.0/8"),       # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),    # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),   # RFC1918
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
)


def compile_spec(spec: ScenarioSpec):
    """Compile without persistence: no DB, no side effects, pure data expansion."""
    return compile_scenario_to_dataset(spec, db=None, persist=False)


def events_of(spec: ScenarioSpec) -> List[Dict[str, Any]]:
    return json.loads(compile_spec(spec).payload_json)


def _host_of(value: str) -> str:
    host = value.split("://", 1)[1] if "://" in value else value
    return host.split("/", 1)[0].split(":", 1)[0]


# ---------------------------------------------------------------------------
# 1. Determinism
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", sorted(CORPUS))
def test_the_same_spec_compiles_to_the_same_bytes(name):
    spec = CORPUS[name]
    first, second = compile_spec(spec), compile_spec(spec)
    assert first.payload_json == second.payload_json
    assert first.id == second.id
    assert first.events_count == second.events_count


_CHILD = (
    "import hashlib, json, sys\n"
    "from app.services.scenario_simulator.spec import ScenarioSpec\n"
    "from app.services.scenario_simulator.compiler import compile_scenario_to_dataset\n"
    "spec = ScenarioSpec(**json.loads(sys.stdin.read()))\n"
    "ds = compile_scenario_to_dataset(spec, db=None, persist=False)\n"
    "sys.stdout.write(hashlib.sha256(ds.payload_json.encode('utf-8')).hexdigest())\n"
)


def _hash_in_child(spec: ScenarioSpec, hash_seed: str) -> str:
    env = dict(os.environ, PYTHONHASHSEED=hash_seed)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD],
        input=json.dumps(spec.model_dump(mode="json")),
        capture_output=True,
        text=True,
        cwd=str(BACKEND_DIR),
        env=env,
        timeout=180,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def test_compilation_is_hash_seed_and_process_independent():
    """Two interpreters with different hash seeds must agree with this process.

    This is what "deterministic seed" has to mean for the claim to be useful: no
    dependence on dict/set iteration order, on ``uuid``, or on the wall clock.
    """
    spec = CORPUS["port_scan|fallback_ids|seed101"]
    local = hashlib.sha256(compile_spec(spec).payload_json.encode("utf-8")).hexdigest()
    assert _hash_in_child(spec, "0") == local
    assert _hash_in_child(spec, "12345") == local


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_timestamps_come_from_the_fixed_epoch_not_the_wall_clock(name):
    stamps = [datetime.fromisoformat(ev["timestamp"]) for ev in events_of(CORPUS[name])]
    assert stamps, "a compiled dataset must contain events"
    for stamp in stamps:
        assert stamp.tzinfo is not None
        # compiler._BASE_EPOCH = 2024-01-01T00:00Z
        assert (stamp.year, stamp.month, stamp.day) == (2024, 1, 1), stamp
    assert max(stamps) < datetime(2024, 1, 2, tzinfo=timezone.utc)


def test_the_seed_drives_only_undeclared_identifiers():
    """Honest scope of ``seed``.

    A fully declared spec is seed-invariant on purpose (nothing is random), so two
    seeds must agree byte for byte. The seed only reaches the telemetry through the
    fallback identifiers used when a template references no entity - and there it
    must actually change the result. Both halves are asserted so neither can be
    claimed beyond what the code does.
    """
    declared_101 = compile_spec(corpus.port_scan_spec(101)).payload_json
    declared_7 = compile_spec(corpus.port_scan_spec(7)).payload_json
    assert declared_101 == declared_7

    fallback_101 = {ev["dest_ip"] for ev in events_of(corpus.port_scan_fallback_ids_spec(101))}
    fallback_7 = {ev["dest_ip"] for ev in events_of(corpus.port_scan_fallback_ids_spec(7))}
    assert fallback_101 and fallback_7
    assert fallback_101 != fallback_7, "the seed must actually reach fallback identifiers"


# ---------------------------------------------------------------------------
# 2. Ground truth stays independent of what the detector sees
# ---------------------------------------------------------------------------
def test_flipping_the_ground_truth_label_changes_no_observable_byte():
    """The decisive independence test.

    Same spec, same seed, same observables - only ``ground_truth_label`` differs.
    If any observable were derived from the label (as the auth ``event_type`` used
    to be), the two payloads could not be identical.
    """
    positive = compile_spec(corpus.brute_force_spec(303, ground_truth_label=1))
    negative = compile_spec(corpus.brute_force_spec(303, ground_truth_label=0))
    assert positive.payload_json == negative.payload_json

    # ... and the labels really are different, so the test is not vacuous.
    assert [t.ground_truth_label for t in corpus.brute_force_spec(303, 1).event_templates] == [1, 1]
    assert [t.ground_truth_label for t in corpus.brute_force_spec(303, 0).event_templates] == [0, 0]


def test_compiler_refuses_to_infer_the_auth_observable_from_the_label():
    data = corpus.brute_force_spec(303).model_dump(mode="json")
    for template in data["event_templates"]:
        template["features"].pop("event_type")
    spec = ScenarioSpec(**data)

    with pytest.raises(CompilationError) as excinfo:
        compile_spec(spec)
    message = str(excinfo.value)
    assert "must declare features.event_type" in message
    assert "never infers an observable from the ground-truth label" in message


def test_auth_template_without_event_type_is_a_repairable_violation():
    """The API must tell the author what is wrong instead of failing at compile time."""
    data = corpus.brute_force_spec(303).model_dump(mode="json")
    for template in data["event_templates"]:
        template["features"].pop("event_type")
    report = run_full_validation(ScenarioSpec(**data))
    codes = {v.code for v in report.violations}
    assert "missing_observable_event_type" in codes, report.to_serializable()
    assert report.ok is False


def test_feature_keys_that_restate_the_label_are_rejected():
    data = corpus.brute_force_spec(303).model_dump(mode="json")
    data["event_templates"][0]["features"]["ground_truth_label"] = 1
    data["event_templates"][1]["features"]["is_attack"] = True
    report = run_full_validation(ScenarioSpec(**data))
    violations = [v for v in report.violations if v.code == "label_key_leakage"]
    assert len(violations) == 2, report.to_serializable()
    assert "ground_truth_label" in violations[0].message


def test_the_schema_cannot_express_a_detector_derived_label_source():
    """The real protection is the closed enum, not a downstream string comparison."""
    assert {g.value for g in GroundTruthSource} == {
        "ids_signature", "scenario_design", "heuristic_policy", "unverified",
    }
    for bad in ("rule_output", "ml_prediction", "detection_score", "detector_label"):
        data = corpus.brute_force_spec(303).model_dump(mode="json")
        data["event_templates"][0]["ground_truth_source"] = bad
        with pytest.raises(ValidationError):
            ScenarioSpec(**data)


def test_expected_labels_are_read_from_the_spec_only():
    """Evaluation compares the authored expectation, never the detector's own output."""
    assert _expected_labels(corpus.port_scan_spec(101)) == ["port_scan_detected"]
    assert _expected_labels(corpus.credential_stuffing_spec(202)) == ["credential_stuffing_detected"]
    assert _expected_labels(corpus.phishing_spec(505)) == ["phishing_url_detected"]


def test_no_compiled_event_carries_a_label_field():
    for name, spec in CORPUS.items():
        for event in events_of(spec):
            for key in event:
                assert "label" not in key.lower(), (name, key)
                assert "ground_truth" not in key.lower(), (name, key)
            # `_template_id` is a provenance link back into the plan, not a label.
            assert "_template_id" in event


# ---------------------------------------------------------------------------
# 3. Schema validation
# ---------------------------------------------------------------------------
def test_unknown_fields_are_rejected_at_both_levels():
    data = corpus.port_scan_spec(101).model_dump(mode="json")
    data["unexpected_top_level"] = 1
    with pytest.raises(ValidationError):
        ScenarioSpec(**data)

    data = corpus.port_scan_spec(101).model_dump(mode="json")
    data["event_templates"][0]["unexpected_template_field"] = 1
    with pytest.raises(ValidationError):
        ScenarioSpec(**data)


def test_reference_integrity_and_routing_are_enforced():
    data = corpus.port_scan_spec(101).model_dump(mode="json")
    data["event_templates"][0]["source_ref"] = "ghost_entity"
    with pytest.raises(ValidationError):
        ScenarioSpec(**data)

    data = corpus.port_scan_spec(101).model_dump(mode="json")
    data["event_templates"][0]["event_category"] = "auth"
    with pytest.raises(ValidationError):
        ScenarioSpec(**data)

    data = corpus.port_scan_spec(101).model_dump(mode="json")
    data["stages"][0]["depends_on"] = ["s_other"]
    with pytest.raises(ValidationError):
        ScenarioSpec(**data)


def test_bounded_counts_are_enforced():
    data = corpus.port_scan_spec(101).model_dump(mode="json")
    data["event_count"] = 0
    with pytest.raises(ValidationError):
        ScenarioSpec(**data)

    data = corpus.port_scan_spec(101).model_dump(mode="json")
    data["event_templates"][0]["repetition"] = MAX_EVENT_COUNT + 1
    with pytest.raises(ValidationError):
        ScenarioSpec(**data)

    # Sum of repetitions may not exceed the declared event_count.
    data = corpus.port_scan_spec(101).model_dump(mode="json")
    data["event_count"] = 5
    with pytest.raises(ValidationError):
        ScenarioSpec(**data)


def test_every_corpus_spec_passes_safety_and_feasibility():
    for name, spec in CORPUS.items():
        report = run_full_validation(spec)
        assert report.ok, (name, report.to_serializable())


def test_undeclared_network_observables_are_warned_about_not_invented():
    report = run_full_validation(corpus.port_scan_spec(101, declare_signature=False))
    codes = {w.code for w in report.warnings}
    assert {"no_declared_dest_port", "no_declared_signature"} <= codes, report.to_serializable()
    assert report.ok is True  # a warning, not a blocker


# ---------------------------------------------------------------------------
# 4. Provenance
# ---------------------------------------------------------------------------
def test_dataset_row_carries_complete_provenance():
    spec = corpus.phishing_spec(505)
    dataset = compile_spec(spec)
    assert dataset.is_synthetic is True
    assert dataset.scenario_id == spec.scenario_id
    assert dataset.generator_version == GENERATOR_VERSION
    assert dataset.dataset_role == "validation"
    assert dataset.llm_input_sha256 == "0" * 64
    assert dataset.schema_version == SCENARIO_SPEC_SCHEMA_VERSION

    preserved = json.loads(dataset.scenario_spec_json)
    assert preserved["scenario_id"] == spec.scenario_id
    assert preserved["seed"] == spec.seed
    assert preserved["generation_provenance"]["source"] == "deterministic"
    # The trusted labels live in the preserved plan, not in the telemetry.
    assert preserved["event_templates"][0]["ground_truth_label"] == 1
    assert preserved["expected_outcomes"][0]["expected_detection_labels"] == ["phishing_url_detected"]


def test_the_prompt_is_hashed_and_never_stored():
    prompt = "Simulate a synthetic port scan against the lab range."
    normalised = _normalize_provenance({"generation_provenance": {}}, "test/model", "corr_1", prompt)
    prov = normalised["generation_provenance"]
    assert prov["llm_input_sha256"] == hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    assert prompt not in json.dumps(normalised)
    assert prov["request_correlation_id"] == "corr_1"
    assert prov["model"] == "test/model"


def test_provenance_cannot_be_claimed_by_the_model():
    """A proposal cannot promote itself to "deterministic" or fake the generator."""
    normalised = _normalize_provenance(
        {"generation_provenance": {"source": "detector", "generator_version": "made-up-9.9"}},
        "test/model", "corr_2", "prompt",
    )
    prov = normalised["generation_provenance"]
    assert prov["source"] == "llm"
    assert prov["generator_version"] == GENERATOR_VERSION
    assert normalised["schema_version"] == SCENARIO_SPEC_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# 5. Documentation-only identifiers
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", sorted(CORPUS))
def test_every_emitted_identifier_is_documentation_only(name):
    ips: List[str] = []
    hosts: List[str] = []
    for event in events_of(CORPUS[name]):
        for key in ("src_ip", "dest_ip", "source"):
            value = event.get(key)
            if isinstance(value, str):
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue
                ips.append(value)
        for key in ("target",):
            value = event.get(key)
            if isinstance(value, str) and ("://" in value or "." in value):
                hosts.append(_host_of(value))

    for value in ips:
        addr = ipaddress.ip_address(value)
        assert any(addr in net for net in RESERVED_NETS), (name, value)

    for host in hosts:
        assert host.endswith(corpus.RESERVED_TLDS) or host == "localhost", (name, host)


def test_public_targets_are_rejected_by_the_safety_validator():
    data = corpus.port_scan_spec(101).model_dump(mode="json")
    data["entity_templates"][0]["value"] = "8.8.8.8"
    report = run_full_validation(ScenarioSpec(**data))
    assert any(v.code == "external_target" for v in report.violations), report.to_serializable()

    data = corpus.phishing_spec(505).model_dump(mode="json")
    data["entity_templates"][0]["value"] = "https://www.real-bank.com/login"
    report = run_full_validation(ScenarioSpec(**data))
    assert any(v.code == "external_target" for v in report.violations), report.to_serializable()


# ---------------------------------------------------------------------------
# 6. Replay
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", sorted(CORPUS))
def test_replay_of_the_lock_matches_the_current_compiler(name):
    assert name in golden["cases"], f"{name} is not in the lock"
    recorded = golden["cases"][name]
    dataset = compile_spec(CORPUS[name])
    events = json.loads(dataset.payload_json)

    assert recorded["payload_sha256"] == hashlib.sha256(dataset.payload_json.encode("utf-8")).hexdigest()
    assert recorded["dataset_id"] == dataset.id
    assert recorded["events_count"] == dataset.events_count == len(events)
    assert recorded["timestamp_min"] == min(ev["timestamp"] for ev in events)
    assert recorded["timestamp_max"] == max(ev["timestamp"] for ev in events)
    assert recorded["src_ips"] == sorted({ev["src_ip"] for ev in events if "src_ip" in ev})
    assert recorded["dest_ips"] == sorted({ev["dest_ip"] for ev in events if "dest_ip" in ev})
    assert recorded["raw_signatures"] == sorted(
        {ev["raw_signature"] for ev in events if "raw_signature" in ev}
    )
    assert recorded["dataset_role"] == dataset.dataset_role
    assert recorded["generator_version"] == dataset.generator_version


def test_the_lock_covers_the_declared_corpus_exactly():
    assert set(golden["cases"]) == set(CORPUS)
    assert golden["schema_version"] == SCENARIO_SPEC_SCHEMA_VERSION


def test_the_lock_itself_records_the_label_independence_property():
    """The evidence lives in the lock, so a reviewer can check it without running code."""
    positive = golden["cases"]["brute_force|seed303"]
    negative = golden["cases"]["brute_force|seed303|label0"]
    assert positive["payload_sha256"] == negative["payload_sha256"]
    assert positive["labels"] == [1, 1]
    assert negative["labels"] == [0, 0]


def test_an_undeclared_signature_is_a_neutral_marker_not_a_vendor_signature():
    signatures = {ev["raw_signature"] for ev in events_of(corpus.port_scan_spec(101))}
    assert signatures == {SYNTHETIC_NO_SIGNATURE}
    assert not any("ET " in sig for sig in signatures)

    declared = {ev["raw_signature"] for ev in events_of(corpus.port_scan_spec(101, declare_signature=True))}
    assert declared == {"ET SCAN Possible Nmap User-Agent Observed"}


def test_replay_refuses_to_invent_a_timestamp():
    with pytest.raises(ReplayError) as missing:
        _parse_ts(None, 3)
    assert "Event 3" in str(missing.value)
    assert "refuses to substitute" in str(missing.value)

    with pytest.raises(ReplayError):
        _parse_ts("not-a-timestamp", 0)
    with pytest.raises(ReplayError):
        _parse_ts({}, 0)

    parsed = _parse_ts("2024-01-01T00:00:10+00:00")
    assert parsed.tzinfo is not None and parsed.year == 2024
    naive = _parse_ts("2024-01-01T00:00:10")
    assert naive.tzinfo == timezone.utc


def test_recompiling_a_persisted_spec_merges_on_the_deterministic_id():
    """`persist=True` keys the Dataset row on scenario_id+seed, so a re-compile is idempotent."""
    from app.database import SessionLocal
    from app.models import Dataset

    db = SessionLocal()
    spec = corpus.phishing_spec(505)
    dataset = None
    try:
        first = compile_scenario_to_dataset(spec, db=db)
        dataset = first
        second = compile_scenario_to_dataset(spec, db=db)
        assert first.id == second.id
        rows = db.query(Dataset).filter(Dataset.id == first.id).all()
        assert len(rows) == 1
        assert rows[0].payload_json == first.payload_json
    finally:
        if dataset is not None:
            db.query(Dataset).filter(Dataset.id == dataset.id).delete()
            db.commit()
        db.close()
