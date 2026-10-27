"""Section D verification - the paper's Random Forest port-scan detector.

These tests pin exactly the claims a review will interrogate:

  * the baseline really is 100 trees / maximum depth 6 over the five declared
    behavioural features, declared in one place and reused everywhere;
  * feature names, order, types, units and ranges are enforced *before* any
    vector reaches an estimator, in training and in serving alike;
  * inference is driven by measured telemetry, never by the scenario identity or
    a stored ground-truth label;
  * a missing model or missing provenance fails loudly instead of returning
    ``None`` and silently skipping the detector;
  * training, evaluation, persistence, promotion and rollback are separate
    operations, and a rejected candidate never reaches the disk;
  * training is deterministic and every artifact carries reproducible provenance;
  * the synthetic-label limitation is quoted by every surface that reports a score.

Each test uses its own in-memory database so the adaptive lifecycle cannot be
disturbed by (or disturb) rows written by other modules.
"""

import inspect
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import numpy as np
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models import (
    Detection,
    DetectionSource,
    DifficultyLevel,
    LearningExample,
    ModelVersion,
    Scenario,
    ScenarioCategory,
    SecurityEvent,
    Session as SessionModel,
    SessionStatus,
    SuricataEvent,
)
from app.services import ml_engine
from ml import registry
from ml.features import (
    AUTH_FEATURE_NAMES,
    FEATURE_NAMES,
    RANDOM_FOREST_BASELINE,
    FeatureSchemaError,
    build_classifier,
    describe_classifier,
    extract_auth_features,
    extract_features,
    feature_importances,
    feature_names_for,
    validate_features,
    vectorize,
)
from ml.registry import ModelIntegrityError, ModelNotAvailableError

# Captured before any test redirects the store, so tests can copy from it.
_REAL_MODELS_DIR = registry.MODELS_DIR


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------
@pytest.fixture()
def db():
    """A private in-memory database per test, with the full schema created."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    ml_engine.clear_model_cache()
    try:
        yield session
    finally:
        session.close()
        ml_engine.clear_model_cache()


@pytest.fixture()
def tmp_models_dir(tmp_path, monkeypatch):
    """Redirect the artifact store so lifecycle tests never touch ml/models."""
    target = tmp_path / "artifacts"
    target.mkdir()
    monkeypatch.setattr(registry, "MODELS_DIR", str(target))
    return str(target)


def _make_session(db, category=ScenarioCategory.PORT_SCAN, student="ml_lifecycle_student"):
    scenario = Scenario(
        name=f"{category.value} scenario",
        category=category,
        difficulty=DifficultyLevel.MEDIUM,
        description="Test fixture scenario.",
        config_json=json.dumps({"behavioral_rule": {"name": "fixture"}}),
    )
    db.add(scenario)
    db.commit()
    db.refresh(scenario)
    session = SessionModel(
        student_id=student,
        scenario_id=scenario.id,
        status=SessionStatus.RUNNING,
        started_at=datetime.now(timezone.utc),
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


def _add_suricata_scan(db, session_id, src_ip="192.0.2.10", ports=24, dest_count=2):
    """Insert port-scan-shaped IDS telemetry (documentation IP space only)."""
    base_time = datetime(2026, 5, 4, 12, 0, tzinfo=timezone.utc)
    rows = []
    for index in range(ports):
        rows.append(SuricataEvent(
            session_id=session_id,
            raw_signature="ET SCAN Potential Syntax Check",
            src_ip=src_ip,
            dest_ip=f"198.51.100.{(index % dest_count) + 1}",
            dest_port=1000 + index,
            protocol="TCP" if index % 3 else "UDP",
            severity=2,
            timestamp=base_time + timedelta(seconds=index * 0.2),
        ))
    db.add_all(rows)
    db.commit()
    return rows


def _port_scan_features(index, attack):
    if attack:
        return {
            "distinct_dest_ports": 20 + index,
            "events_per_second": 20.0 + index,
            "distinct_dest_ips": 2 + (index % 3),
            "avg_severity": 2.0 + (index % 2) * 0.5,
            "protocol_diversity": 2,
        }
    return {
        "distinct_dest_ports": 1 + (index % 5),
        "events_per_second": 0.5 + 0.1 * index,
        "distinct_dest_ips": 1,
        "avg_severity": 3.0,
        "protocol_diversity": 1,
    }


def _seed_examples(db, task_name, normal=12, attack=12):
    rows = []
    for index in range(normal):
        rows.append(LearningExample(
            task_name=task_name, label=0,
            feature_json=json.dumps(_port_scan_features(index, False), sort_keys=True),
            feature_schema_version=registry.feature_schema_version_for(task_name),
        ))
    for index in range(attack):
        rows.append(LearningExample(
            task_name=task_name, label=1,
            feature_json=json.dumps(_port_scan_features(index, True), sort_keys=True),
            feature_schema_version=registry.feature_schema_version_for(task_name),
        ))
    db.add_all(rows)
    db.commit()
    return len(rows)


def _register_version(db, task_name, version_string, accepted=False, f1=None, **extra):
    row = ModelVersion(
        version_string=version_string,
        task_name=task_name,
        is_accepted=accepted,
        f1_score=f1,
        training_samples=18,
        **extra,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


class _RecordingClassifier:
    """Stub estimator that records exactly which vectors the service feeds it."""

    def __init__(self, probability=0.99):
        self.probability = probability
        self.seen_vectors = []
        self.classes_ = [0, 1]
        self.n_features_in_ = len(FEATURE_NAMES)
        self._metadata = {"model_version": "stub", "feature_schema_version": "1.0"}
        self._loaded_path = "stub://recording-classifier"

    def predict_proba(self, rows):
        self.seen_vectors = [list(row) for row in rows]
        return [[1.0 - self.probability, self.probability] for _ in self.seen_vectors]


# ---------------------------------------------------------------------------
# 1. The reported baseline is declared once and used everywhere
# ---------------------------------------------------------------------------
def test_paper_baseline_is_declared_once_and_instantiated_exactly(tmp_path):
    assert FEATURE_NAMES == [
        "distinct_dest_ports",
        "events_per_second",
        "distinct_dest_ips",
        "avg_severity",
        "protocol_diversity",
    ], "the five features are a reported result, not an implementation detail"

    assert RANDOM_FOREST_BASELINE["class_name"] == "RandomForestClassifier"
    assert RANDOM_FOREST_BASELINE["n_estimators"] == 100
    assert RANDOM_FOREST_BASELINE["max_depth"] == 6
    assert RANDOM_FOREST_BASELINE["random_state"] == 42

    clf = build_classifier()
    assert describe_classifier(clf) == RANDOM_FOREST_BASELINE

    # No code path may inflate the reported score by swapping the baseline.
    assert "XGB" not in inspect.getsource(ml_engine)
    assert "xgboost" not in inspect.getsource(ml_engine).lower()
    assert os.path.isfile(registry.base_path("port_scan"))


def test_feature_contract_covers_units_ranges_and_derivation():
    from ml.features import FEATURE_SPECS, feature_specs_for

    assert set(FEATURE_SPECS) == set(FEATURE_NAMES)
    assert feature_specs_for("port_scan") == FEATURE_SPECS
    for name, spec in FEATURE_SPECS.items():
        assert spec["unit"], name
        assert spec["maximum"] >= spec["minimum"], name
        assert spec["derived_from"], name
        assert "SuricataEvent" in spec["derived_from"], name
    # avg_severity is a Suricata severity, so the contract must forbid the
    # inverted "higher is worse" reading of the field.
    assert FEATURE_SPECS["avg_severity"]["maximum"] == 4.0
    assert FEATURE_SPECS["distinct_dest_ports"]["integer"] is True
    assert feature_specs_for("brute_force").keys() == set(AUTH_FEATURE_NAMES)


# ---------------------------------------------------------------------------
# 2. Feature validation: names, order, types, missing values, ranges
# ---------------------------------------------------------------------------
def test_validate_features_accepts_only_the_declared_contract():
    good = _port_scan_features(0, True)
    assert validate_features(good, "port_scan") is None

    cases = []
    missing = dict(good)
    missing.pop("avg_severity")
    cases.append((missing, "avg_severity"))

    extra = dict(good)
    extra["scenario_name"] = "port_scan"
    cases.append((extra, "scenario_name"))

    textual = dict(good)
    textual["events_per_second"] = "fast"
    cases.append((textual, "events_per_second"))

    boolean = dict(good)
    boolean["distinct_dest_ports"] = True
    cases.append((boolean, "distinct_dest_ports"))

    nan_value = dict(good)
    nan_value["avg_severity"] = float("nan")
    cases.append((nan_value, "avg_severity"))

    fractional_count = dict(good)
    fractional_count["distinct_dest_ports"] = 4.5
    cases.append((fractional_count, "distinct_dest_ports"))

    out_of_range = dict(good)
    out_of_range["avg_severity"] = 5.0
    cases.append((out_of_range, "avg_severity"))

    negative = dict(good)
    negative["distinct_dest_ports"] = -1
    cases.append((negative, "distinct_dest_ports"))

    for payload, expected_in_message in cases:
        with pytest.raises(FeatureSchemaError) as excinfo:
            validate_features(payload, "port_scan")
        assert expected_in_message in str(excinfo.value), payload

    with pytest.raises(FeatureSchemaError):
        validate_features(["not", "a", "mapping"], "port_scan")
    with pytest.raises(FeatureSchemaError):
        feature_names_for("unknown_task")


def test_vectorize_is_order_checked_and_lossless():
    features = {
        "protocol_diversity": 3,
        "avg_severity": 2.5,
        "distinct_dest_ips": 4,
        "events_per_second": 12.5,
        "distinct_dest_ports": 40,
    }
    vector = vectorize(features, "port_scan")
    assert vector == [40.0, 12.5, 4.0, 2.5, 3.0]
    assert all(isinstance(value, float) for value in vector)
    # Reordering the declared schema must change the vector, never be tolerated.
    from ml import features as features_module
    original = list(features_module.FEATURE_NAMES)
    try:
        features_module.FEATURE_NAMES[0], features_module.FEATURE_NAMES[1] = (
            features_module.FEATURE_NAMES[1], features_module.FEATURE_NAMES[0],
        )
        assert vectorize(features, "port_scan") == [12.5, 40.0, 4.0, 2.5, 3.0]
    finally:
        features_module.FEATURE_NAMES[:] = original


def test_extracted_features_satisfy_the_contract_for_real_telemetry(db):
    session = _make_session(db)
    events = _add_suricata_scan(db, session.id)
    grouped = ml_engine._suricata_groups_by_source(session.id, db)
    src_ip, rows = next(iter(grouped.items()))
    measured = extract_features(rows)
    validate_features(measured, "port_scan")
    assert measured["distinct_dest_ports"] == len({e.dest_port for e in events})
    assert measured["distinct_dest_ips"] == len({e.dest_ip for e in events})
    assert measured["protocol_diversity"] == 2  # TCP + UDP
    assert 1.0 <= measured["avg_severity"] <= 4.0
    assert measured["events_per_second"] > 0.0


# ---------------------------------------------------------------------------
# 3. Provenance of the bundled, paper-reported artifact
# ---------------------------------------------------------------------------
def test_bundled_artifact_is_verifiable_and_reports_the_reported_config():
    path = registry.base_path("port_scan")
    metadata = registry.validate_artifact(path, "port_scan")

    assert metadata["feature_names"] == FEATURE_NAMES
    assert metadata["feature_schema_version"] == registry.FEATURE_SCHEMA_VERSION
    assert metadata["model_config"]["n_estimators"] == 100
    assert metadata["model_config"]["max_depth"] == 6
    assert metadata["random_seed"] == 42
    assert metadata["n_features_in"] == len(FEATURE_NAMES)
    assert metadata["training_data_version"].startswith("sha256:")
    assert metadata["limitations"] == registry.SYNTHETIC_LIMITATION
    # Attested, not retrained: the tool must not pretend it re-measured accuracy.
    assert metadata["evaluation"]["provenance"] == (
        "reported_by_existing_metrics_sidecar_not_remeasured"
    )

    clf = registry.load_verified(path, "port_scan")
    assert clf.n_features_in_ == len(FEATURE_NAMES)
    assert list(clf.classes_) == [0, 1]
    assert clf._metadata["model_version"] == "base_model"
    assert feature_importances(clf, "port_scan").keys() == set(FEATURE_NAMES)


def test_registry_refuses_unverified_or_mismatched_artifacts(tmp_models_dir):
    from joblib import dump

    clf = build_classifier()
    clf.fit(np.array([[float(v) for v in _port_scan_features(i, i % 2).values()] for i in range(8)]),
            [0, 1] * 4)

    # (a) artifact with no metadata sidecar at all
    orphan = os.path.join(tmp_models_dir, "orphan.joblib")
    dump(clf, orphan)
    with pytest.raises(ModelIntegrityError, match="sidecar"):
        registry.validate_artifact(orphan, "port_scan")
    assert registry.artifact_inventory()["unverified"][0]["filename"] == "orphan.joblib"

    # (b) missing artifact -> actionable error, never None
    with pytest.raises(ModelNotAvailableError, match="not present"):
        registry.validate_artifact(os.path.join(tmp_models_dir, "nope.joblib"), "port_scan")
    with pytest.raises(ModelNotAvailableError):
        registry.base_path("nonexistent_task")

    # (c) metadata that contradicts the declared feature contract
    wrong_features = os.path.join(tmp_models_dir, "wrong.joblib")
    registry.save_model(
        clf, wrong_features, task_name="port_scan",
        training_data_digest="sha256:test", config=describe_classifier(clf),
        evaluation={}, seed=42,
    )
    meta_path = registry.metadata_path(wrong_features)
    with open(meta_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    payload["feature_names"] = ["a", "b", "c", "d", "e"]
    with open(meta_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    with pytest.raises(ModelIntegrityError, match="Refusing to score"):
        registry.validate_artifact(wrong_features, "port_scan")

    # (d) schema version drift is rejected rather than served
    drifted = os.path.join(tmp_models_dir, "drifted.joblib")
    registry.save_model(
        clf, drifted, task_name="port_scan",
        training_data_digest="sha256:test", config=describe_classifier(clf),
        evaluation={}, seed=42,
    )
    meta_path = registry.metadata_path(drifted)
    with open(meta_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    payload["feature_schema_version"] = "9.9"
    with open(meta_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    with pytest.raises(ModelIntegrityError, match="feature schema version"):
        registry.validate_artifact(drifted, "port_scan")


def test_training_data_digest_is_order_independent_but_data_sensitive():
    rows = [(json.dumps(_port_scan_features(i, i % 2), sort_keys=True), i % 2) for i in range(6)]
    forward = registry.training_data_version(rows)
    reversed_ = registry.training_data_version(list(reversed(rows)))
    assert forward == reversed_, "the same dataset must always get the same identifier"

    changed = list(rows)
    changed[0] = (json.dumps(_port_scan_features(99, True), sort_keys=True), 1)
    assert registry.training_data_version(changed) != forward


# ---------------------------------------------------------------------------
# 4. Inference is driven by features, never by the scenario identity
# ---------------------------------------------------------------------------
def test_inference_runs_from_measured_features_under_an_unrelated_scenario(db, monkeypatch):
    """A port-scan-shaped flow recorded under a *brute_force* scenario still scores.

    This is the anti-cheat proof: the detector cannot be gated on the scenario
    name, and the vector it consumes is exactly the measured feature set.
    """
    session = _make_session(db, category=ScenarioCategory.BRUTE_FORCE)
    _add_suricata_scan(db, session.id)

    stub = _RecordingClassifier(probability=0.93)
    monkeypatch.setattr(ml_engine, "_load_model", lambda db_, task, version=None: stub)

    detections = ml_engine.evaluate_ml(session_id=session.id, db=db)
    assert [d.label for d in detections] == ["port_scan_detected"]

    expected = vectorize(extract_features(
        ml_engine._suricata_groups_by_source(session.id, db)["192.0.2.10"]
    ), "port_scan")
    assert stub.seen_vectors == [expected]
    assert all(isinstance(value, float) for value in stub.seen_vectors[0])

    detection = detections[0]
    assert detection.source == DetectionSource.ML
    assert detection.confidence == pytest.approx(0.93, abs=1e-4)
    payload = json.loads(detection.features)
    assert payload["feature_names"] == FEATURE_NAMES
    assert payload["features"] == pytest.approx(dict(zip(FEATURE_NAMES, expected)))
    assert payload["raw_probability"] == pytest.approx(0.93, abs=1e-6)
    assert payload["flagging_threshold"] == ml_engine.ML_FLAG_THRESHOLD
    assert payload["limitation"] == registry.SYNTHETIC_LIMITATION
    assert payload["evidence"][0]["source_ip"] == "192.0.2.10"
    # The detector's own inputs and verdict carry no scenario identity at all -
    # only the quoted research limitation may mention the generator.
    assert set(payload["features"]) == set(FEATURE_NAMES)
    assert "scenario" not in json.dumps(payload["features"]).lower()
    assert "scenario" not in (detection.label + detection.explanation).lower()


def test_low_probability_scores_no_detection_but_is_recorded_in_diagnostics(db, monkeypatch):
    session = _make_session(db)
    _add_suricata_scan(db, session.id)
    stub = _RecordingClassifier(probability=0.20)
    monkeypatch.setattr(ml_engine, "_load_model", lambda db_, task, version=None: stub)

    assert ml_engine.evaluate_ml(session_id=session.id, db=db) == []
    notes = {n["task_name"]: n for n in ml_engine.evaluate_ml_detailed(
        session_id=session.id, db=db)["diagnostics"]}
    assert notes["port_scan"]["status"] == "SCORED_BELOW_THRESHOLD"
    assert notes["port_scan"]["highest_probability"] == pytest.approx(0.2, abs=1e-6)


def test_evaluate_ml_detailed_never_silently_skips_an_absent_model(db, tmp_models_dir):
    session = _make_session(db, category=ScenarioCategory.BRUTE_FORCE)
    now = datetime(2026, 5, 4, 12, 0, tzinfo=timezone.utc)
    db.add_all([SecurityEvent(
        session_id=session.id, simulation_id="sim_auth_run", scenario="brute_force",
        event_type="failed_login", timestamp=now - timedelta(seconds=10 * i),
        source="192.0.2.50", target="svc-account", device="dev-1", location="dc-1",
    ) for i in range(1, 6)])
    db.commit()

    result = ml_engine.evaluate_ml_detailed(session_id=session.id, db=db)
    notes = {n["task_name"]: n for n in result["diagnostics"]}

    # No network telemetry at all -> an explicit, named state (not a silent pass).
    assert notes["port_scan"]["status"] == "NO_TELEMETRY"
    # Auth model genuinely not deployed -> reported, never faked.
    assert notes["brute_force"]["status"] == "MODEL_UNAVAILABLE"
    assert notes["brute_force"]["availability"] == "extension_not_trained"
    assert "brute_force_rf.joblib" in notes["brute_force"]["reason"]
    assert result["detections"] == []
    assert result["limitation"] == registry.SYNTHETIC_LIMITATION

    # Loading it directly raises an actionable error instead of returning None.
    with pytest.raises(ModelNotAvailableError, match="brute_force"):
        ml_engine._load_model(db, "brute_force")


def test_unknown_session_and_duplicate_run_are_reported(db):
    notes = ml_engine.evaluate_ml_detailed(session_id=999999, db=db)["diagnostics"]
    assert notes[0]["status"] == "NO_SESSION"

    session = _make_session(db)
    _add_suricata_scan(db, session.id)
    # The stored verdict is re-derivable, so an idempotent re-run is required:
    # calling the detector twice must not fabricate a second signal (which the
    # risk engine would then count twice).
    ml_engine.evaluate_ml(session_id=session.id, db=db)
    first = db.query(Detection).filter(Detection.source == DetectionSource.ML).count()
    second_run = ml_engine.evaluate_ml(session_id=session.id, db=db)
    second = db.query(Detection).filter(Detection.source == DetectionSource.ML).count()
    assert second_run == []
    assert first == second, "a repeated evaluation must not duplicate ML detections"


@pytest.mark.parametrize("function_name", [
    "evaluate_ml", "evaluate_ml_detailed", "_evaluate_ml_impl", "runner_has_telemetry",
    "_run_port_scan", "_run_auth", "_suricata_groups_by_source",
    "_security_groups_by_source", "_positive_probability",
])
def test_detection_code_path_contains_no_ground_truth_shortcut(function_name):
    """No detector may read the scenario identity or the stored verdict."""
    source = inspect.getsource(getattr(ml_engine, function_name))
    for forbidden in (".scenario", "ScenarioCategory", "detection_status", "category ==",
                      "expected_attack"):
        assert forbidden not in source, f"{function_name} references {forbidden!r}"


# ---------------------------------------------------------------------------
# 5. Training / evaluation / persistence / promotion / rollback are separate
# ---------------------------------------------------------------------------
def test_data_adequacy_gates_are_explicit(db):
    _seed_examples(db, "port_scan", normal=3, attack=2)
    assert train_status(db) == "NOT_ENOUGH_DATA"

    db.query(LearningExample).delete()
    db.commit()
    _seed_examples(db, "port_scan", normal=12, attack=1)
    assert train_status(db) == "INSUFFICIENT_CLASSES"


def train_status(db):
    return ml_engine.train_candidate("port_scan", db)["status"]


def test_train_candidate_has_no_side_effects(db, tmp_models_dir):
    _seed_examples(db, "port_scan")
    trained = ml_engine.train_candidate("port_scan", db)

    assert trained["status"] == "TRAINED"
    assert trained["training_samples"] == 18 and trained["test_samples"] == 6
    assert trained["feature_names"] == FEATURE_NAMES
    assert trained["feature_schema_version"] == registry.FEATURE_SCHEMA_VERSION
    assert trained["model_config"] == RANDOM_FOREST_BASELINE
    assert trained["random_seed"] == 42
    assert trained["training_data_version"].startswith("sha256:")
    # Training alone must not write anything.
    assert os.listdir(tmp_models_dir) == []
    assert db.query(ModelVersion).count() == 0

    evaluation = ml_engine.evaluate_candidate(trained["classifier"], trained["X_test"], trained["y_test"])
    assert set(evaluation) == {"accuracy", "f1_score", "precision", "recall", "confusion_matrix"}
    assert evaluation["f1_score"] > ml_engine.ACCEPTANCE_F1_THRESHOLD
    # Evaluation alone must not write anything either.
    assert os.listdir(tmp_models_dir) == []


def test_persist_and_promote_are_distinct_operations(db, tmp_models_dir):
    _seed_examples(db, "port_scan")
    trained = ml_engine.train_candidate("port_scan", db)
    evaluation = ml_engine.evaluate_candidate(
        trained["classifier"], trained["X_test"], trained["y_test"])

    # Promotion requires a registered version and a real artifact.
    with pytest.raises(ModelNotAvailableError, match="not registered"):
        ml_engine.promote_version("port_scan", "v_missing", db)

    persisted = ml_engine.persist_candidate(
        task_name="port_scan", version_string="v_persist_1", clf=trained["classifier"],
        training_data_version=trained["training_data_version"], evaluation=evaluation,
        samples={"train": 18, "test": 6, "total": 24}, seed=42,
    )
    assert os.path.isfile(persisted["artifact_path"])
    assert os.path.isfile(registry.metadata_path(persisted["artifact_path"]))
    metadata = registry.read_metadata(persisted["artifact_path"])
    assert metadata["training_data_version"] == trained["training_data_version"]
    assert metadata["feature_names"] == FEATURE_NAMES
    assert metadata["model_config"] == RANDOM_FOREST_BASELINE
    assert metadata["evaluation"]["f1_score"] == pytest.approx(evaluation["f1_score"])
    # Persisting is not promoting.
    assert db.query(ModelVersion).count() == 0
    assert ml_engine._resolve_artifact_path(db, "port_scan", None) == registry.base_path("port_scan")

    _register_version(db, "port_scan", "v_persist_1", f1=evaluation["f1_score"])
    result = ml_engine.promote_version("port_scan", "v_persist_1", db, reason="review")
    assert result["status"] == "PROMOTED"
    assert ml_engine._resolve_artifact_path(db, "port_scan", None) == registry.version_path("v_persist_1")
    assert ml_engine.get_active_version(db, "port_scan").version_string == "v_persist_1"

    # An accepted row whose artifact vanished is refused, not served blindly.
    os.remove(registry.version_path("v_persist_1"))
    with pytest.raises(ModelNotAvailableError, match="no artifact on disk"):
        ml_engine.promote_version("port_scan", "v_persist_1", db)


def test_promotion_supersedes_the_previous_active_model(db, tmp_models_dir):
    _seed_examples(db, "port_scan")
    trained = ml_engine.train_candidate("port_scan", db)
    for name in ("v_first", "v_second"):
        ml_engine.persist_candidate(
            task_name="port_scan", version_string=name, clf=trained["classifier"],
            training_data_version=trained["training_data_version"],
            evaluation={"f1_score": 0.99}, samples={"total": 24}, seed=42,
        )
        _register_version(db, "port_scan", name, f1=0.99)
        ml_engine.promote_version("port_scan", name, db)

    states = {
        row.version_string: (row.is_accepted, row.promotion_state)
        for row in db.query(ModelVersion).all()
    }
    assert states["v_first"] == (False, "SUPERSEDED")
    assert states["v_second"] == (True, "PROMOTED")


def test_rollback_restores_an_accepted_version_and_refuses_fabrication(db, tmp_models_dir):
    _seed_examples(db, "port_scan")
    trained = ml_engine.train_candidate("port_scan", db)
    for name in ("v_alpha", "v_beta"):
        ml_engine.persist_candidate(
            task_name="port_scan", version_string=name, clf=trained["classifier"],
            training_data_version=trained["training_data_version"],
            evaluation={"f1_score": 0.99}, samples={"total": 24}, seed=42,
        )
        _register_version(db, "port_scan", name, f1=0.99)
    ml_engine.promote_version("port_scan", "v_beta", db)

    result = ml_engine.rollback_model("port_scan", "v_alpha", db)
    assert result["status"] == "SUCCESS"
    assert result["active_version"] == "v_alpha"
    assert result["rolled_back_from"] == "v_beta"
    assert result["training_data_version"] == trained["training_data_version"]
    assert db.query(ModelVersion).filter_by(version_string="v_beta").first().promotion_state == "ROLLED_BACK"
    assert db.query(ModelVersion).filter_by(version_string="v_alpha").first().is_accepted is True

    with pytest.raises(ValueError, match="not found"):
        ml_engine.rollback_model("port_scan", "v_never_existed", db)

    # A rejected candidate was never written, so it cannot be rolled back to.
    _register_version(db, "port_scan", "v_ghost", f1=0.99)
    with pytest.raises(ValueError, match="Rejected candidates are never persisted"):
        ml_engine.rollback_model("port_scan", "v_ghost", db)


def test_acceptance_gate_boundaries():
    accepted, reason = ml_engine.acceptance_gate(0.85, 0.0)
    assert accepted is False and "did not exceed" in reason

    accepted, _ = ml_engine.acceptance_gate(0.8501, 0.0)
    assert accepted is True

    accepted, reason = ml_engine.acceptance_gate(0.86, 0.90)
    assert accepted is False and "regression" in reason

    accepted, _ = ml_engine.acceptance_gate(1.0, 1.0)
    assert accepted is True, "matching the active model is not a regression"


def test_rejected_candidate_is_never_written_to_disk(db, tmp_models_dir, monkeypatch):
    _seed_examples(db, "port_scan")
    monkeypatch.setattr(ml_engine, "acceptance_gate",
                        lambda candidate_f1, active_f1: (False, "forced rejection under test"))

    result = ml_engine.train_and_evaluate_model("port_scan", db)
    assert result["status"] == "REJECTED"
    assert result["persisted"] is False
    assert result["artifact_filename"] is None
    assert result["reason"] == "forced rejection under test"
    assert os.listdir(tmp_models_dir) == [], "rejected models must not accumulate"

    row = db.query(ModelVersion).first()
    assert row.promotion_state == "REJECTED" and row.is_accepted is False
    assert row.artifact_filename is None
    assert ml_engine.get_active_version(db, "port_scan") is None, "the base model stays active"


def test_train_and_evaluate_composes_the_lifecycle_and_keeps_the_limitation(
    db, tmp_models_dir
):
    _seed_examples(db, "port_scan")
    result = ml_engine.train_and_evaluate_model("port_scan", db)

    assert result["status"] == "ACCEPTED"
    assert result["persisted"] is True
    assert result["decision"] == "ACCEPTED"
    assert result["threshold"] == ml_engine.ACCEPTANCE_F1_THRESHOLD
    assert result["previous_active_version"] == "base_model"
    assert result["active_model_version"] == result["candidate_version"]
    assert result["limitation"] == registry.SYNTHETIC_LIMITATION
    assert result["model_config"] == RANDOM_FOREST_BASELINE
    assert result["random_seed"] == 42
    assert result["feature_names"] == FEATURE_NAMES
    assert set(result["feature_importances"]) == set(FEATURE_NAMES)
    assert os.path.isfile(registry.version_path(result["candidate_version"]))

    row = db.query(ModelVersion).filter_by(version_string=result["candidate_version"]).first()
    assert row.is_accepted is True and row.promotion_state == "PROMOTED"
    assert json.loads(row.model_config_json) == RANDOM_FOREST_BASELINE
    assert json.loads(row.feature_names_json) == FEATURE_NAMES
    assert row.training_data_version == result["training_data_version"]
    assert row.parent_version == "base_model"
    assert json.loads(row.evaluation_json)["f1_score"] == pytest.approx(
        result["candidate_metrics"]["f1_score"])


def test_training_is_deterministic_for_identical_data(db, tmp_models_dir):
    _seed_examples(db, "port_scan")
    first = ml_engine.train_candidate("port_scan", db)
    second = ml_engine.train_candidate("port_scan", db)

    assert first["training_data_version"] == second["training_data_version"]
    assert first["model_config"] == second["model_config"]
    assert json.dumps(first["class_distribution"], sort_keys=True) == \
        json.dumps(second["class_distribution"], sort_keys=True)
    assert feature_importances(first["classifier"], "port_scan") == \
        feature_importances(second["classifier"], "port_scan")
    probe = np.array([[float(v) for v in _port_scan_features(1, True).values()]])
    assert np.array_equal(first["classifier"].predict(probe),
                          second["classifier"].predict(probe))

    evaluation_a = ml_engine.evaluate_candidate(first["classifier"], first["X_test"], first["y_test"])
    evaluation_b = ml_engine.evaluate_candidate(second["classifier"], second["X_test"], second["y_test"])
    assert evaluation_a == evaluation_b


def test_corrupt_training_rows_fail_the_run_instead_of_silently_training(
    db, tmp_models_dir
):
    _seed_examples(db, "port_scan")
    db.add(LearningExample(
        task_name="port_scan", label=1, feature_json=json.dumps({"nonsense": 1}),
        feature_schema_version=registry.FEATURE_SCHEMA_VERSION,
    ))
    db.commit()
    with pytest.raises(FeatureSchemaError, match="violate the declared feature schema"):
        ml_engine._load_training_matrix(db, "port_scan")


# ---------------------------------------------------------------------------
# 6. Honest readiness reporting
# ---------------------------------------------------------------------------
def test_readiness_distinguishes_ready_and_unavailable_tasks(db):
    """Real artifact store: what is deployed right now, stated exactly."""
    readiness = ml_engine.get_ml_readiness(db)
    tasks = readiness["tasks"]

    assert set(tasks) == set(registry.TASKS)
    assert tasks["port_scan"]["state"] == "READY"
    assert tasks["port_scan"]["serving_from"] == "base_model"
    assert tasks["port_scan"]["base_artifact_verified"] is True
    assert tasks["port_scan"]["feature_names"] == FEATURE_NAMES
    assert tasks["port_scan"]["flagging_threshold"] == ml_engine.ML_FLAG_THRESHOLD
    assert tasks["brute_force"]["state"] == "UNAVAILABLE"
    assert tasks["brute_force"]["base_artifact_present"] is False
    assert tasks["brute_force"]["serving_from"] is None
    assert tasks["credential_stuffing"]["state"] == "UNAVAILABLE"

    inventory = readiness["artifact_inventory"]
    assert "port_scan_rf.joblib" in inventory["verified_artifacts"]
    assert readiness["limitation"] == registry.SYNTHETIC_LIMITATION
    assert readiness["random_forest_baseline"] == RANDOM_FOREST_BASELINE


def test_readiness_names_an_artifact_without_provenance_as_unverified(db, tmp_models_dir):
    """A bare .joblib with no sidecar is a distinct, named capability state."""
    import shutil

    shutil.copy(os.path.join(_REAL_MODELS_DIR, "port_scan_rf.joblib"), tmp_models_dir)

    tasks = ml_engine.get_ml_readiness(db)["tasks"]
    assert tasks["port_scan"]["state"] == "UNVERIFIED_PROVENANCE"
    assert tasks["port_scan"]["base_artifact_present"] is True
    assert tasks["port_scan"]["base_artifact_verified"] is False
    assert tasks["port_scan"]["serving_from"] is None
    assert "refuses to score" in tasks["port_scan"]["detail"]


def test_readiness_follows_a_promoted_version_and_flags_a_missing_artifact(
    db, tmp_models_dir
):
    _seed_examples(db, "port_scan")
    result = ml_engine.train_and_evaluate_model("port_scan", db)
    tasks = ml_engine.get_ml_readiness(db)["tasks"]
    assert tasks["port_scan"]["state"] == "READY"
    assert tasks["port_scan"]["serving_from"] == result["candidate_version"]
    assert tasks["port_scan"]["active_version"] == result["candidate_version"]

    os.remove(registry.version_path(result["candidate_version"]))
    ml_engine.clear_model_cache()
    tasks = ml_engine.get_ml_readiness(db)["tasks"]
    assert tasks["port_scan"]["state"] == "UNAVAILABLE"
    assert "no verified artifact on disk" in tasks["port_scan"]["detail"]


def test_adaptive_status_reports_provenance_and_history(db, tmp_models_dir):
    _seed_examples(db, "port_scan", normal=6, attack=6)
    status = ml_engine.get_adaptive_status("port_scan", db)
    assert status["status"] == "READY_FOR_TRAINING"
    assert status["total_examples"] == 12
    assert status["current_version"] == "base_model"
    assert status["metrics"] is None
    assert status["model_config"] == RANDOM_FOREST_BASELINE
    assert status["feature_names"] == FEATURE_NAMES
    assert status["limitation"] == registry.SYNTHETIC_LIMITATION
    assert status["model_readiness"]["state"] == "UNAVAILABLE", \
        "the tmp artifact store holds no base model, and readiness must say so"

    result = ml_engine.train_and_evaluate_model("port_scan", db)
    status = ml_engine.get_adaptive_status("port_scan", db)
    assert status["model_readiness"]["state"] == "READY"
    assert status["current_version"] == result["candidate_version"]
    assert status["history"][0]["version"] == result["candidate_version"]
    assert status["history"][0]["training_data_version"] == result["training_data_version"]
    assert status["training_data_version"] == result["training_data_version"]
    assert status["random_seed"] == 42


# ---------------------------------------------------------------------------
# 7. The adaptive feature store keeps generator truth, not detector output
# ---------------------------------------------------------------------------
def test_learning_examples_carry_provenance_and_generator_labels(db):
    session = _make_session(db, category=ScenarioCategory.BRUTE_FORCE)
    now = datetime(2026, 5, 4, 12, 0, tzinfo=timezone.utc)
    db.add_all([SecurityEvent(
        session_id=session.id, simulation_id="sim_auth_run_7", scenario="brute_force",
        event_type="failed_login", timestamp=now - timedelta(seconds=10 * i),
        source="192.0.2.70", target="svc-account", device="dev-7", location="dc-2",
    ) for i in range(1, 8)])
    db.commit()

    added = ml_engine.extract_and_store_learning_examples(session.id, db)
    assert added > 0, "a session must yield training examples"

    rows = db.query(LearningExample).filter(
        LearningExample.session_id == session.id).all()
    assert rows, "examples are attached to the session that produced them"
    for row in rows:
        assert row.source_simulation == "sim_auth_run_7", \
            "provenance comes from the recorded run identifier"
        assert row.feature_schema_version in (registry.FEATURE_SCHEMA_VERSION,
                                              registry.AUTH_FEATURE_SCHEMA_VERSION)
        assert row.trusted_label_source in ("scenario_generator", "signature_or_baseline")
        features = json.loads(row.feature_json)
        validate_features(features, row.task_name)
        if row.task_name == "port_scan":
            assert features["distinct_dest_ports"] == 0  # benign network baseline
        else:
            assert features["failed_attempts"] == 7

    # The label came from the generator's scenario record, and the auth feature
    # vector is exactly what the pipeline measured from the stored events.
    auth_rows = [r for r in rows if r.task_name == "brute_force"]
    assert auth_rows and auth_rows[0].label == 1
    expected = extract_auth_features([{
        "event_type": "failed_login", "target": "svc-account", "device": "dev-7",
        "timestamp": now - timedelta(seconds=10 * i), "payload_json": None, "event_id": i,
    } for i in range(1, 8)])
    assert json.loads(auth_rows[0].feature_json) == pytest.approx(expected)


def test_ml_detection_is_reproducible_from_stored_evidence(db, monkeypatch):
    """A reviewer can re-derive the verdict from the persisted row alone."""
    session = _make_session(db)
    _add_suricata_scan(db, session.id)
    stub = _RecordingClassifier(probability=0.88)
    monkeypatch.setattr(ml_engine, "_load_model", lambda db_, task, version=None: stub)
    ml_engine.evaluate_ml(session_id=session.id, db=db)

    detection = db.query(Detection).filter(Detection.source == DetectionSource.ML).first()
    payload = json.loads(detection.features)
    replayed = vectorize(payload["features"], payload["task_name"])
    assert replayed == stub.seen_vectors[0]
    assert detection.confidence == pytest.approx(payload["raw_probability"], abs=1e-4)
    assert payload["model_version"] == "stub"
    assert payload["artifact_filename"] == "recording-classifier"
    assert payload["task_name"] == "port_scan"
