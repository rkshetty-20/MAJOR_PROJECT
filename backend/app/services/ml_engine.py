"""Machine-learning detection and adaptive lifecycle for the AOD-IPS framework.

This service implements the research paper's ML contribution exactly as
reported, and nothing else:

  * a Random Forest classifier - 100 trees, maximum depth 6 - over five
    behavioural features extracted from Suricata telemetry
    (``distinct_dest_ports``, ``events_per_second``, ``distinct_dest_ips``,
    ``avg_severity``, ``protocol_diversity``);
  * a probability threshold of ``ML_FLAG_THRESHOLD`` before a detection is raised;
  * an adaptive lifecycle in which training, evaluation, promotion and rollback
    are separate operations guarded by an explicit acceptance gate.

Non-negotiable invariants enforced here
---------------------------------------
1. Inference is driven by measured feature values only. Neither the scenario
   name, the scenario category nor any stored ground-truth label is consulted to
   decide whether the model runs or what it reports.
2. Feature names, order, type and unit ranges are validated before a vector is
   handed to any estimator - in training and in serving alike.
3. Every persisted model carries provenance: configuration, random seed,
   training-data digest, feature schema version and evaluation results
   (see :mod:`ml.registry`).
4. A rejected candidate is never written to disk, so the artifact directory
   cannot accumulate unverifiable models.
5. Scientific limitation, preserved verbatim in every response: perfect accuracy
   on the synthetic hold-out does **not** establish real-world generalization,
   because the labels derive from the generator's own signatures.
"""

import json
import logging
import os
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import (
    Detection,
    DetectionSource,
    LearningExample,
    ModelVersion,
    SecurityEvent,
    Session as SessionModel,
    SuricataEvent,
)
from ml import registry
from ml.features import (
    FeatureSchemaError,
    describe_classifier,
    feature_importances,
    feature_names_for,
    feature_schema_version_for,
    build_classifier,
    extract_auth_features,
    extract_features,
    validate_features,
    vectorize,
)
from ml.registry import ModelIntegrityError, ModelNotAvailableError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Reported configuration. Single source of truth for the thresholds quoted in
# the paper; changing one here changes it everywhere and is recorded with each
# detection so a verdict can be re-derived later.
# ---------------------------------------------------------------------------
ML_FLAG_THRESHOLD = 0.7            # port-scan probability needed to raise a detection
AUTH_FLAG_THRESHOLD = 0.8          # auth-attack probability needed (extension task)
ACCEPTANCE_F1_THRESHOLD = 0.85     # adaptive candidate must exceed this held-out F1
MIN_TRAINING_EXAMPLES = 10
MIN_EXAMPLES_PER_CLASS = 2
TEST_SIZE = 0.25
SPLIT_RANDOM_STATE = 42
RANDOM_TRAINING_SEED = registry.TRAINING_SEED

MODEL_TASKS = list(registry.TASKS)

# The paper's own caveat, quoted from the registry so the trainer, the artifact
# metadata and this serving layer always state the same limitation.
SYNTHETIC_LABEL_LIMITATION = registry.SYNTHETIC_LIMITATION

# ---------------------------------------------------------------------------
# Model cache (path keyed, so a promoted artifact cannot be shadowed by a stale
# in-memory copy).
# ---------------------------------------------------------------------------
_MODEL_CACHE: Dict[str, Any] = {}


def clear_model_cache() -> None:
    """Drop every cached estimator. Called after promotion/rollback."""
    _MODEL_CACHE.clear()


def get_active_version(db: Session, task_name: str = "port_scan") -> Optional[ModelVersion]:
    """The currently accepted :class:`ModelVersion` row for a task, or ``None``.

    ``None`` means "no adaptive model has been promoted", in which case the
    bundled base artifact is served (if it carries verified provenance).
    """
    return registry._active_version_row(db, task_name)


# Retained for existing importers (adaptive_learning.analysis_context).
_get_active_version = get_active_version


def _resolve_artifact_path(db: Optional[Session], task_name: str,
                          version_string: Optional[str]) -> str:
    """Decide which artifact file a task should be served from (deterministic)."""
    if version_string:
        return registry.version_path(version_string)
    active = registry._active_version_row(db, task_name) if db is not None else None
    if active is not None:
        candidate = registry.version_path(active.version_string)
        if os.path.isfile(candidate):
            return candidate
    return registry.base_path(task_name)


def _load_model(db: Session, task_name: str, version_string: Optional[str] = None):
    """Deterministically load the active estimator for a task.

    Raises :class:`ModelNotAvailableError` when no artifact exists and
    :class:`ModelIntegrityError` when an artifact exists but its provenance
    cannot be verified - never a silent ``None``.
    """
    path = _resolve_artifact_path(db, task_name, version_string)
    cached = _MODEL_CACHE.get(path)
    if cached is not None:
        return cached

    if not os.path.isfile(path):
        raise ModelNotAvailableError(
            f"No model artifact for task {task_name!r} at {path}. Train and promote a "
            f"version (POST /api/ml/train) or run ml/train_port_scan_model.py for the "
            f"bundled baseline."
        )

    clf = registry.load_verified(path, task_name)
    _MODEL_CACHE[clf._loaded_path] = clf
    return clf


# ---------------------------------------------------------------------------
# Feature extraction from persisted telemetry
# ---------------------------------------------------------------------------
def _suricata_groups_by_source(session_id: int, db: Session) -> Dict[str, List[Dict[str, Any]]]:
    """Group a session's IDS events by source IP in deterministic timestamp order."""
    events = (
        db.query(SuricataEvent)
        .filter(SuricataEvent.session_id == session_id)
        .order_by(SuricataEvent.timestamp.asc(), SuricataEvent.id.asc())
        .all()
    )
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for ev in events:
        if not ev.src_ip:
            continue
        grouped[ev.src_ip].append({
            "src_ip": ev.src_ip,
            "dest_ip": ev.dest_ip,
            "dest_port": ev.dest_port,
            "protocol": ev.protocol,
            "severity": ev.severity,
            "timestamp": ev.timestamp,
            "raw_signature": ev.raw_signature,
            "event_id": ev.id,
        })
    return dict(sorted(grouped.items()))


def _security_groups_by_source(session_id: int, db: Session) -> Dict[str, List[Dict[str, Any]]]:
    """Group a session's authentication telemetry by source in timestamp order."""
    sec_events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.session_id == session_id)
        .order_by(SecurityEvent.timestamp.asc(), SecurityEvent.id.asc())
        .all()
    )
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for ev in sec_events:
        if not ev.source:
            continue
        grouped[ev.source].append({
            "event_type": ev.event_type,
            "target": ev.target,
            "device": ev.device,
            "timestamp": ev.timestamp,
            "payload_json": ev.payload_json,
            "event_id": ev.id,
        })
    return dict(sorted(grouped.items()))


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------
def evaluate_ml(session_id: int, db: Session) -> List[Detection]:
    """Run every available ML detector over a session's telemetry.

    Returns the newly created :class:`Detection` rows. The scenario name and
    category are deliberately *not* inspected: if the telemetry contains the
    features a model was trained on, the model is allowed to score them.
    """
    detections, _diagnostics = _evaluate_ml_impl(session_id, db)
    return detections


def evaluate_ml_detailed(session_id: int, db: Session) -> Dict[str, Any]:
    """Like :func:`evaluate_ml` but also reports why a detector did not run.

    Exposed so the API and the frontend can never imply ML coverage that is not
    backed by a loadable, provenance-verified artifact.
    """
    detections, diagnostics = _evaluate_ml_impl(session_id, db)
    return {
        "detections": detections,
        "diagnostics": diagnostics,
        "limitation": SYNTHETIC_LABEL_LIMITATION,
    }


def _evaluate_ml_impl(session_id: int, db: Session) -> Tuple[List[Detection], List[Dict[str, Any]]]:
    new_detections: List[Detection] = []
    diagnostics: List[Dict[str, Any]] = []

    session = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not session:
        diagnostics.append({
            "task_name": "*",
            "status": "NO_SESSION",
            "reason": f"Session {session_id} does not exist; no inference performed.",
        })
        return new_detections, diagnostics

    existing_labels = {
        d.label
        for d in db.query(Detection).filter(
            Detection.session_id == session_id,
            Detection.source == DetectionSource.ML,
        ).all()
    }

    for task, runner in (
        ("port_scan", _run_port_scan),
        ("brute_force", _run_auth),
    ):
        if not runner_has_telemetry(task, session_id, db):
            diagnostics.append({
                "task_name": task,
                "status": "NO_TELEMETRY",
                "reason": "No events carrying this detector's input features in the session.",
            })
            continue
        detection, note = runner(db, session_id, existing_labels)
        if note:
            diagnostics.append(note)
        if detection is not None:
            existing_labels.add(detection.label)
            new_detections.append(detection)

    return new_detections, diagnostics


def runner_has_telemetry(task_name: str, session_id: int, db: Session) -> bool:
    """Whether the telemetry a detector consumes exists at all."""
    if task_name == "port_scan":
        return bool(_suricata_groups_by_source(session_id, db))
    return bool(_security_groups_by_source(session_id, db))


def _model_provenance(clf: Any) -> Dict[str, Any]:
    meta = getattr(clf, "_metadata", None) or {}
    loaded = getattr(clf, "_loaded_path", "") or ""
    return {
        "artifact_filename": os.path.basename(meta.get("artifact_filename") or loaded),
        "model_version": meta.get("model_version", "base_model"),
        "feature_schema_version": meta.get("feature_schema_version"),
        "training_data_version": meta.get("training_data_version"),
        "model_config": meta.get("model_config"),
        "random_seed": meta.get("random_seed"),
    }


def _run_port_scan(db: Session, session_id: int, existing_labels: set) -> Tuple[Optional[Detection], Dict[str, Any]]:
    task = "port_scan"
    if "port_scan_detected" in existing_labels:
        return None, {"task_name": task, "status": "ALREADY_PRESENT",
                      "reason": "An ML port_scan detection already exists for this session."}
    try:
        clf = _load_model(db, task)
    except (ModelNotAvailableError, ModelIntegrityError) as exc:
        return None, {"task_name": task, "status": "MODEL_UNAVAILABLE", "reason": str(exc)}

    grouped = _suricata_groups_by_source(session_id, db)
    best: Optional[Tuple[float, Dict[str, Any], str]] = None
    for src_ip, ip_events in grouped.items():
        feat_dict = extract_features(ip_events)
        try:
            vector = vectorize(feat_dict, task)
        except FeatureSchemaError as exc:
            return None, {"task_name": task, "status": "FEATURE_SCHEMA_VIOLATION", "reason": str(exc)}
        probability = _positive_probability(clf, vector)
        if best is None or probability > best[0]:
            best = (probability, feat_dict, src_ip)

    if best is None:
        return None, {"task_name": task, "status": "NO_FEATURE_GROUPS", "reason": "No source IP with usable telemetry."}

    probability, feat_dict, src_ip = best
    note = {
        "task_name": task,
        "status": "SCORED",
        "scored_groups": len(grouped),
        "highest_probability": round(probability, 6),
        "threshold": ML_FLAG_THRESHOLD,
        "model_version": _model_provenance(clf)["model_version"],
    }
    if probability <= ML_FLAG_THRESHOLD:
        note["status"] = "SCORED_BELOW_THRESHOLD"
        return None, note

    detection = _create_detection(
        db=db,
        session_id=session_id,
        label="port_scan_detected",
        probability=probability,
        features=feat_dict,
        task=task,
        clf=clf,
        evidence=[{
            "type": "SuricataEvent", "source_ip": src_ip,
            "reason": f"{int(feat_dict['distinct_dest_ports'])} distinct destination ports from {src_ip}",
        }],
        explanation=(
            f"Random Forest scored {int(feat_dict['distinct_dest_ports'])} distinct ports / "
            f"{int(feat_dict['distinct_dest_ips'])} destination IPs from {src_ip} as "
            f"port-scan-like (p={probability:.4f}, threshold {ML_FLAG_THRESHOLD})"
        ),
    )
    return detection, note


def _run_auth(db: Session, session_id: int, existing_labels: set) -> Tuple[Optional[Detection], Dict[str, Any]]:
    """Authentication-attack detector (extension task, not part of the paper's
    reported single-model contribution).

    It is kept because the feature pipeline and the learning lifecycle already
    exist, but it is *never* silently skipped: when its artifact is absent the
    caller receives an explicit ``MODEL_UNAVAILABLE`` diagnostic, so the
    framework cannot claim auth-ML coverage that is not deployed.
    """
    task = "brute_force"
    try:
        clf = _load_model(db, task)
    except (ModelNotAvailableError, ModelIntegrityError) as exc:
        return None, {
            "task_name": task,
            "status": "MODEL_UNAVAILABLE",
            "reason": str(exc),
            "availability": "extension_not_trained",
        }

    grouped = _security_groups_by_source(session_id, db)
    best: Optional[Tuple[float, Dict[str, Any], str]] = None
    for src, events in grouped.items():
        feat_dict = extract_auth_features(events)
        if feat_dict["failed_attempts"] <= 0 and feat_dict["successful_attempts"] <= 0:
            continue
        try:
            vector = vectorize(feat_dict, "brute_force")
        except FeatureSchemaError as exc:
            return None, {"task_name": task, "status": "FEATURE_SCHEMA_VIOLATION", "reason": str(exc)}
        probability = _positive_probability(clf, vector)
        if best is None or probability > best[0]:
            best = (probability, feat_dict, src)

    if best is None:
        return None, {"task_name": task, "status": "NO_AUTH_TELEMETRY",
                      "reason": "No failed or successful authentication events to score."}

    probability, feat_dict, src = best
    note = {
        "task_name": task, "status": "SCORED",
        "scored_groups": len(grouped),
        "highest_probability": round(probability, 6),
        "threshold": AUTH_FLAG_THRESHOLD,
        "model_version": _model_provenance(clf)["model_version"],
    }
    if probability <= AUTH_FLAG_THRESHOLD:
        note["status"] = "SCORED_BELOW_THRESHOLD"
        return None, note

    label = "credential_stuffing_detected" if feat_dict.get("distinct_targets", 0) >= 3 else "brute_force_detected"
    if label in existing_labels:
        note["status"] = "ALREADY_PRESENT"
        return None, note

    detection = _create_detection(
        db=db,
        session_id=session_id,
        label=label,
        probability=probability,
        features=feat_dict,
        task=task,
        clf=clf,
        evidence=[{
            "type": "SecurityEvent", "source_ip": src,
            "reason": f"{int(feat_dict['failed_attempts'])} failed / "
                      f"{int(feat_dict['successful_attempts'])} successful authentications "
                      f"across {int(feat_dict['distinct_targets'])} accounts",
        }],
        explanation=(
            f"Random Forest scored authentication telemetry from {src} as {label} "
            f"(p={probability:.4f}, threshold {AUTH_FLAG_THRESHOLD})"
        ),
    )
    return detection, note


def _positive_probability(clf: Any, vector: List[float]) -> float:
    """P(attack) taken from the estimator's own class ordering, never an index."""
    probabilities = clf.predict_proba([vector])[0]
    classes = list(getattr(clf, "classes_", []))
    if 1 in classes:
        return float(probabilities[classes.index(1)])
    return float(max(probabilities))


def _create_detection(db: Session, session_id: int, label: str, probability: float,
                      features: Dict[str, Any], task: str, clf: Any,
                      evidence: List[Dict[str, Any]], explanation: str) -> Detection:
    """Persist an ML detection with the full provenance needed to reproduce it."""
    payload = {
        "features": features,
        "feature_names": feature_names_for(task),
        "task_name": task,
        "flagging_threshold": ML_FLAG_THRESHOLD if task == "port_scan" else AUTH_FLAG_THRESHOLD,
        "raw_probability": round(float(probability), 6),
        "evidence": evidence,
        **_model_provenance(clf),
        "limitation": SYNTHETIC_LABEL_LIMITATION,
    }
    detection = Detection(
        session_id=session_id,
        source=DetectionSource.ML,
        label=label,
        confidence=round(float(probability), 4),
        explanation=explanation,
        features=json.dumps(payload),
        timestamp=datetime.now(timezone.utc),
    )
    db.add(detection)
    db.commit()
    db.refresh(detection)
    return detection


# ---------------------------------------------------------------------------
# Adaptive learning: feature store
# ---------------------------------------------------------------------------
def _session_simulation_id(db: Session, session_id: int) -> Optional[str]:
    """Return the run identifier that tagged this session's telemetry.

    ``simulation_id`` lives on the generated events (one run can be recorded
    across several sessions), not on the ``Session`` row, so provenance for a
    training example is read back from the evidence itself.
    """
    for model in (SecurityEvent, SuricataEvent):
        column = getattr(model, "simulation_id", None)
        if column is None:
            continue
        value = (
            db.query(column)
            .filter(model.session_id == session_id, column.isnot(None))
            .limit(1)
            .scalar()
        )
        if value:
            return str(value)
    return None


def extract_and_store_learning_examples(session_id: int, db: Session) -> int:
    """Extract features from a session and persist them as labelled examples.

    Ground truth is taken from the *generator's* trusted telemetry markers (the
    IDS signature for network traffic, the scenario template for authentication),
    never from a detector's output - otherwise the adaptive loop would train on
    its own predictions.
    """
    session = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not session:
        return 0

    simulation_id = _session_simulation_id(db, session_id)
    count = 0

    grouped = _suricata_groups_by_source(session_id, db)
    if not grouped:
        # A session with no network telemetry is a benign network baseline.
        feat_dict = {name: 0.0 for name in feature_names_for("port_scan")}
        count += _add_example(db, session_id, "port_scan", 0, feat_dict,
                              source_simulation=simulation_id)
    else:
        for src_ip, ip_events in grouped.items():
            feat_dict = extract_features(ip_events)
            label = 1 if any("SCAN" in str(ev.get("raw_signature") or "").upper() for ev in ip_events) else 0
            if feat_dict["events_per_second"] > 0 or feat_dict["distinct_dest_ports"] > 0:
                count += _add_example(db, session_id, "port_scan", label, feat_dict,
                                      source_simulation=simulation_id,
                                      evidence=[ev["event_id"] for ev in ip_events])

    auth_grouped = _security_groups_by_source(session_id, db)
    for src, events in auth_grouped.items():
        relevant = [ev for ev in events if _is_auth_event(ev.get("event_type"))]
        if not relevant:
            continue
        feat_dict = extract_auth_features(relevant)
        if feat_dict["failed_attempts"] <= 0 and feat_dict["successful_attempts"] <= 0:
            continue
        trusted = _trusted_auth_label(db, session_id, src)
        count += _add_example(db, session_id, trusted["task_name"], trusted["label"], feat_dict,
                              source_simulation=simulation_id,
                              evidence=[ev["event_id"] for ev in relevant],
                              label_source=trusted["source"])

    db.commit()
    return count


AUTH_EVENT_TYPES = {
    "failed_login", "successful_login", "login_attempt", "failed_authentication",
    "baseline_login", "known_device_login",
}


def _is_auth_event(event_type: Optional[str]) -> bool:
    return (event_type or "") in AUTH_EVENT_TYPES


def _trusted_auth_label(db: Session, session_id: int, source: str) -> Dict[str, Any]:
    """Label one source's authentication burst from generator ground truth.

    The generator records the scenario it emitted in ``SecurityEvent.scenario``.
    That column is generator metadata: it is legitimate *here*, when attaching a
    training label, and forbidden inside the detectors (see
    ``rule_engine._evaluate_security_events`` and :func:`evaluate_ml`).
    """
    rows = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.session_id == session_id, SecurityEvent.source == source)
        .all()
    )
    scenarios = {(row.scenario or "").lower() for row in rows}
    if "credential_stuffing" in scenarios:
        return {"task_name": "credential_stuffing", "label": 1, "source": "scenario_generator"}
    if "brute_force" in scenarios:
        return {"task_name": "brute_force", "label": 1, "source": "scenario_generator"}
    return {"task_name": "brute_force", "label": 0, "source": "scenario_generator"}


def _add_example(db: Session, session_id: int, task_name: str, label: int,
                 feat_dict: Dict[str, Any], source_simulation: Optional[str] = None,
                 evidence: Optional[List[int]] = None,
                 label_source: str = "signature_or_baseline") -> int:
    validate_features(feat_dict, task_name)
    example = LearningExample(
        session_id=session_id,
        task_name=task_name,
        label=int(label),
        feature_json=json.dumps(feat_dict, sort_keys=True),
        feature_schema_version=feature_schema_version_for(task_name),
        source_simulation=source_simulation,
        trusted_label_source=label_source,
        relevant_event_identifiers=json.dumps(evidence or []),
    )
    db.add(example)
    return 1


# ---------------------------------------------------------------------------
# Adaptive lifecycle - training, evaluation, promotion and rollback are
# deliberately separate operations. Nothing is written to disk until the
# acceptance gate has passed.
# ---------------------------------------------------------------------------
def _load_training_matrix(db: Session, task_name: str) -> Tuple[List[List[float]], List[int], List[LearningExample]]:
    """Read the persisted feature store into an ordered matrix, schema-validated.

    Every example is checked against the declared feature contract, so a row
    produced by an older or renamed pipeline fails the run with the offending
    example ids instead of quietly corrupting the model.
    """
    examples = (
        db.query(LearningExample)
        .filter(LearningExample.task_name == task_name)
        .order_by(LearningExample.id.asc())
        .all()
    )
    expected = feature_names_for(task_name)
    vectors: List[List[float]] = []
    labels: List[int] = []
    accepted: List[LearningExample] = []
    rejected: List[str] = []

    for example in examples:
        try:
            feat_dict = json.loads(example.feature_json)
            vector = vectorize(feat_dict, task_name)
        except (FeatureSchemaError, json.JSONDecodeError) as exc:
            rejected.append(f"#{example.id}: {exc}")
            continue
        vectors.append(vector)
        labels.append(int(example.label))
        accepted.append(example)

    if rejected:
        raise FeatureSchemaError(
            f"{task_name}: {len(rejected)} stored example(s) violate the declared feature "
            f"schema {expected}: " + " | ".join(rejected[:5])
        )
    return vectors, labels, accepted


def train_candidate(task_name: str, db: Session) -> Dict[str, Any]:
    """Train a candidate estimator on the persisted feature store.

    Purely a training operation: it fits the model and returns it together with
    the split it was fitted on. It does not evaluate, persist or promote.
    """
    vectors, labels, examples = _load_training_matrix(db, task_name)

    if len(vectors) < MIN_TRAINING_EXAMPLES:
        return {
            "status": "NOT_ENOUGH_DATA",
            "reason": f"Insufficient data: {len(vectors)} examples (need {MIN_TRAINING_EXAMPLES}+)",
        }

    X = np.array(vectors, dtype=float)
    y = np.array(labels, dtype=int)

    unique, counts = np.unique(y, return_counts=True)
    distribution = {int(u): int(c) for u, c in zip(unique, counts)}
    normal_count = distribution.get(0, 0)
    attack_count = distribution.get(1, 0)
    if normal_count < MIN_EXAMPLES_PER_CLASS or attack_count < MIN_EXAMPLES_PER_CLASS:
        return {
            "status": "INSUFFICIENT_CLASSES",
            "reason": (
                f"Requires at least {MIN_EXAMPLES_PER_CLASS} examples of both classes. "
                f"Found Normal: {normal_count}, Attack: {attack_count}"
            ),
            "class_distribution": {"normal": normal_count, "port_scan": attack_count},
        }

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=SPLIT_RANDOM_STATE, stratify=y,
    )

    clf = build_classifier()
    clf.fit(X_train, y_train)

    return {
        "status": "TRAINED",
        "task_name": task_name,
        "classifier": clf,
        "X_test": X_test,
        "y_test": y_test,
        "training_samples": int(len(y_train)),
        "test_samples": int(len(y_test)),
        "class_distribution": {"normal": normal_count, "port_scan": attack_count},
        "training_data_version": registry.training_data_version(
            [(ex.feature_json, ex.label) for ex in examples]
        ),
        "feature_names": feature_names_for(task_name),
        "feature_schema_version": feature_schema_version_for(task_name),
        "model_config": describe_classifier(clf),
        "random_seed": RANDOM_TRAINING_SEED,
    }


def evaluate_candidate(clf: Any, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, float]:
    """Score a fitted estimator on its held-out split. No side effects."""
    y_pred = clf.predict(X_test)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    return {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def persist_candidate(task_name: str, version_string: str, clf: Any,
                      training_data_version: str, evaluation: Dict[str, Any],
                      samples: Dict[str, Any], seed: int) -> Dict[str, Any]:
    """Write an accepted artifact plus its mandatory provenance sidecar."""
    path = registry.version_path(version_string)
    payload = registry.save_model(
        clf, path,
        task_name=task_name,
        training_data_digest=training_data_version,
        config=describe_classifier(clf),
        evaluation={k: v for k, v in evaluation.items()},
        seed=seed,
        random_seed=SPLIT_RANDOM_STATE,
        samples=samples,
        limitations=SYNTHETIC_LABEL_LIMITATION,
    )
    payload["model_version"] = version_string
    registry.write_metadata(path, payload)
    return {"artifact_path": path, "metadata": payload}


def promote_version(task_name: str, version_string: str, db: Session,
                    reason: str = "") -> Dict[str, Any]:
    """Make an accepted version the active model, superseding the previous one."""
    target = (
        db.query(ModelVersion)
        .filter(ModelVersion.task_name == task_name, ModelVersion.version_string == version_string)
        .first()
    )
    if target is None:
        raise ModelNotAvailableError(
            f"Version {version_string!r} is not registered for task {task_name!r}; "
            f"train and persist it before promoting."
        )
    if not os.path.isfile(registry.version_path(version_string)):
        raise ModelNotAvailableError(
            f"Version {version_string!r} has no artifact on disk; refusing to promote."
        )
    registry.validate_artifact(registry.version_path(version_string), task_name)

    previous = (
        db.query(ModelVersion)
        .filter(ModelVersion.task_name == task_name, ModelVersion.is_accepted == True)  # noqa: E712
        .all()
    )
    for row in previous:
        if row.version_string != version_string:
            row.is_accepted = False
            row.promotion_state = "SUPERSEDED"

    target.is_accepted = True
    target.promotion_state = "PROMOTED"
    if reason:
        target.decision_reason = reason
    db.commit()
    clear_model_cache()
    return {"status": "PROMOTED", "task_name": task_name, "active_version": version_string}


def acceptance_gate(candidate_f1: float, active_f1: float) -> Tuple[bool, str]:
    """The reported promotion rule: held-out F1 above threshold and not worse."""
    if candidate_f1 <= ACCEPTANCE_F1_THRESHOLD:
        return False, (
            f"Candidate F1 ({candidate_f1:.4f}) did not exceed the required "
            f"{ACCEPTANCE_F1_THRESHOLD}."
        )
    if candidate_f1 < active_f1:
        return False, (
            f"Candidate F1 ({candidate_f1:.4f}) is below the active model F1 "
            f"({active_f1:.4f}); promotion would be a regression."
        )
    return True, (
        f"Candidate F1 ({candidate_f1:.4f}) > {ACCEPTANCE_F1_THRESHOLD} and is not "
        f"below the active F1 ({active_f1:.4f})."
    )


def train_and_evaluate_model(task_name: str, db: Session) -> Dict[str, Any]:
    """Compose the lifecycle for the API: train -> evaluate -> gate -> persist -> promote.

    A rejected candidate is never written to disk. The returned payload always
    carries the synthetic-label limitation so no consumer can present these
    numbers as production accuracy.
    """
    trained = train_candidate(task_name, db)
    if trained["status"] != "TRAINED":
        return trained

    clf = trained["classifier"]
    evaluation = evaluate_candidate(clf, trained["X_test"], trained["y_test"])
    feature_imp = feature_importances(clf, task_name)

    active = (
        db.query(ModelVersion)
        .filter(ModelVersion.task_name == task_name, ModelVersion.is_accepted == True)  # noqa: E712
        .order_by(ModelVersion.created_at.desc())
        .first()
    )
    current_f1 = float(active.f1_score) if active and active.f1_score is not None else 0.0
    previous_active_version = active.version_string if active else "base_model"

    accepted, reason = acceptance_gate(evaluation["f1_score"], current_f1)
    version_string = (
        f"v_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:4]}"
    )

    artifact_filename = None
    if accepted:
        persisted = persist_candidate(
            task_name=task_name,
            version_string=version_string,
            clf=clf,
            training_data_version=trained["training_data_version"],
            evaluation=evaluation,
            samples={
                "training": trained["training_samples"],
                "test": trained["test_samples"],
                "total": trained["training_samples"] + trained["test_samples"],
            },
            seed=trained["random_seed"],
        )
        artifact_filename = os.path.basename(persisted["artifact_path"])

    record = ModelVersion(
        version_string=version_string,
        task_name=task_name,
        is_accepted=accepted,
        accuracy=evaluation["accuracy"],
        f1_score=evaluation["f1_score"],
        precision=evaluation["precision"],
        recall=evaluation["recall"],
        training_samples=trained["training_samples"],
        model_config_json=json.dumps(trained["model_config"], sort_keys=True),
        random_seed=trained["random_seed"],
        feature_schema_version=trained["feature_schema_version"],
        feature_names_json=json.dumps(trained["feature_names"]),
        training_data_version=trained["training_data_version"],
        test_samples=trained["test_samples"],
        evaluation_json=json.dumps(evaluation),
        artifact_filename=artifact_filename,
        promotion_state="ACCEPTED" if accepted else "REJECTED",
        parent_version=previous_active_version,
        decision_reason=reason,
        sklearn_version=registry._sklearn_version(),
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    if accepted:
        promote_version(task_name, version_string, db, reason=reason)
        status_msg = "ACCEPTED"
    else:
        clear_model_cache()
        status_msg = "REJECTED"

    return {
        "status": status_msg,
        "candidate_version": version_string,
        "previous_active_version": previous_active_version,
        "active_model_version": version_string if accepted else previous_active_version,
        "decision": status_msg,
        "reason": reason,
        "threshold": ACCEPTANCE_F1_THRESHOLD,
        "f1_difference": evaluation["f1_score"] - current_f1,
        "training_examples": trained["training_samples"],
        "test_examples": trained["test_samples"],
        "class_distribution": trained["class_distribution"],
        "candidate_metrics": evaluation,
        "active_metrics": {"f1_score": current_f1},
        "feature_importances": feature_imp,
        "feature_names": trained["feature_names"],
        "feature_schema_version": trained["feature_schema_version"],
        "training_data_version": trained["training_data_version"],
        "model_config": trained["model_config"],
        "random_seed": trained["random_seed"],
        "artifact_filename": artifact_filename,
        "persisted": bool(artifact_filename),
        "adapted_at": datetime.now(timezone.utc).isoformat(),
        "limitation": SYNTHETIC_LABEL_LIMITATION,
    }


def rollback_model(task_name: str, target_version: str, db: Session) -> Dict[str, Any]:
    """Roll the active model back to a previously *accepted* version."""
    target = (
        db.query(ModelVersion)
        .filter(ModelVersion.version_string == target_version, ModelVersion.task_name == task_name)
        .first()
    )
    if not target:
        raise ValueError(f"Model version {target_version} not found.")

    path = registry.version_path(target_version)
    if not os.path.isfile(path):
        raise ValueError(
            f"Artifact for version {target_version} not found on disk. Rejected "
            f"candidates are never persisted, so only previously accepted versions "
            f"can be rolled back to."
        )
    try:
        metadata = registry.validate_artifact(path, task_name)
    except (ModelNotAvailableError, ModelIntegrityError) as exc:
        raise ValueError(str(exc)) from exc

    current = (
        db.query(ModelVersion)
        .filter(ModelVersion.task_name == task_name, ModelVersion.is_accepted == True)  # noqa: E712
        .first()
    )
    rolled_back_from = current.version_string if current else None
    if current:
        current.is_accepted = False
        current.promotion_state = "ROLLED_BACK"

    target.is_accepted = True
    target.promotion_state = "PROMOTED"
    db.commit()
    clear_model_cache()

    return {
        "status": "SUCCESS",
        "active_version": target_version,
        "rolled_back_from": rolled_back_from,
        "message": f"Successfully rolled back to {target_version}",
        "training_data_version": metadata.get("training_data_version"),
        "feature_schema_version": metadata.get("feature_schema_version"),
    }


def get_ml_readiness(db: Session) -> Dict[str, Any]:
    """What ML capability actually exists right now, per task.

    Reported so the UI/review can never claim a detector that is not deployed:
    an absent artifact, an artifact without provenance, and an untrained model
    are three different, explicitly named states.
    """
    inventory = registry.artifact_inventory()
    tasks: Dict[str, Any] = {}

    for task in MODEL_TASKS:
        base = registry.base_path(task)
        base_present = os.path.isfile(base)
        base_meta = registry.read_metadata(base) if base_present else None
        active = registry._active_version_row(db, task)

        serving = "base_model"
        state = "UNAVAILABLE"
        detail = ""
        if base_present and base_meta is None:
            state = "UNVERIFIED_PROVENANCE"
            detail = (
                "Artifact exists but has no metadata sidecar; the service refuses to "
                "score features against an unverified model."
            )
        elif base_present:
            state = "READY"
        if active is not None:
            serving = active.version_string
            candidate = registry.version_path(active.version_string)
            if os.path.isfile(candidate) and registry.read_metadata(candidate):
                state = "READY"
            else:
                detail = detail or (
                    f"Accepted version {active.version_string} has no verified artifact on disk."
                )

        tasks[task] = {
            "feature_names": feature_names_for(task),
            "feature_schema_version": feature_schema_version_for(task),
            "flagging_threshold": ML_FLAG_THRESHOLD if task == "port_scan" else AUTH_FLAG_THRESHOLD,
            "base_artifact_present": base_present,
            "base_artifact_verified": base_meta is not None,
            "active_version": active.version_string if active else None,
            "serving_from": serving if state == "READY" else None,
            "state": state,
            "detail": detail,
            "total_examples": db.query(LearningExample).filter(LearningExample.task_name == task).count(),
        }

    return {
        "tasks": tasks,
        "artifact_inventory": {
            "models_dir": inventory["models_dir"],
            "verified_artifacts": [a["filename"] for a in inventory["artifacts"]],
            "unverified_artifacts": [a["filename"] for a in inventory["unverified"]],
            "unverified_count": len(inventory["unverified"]),
        },
        "random_forest_baseline": registry_baseline(),
        "limitation": SYNTHETIC_LABEL_LIMITATION,
    }


def registry_baseline() -> Dict[str, Any]:
    from ml.features import RANDOM_FOREST_BASELINE

    return dict(RANDOM_FOREST_BASELINE)


def get_adaptive_status(task_name: str, db: Session) -> Dict[str, Any]:
    """Comprehensive state of the adaptive ML engine for one task."""
    active_model = (
        db.query(ModelVersion)
        .filter(ModelVersion.task_name == task_name, ModelVersion.is_accepted == True)  # noqa: E712
        .order_by(ModelVersion.created_at.desc())
        .first()
    )

    total_examples = db.query(LearningExample).filter(LearningExample.task_name == task_name).count()

    if active_model:
        new_examples = db.query(LearningExample).filter(
            LearningExample.task_name == task_name,
            LearningExample.created_at > active_model.created_at,
        ).count()
    else:
        new_examples = total_examples

    last_candidate = (
        db.query(ModelVersion)
        .filter(ModelVersion.task_name == task_name)
        .order_by(ModelVersion.created_at.desc())
        .first()
    )

    history_records = (
        db.query(ModelVersion)
        .filter(ModelVersion.task_name == task_name)
        .order_by(ModelVersion.created_at.desc())
        .limit(10)
        .all()
    )
    history = []
    for row in history_records:
        history.append({
            "version": row.version_string,
            "f1_score": row.f1_score,
            "is_accepted": row.is_accepted,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "training_samples": row.training_samples,
            "promotion_state": row.promotion_state,
            "parent_version": row.parent_version,
            "training_data_version": row.training_data_version,
            "feature_schema_version": row.feature_schema_version,
            "artifact_filename": row.artifact_filename,
            "decision_reason": row.decision_reason,
        })

    class_dist = dict(
        db.query(LearningExample.label, func.count(LearningExample.label))
        .filter(LearningExample.task_name == task_name)
        .group_by(LearningExample.label)
        .all()
    )
    normal_count = int(class_dist.get(0, 0))
    attack_count = int(class_dist.get(1, 0))

    status = "NO_NEW_DATA"
    if total_examples < MIN_TRAINING_EXAMPLES:
        status = "NOT_READY"
    elif normal_count < MIN_EXAMPLES_PER_CLASS or attack_count < MIN_EXAMPLES_PER_CLASS:
        status = "INSUFFICIENT_CLASSES"
    elif new_examples > 0:
        status = "NEW_DATA_AVAILABLE"
        if new_examples >= 5:
            status = "READY_FOR_TRAINING"

    readiness = get_ml_readiness(db)["tasks"].get(task_name, {})

    return {
        "task_name": task_name,
        "current_version": active_model.version_string if active_model else "base_model",
        "total_examples": total_examples,
        "new_examples": new_examples,
        "training_samples": active_model.training_samples if active_model else 0,
        "metrics": {
            "f1_score": active_model.f1_score,
            "accuracy": active_model.accuracy,
            "precision": active_model.precision,
            "recall": active_model.recall,
        } if active_model else None,
        "last_trained": last_candidate.created_at.isoformat() if last_candidate and last_candidate.created_at else None,
        "last_decision": (
            "ACCEPTED" if last_candidate and last_candidate.is_accepted
            else "REJECTED" if last_candidate
            else None
        ),
        "status": status,
        "history": history,
        "feature_names": readiness.get("feature_names"),
        "feature_schema_version": readiness.get("feature_schema_version"),
        "model_config": json.loads(active_model.model_config_json) if active_model and active_model.model_config_json else registry_baseline(),
        "random_seed": active_model.random_seed if active_model else None,
        "training_data_version": active_model.training_data_version if active_model else None,
        "model_readiness": readiness,
        "limitation": SYNTHETIC_LABEL_LIMITATION,
    }
