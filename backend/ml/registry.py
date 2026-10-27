"""Model artifact registry: deterministic loading, metadata and provenance.

Every persisted estimator must ship with a JSON sidecar recording the feature
schema it was trained against, its hyper-parameters, the random seed, the
identity of the training data and the evaluation results. Loading an artifact
without matching metadata fails loudly instead of silently serving a model whose
inputs cannot be verified - the paper's reproducibility claim depends on that.

This module owns artifact *storage* only. Training, evaluation, promotion and
rollback *operations* live in ``app.services.ml_engine``.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import joblib

from ml.features import (
    FEATURE_SCHEMA_VERSION,
    AUTH_FEATURE_SCHEMA_VERSION,
    FeatureSchemaError,
    build_classifier,
    describe_classifier,
    feature_names_for,
    feature_schema_version_for,
)

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "models"))

# Bundled, paper-reported base artifacts. These are the models that exist before
# any adaptive training has been promoted.
BASE_ARTIFACTS: Dict[str, str] = {
    "port_scan": "port_scan_rf.joblib",
    "brute_force": "brute_force_rf.joblib",
    "credential_stuffing": "brute_force_rf.joblib",
}

TASKS: List[str] = ["port_scan", "brute_force", "credential_stuffing"]

REGISTRY_VERSION = "1.0"

# Default estimator/generator seed for the paper's baseline.
TRAINING_SEED = 42

# The paper's own caveat about synthetic evaluation. Kept in the registry so the
# trainer, the artifact metadata and the serving layer all quote one text.
SYNTHETIC_LIMITATION = (
    "Reported metrics are measured on a synthetic hold-out whose labels are "
    "derived from the scenario generator's own signatures. Perfect synthetic "
    "accuracy does not establish real-world generalization and must not be "
    "quoted as production detection performance."
)


class ModelNotAvailableError(RuntimeError):
    """No usable model artifact (or metadata) exists for a requested task."""


class ModelIntegrityError(RuntimeError):
    """An artifact exists but contradicts its recorded provenance/schema."""


def _ensure_dir() -> str:
    os.makedirs(MODELS_DIR, exist_ok=True)
    return MODELS_DIR


def base_path(task_name: str) -> str:
    """Path of the bundled base artifact for a task (may not exist on disk)."""
    filename = BASE_ARTIFACTS.get(task_name)
    if not filename:
        raise ModelNotAvailableError(
            f"No bundled base artifact is declared for task {task_name!r}. "
            f"Known tasks: {sorted(BASE_ARTIFACTS)}."
        )
    return os.path.join(MODELS_DIR, filename)


def version_path(version_string: str) -> str:
    return os.path.join(_ensure_dir(), f"{version_string}.joblib")


def metadata_path(artifact_path: str) -> str:
    """``x.joblib`` -> ``x.meta.json`` sidecar next to the artifact."""
    stem, _ext = os.path.splitext(artifact_path)
    return f"{stem}.meta.json"


def training_data_version(rows: Iterable[Any]) -> str:
    """Deterministic digest identifying the exact training set used.

    Accepts :class:`LearningExample` ORM rows or ``(feature_json, label)``
    tuples; order-independent so re-running training over the same data yields
    the same identifier.
    """
    material: List[str] = []
    for row in rows:
        if isinstance(row, tuple):
            feature_json, label = row[0], row[1]
        else:
            feature_json, label = row.feature_json, row.label
        material.append(f"{feature_json}|{label}")
    digest = hashlib.sha256("\n".join(sorted(material)).encode("utf-8")).hexdigest()
    return f"sha256:{digest[:16]}"


def write_metadata(artifact_path: str, payload: Dict[str, Any]) -> str:
    """Persist model provenance next to the artifact and return its path."""
    path = metadata_path(artifact_path)
    record = dict(payload)
    record.setdefault("registry_version", REGISTRY_VERSION)
    record["artifact_filename"] = os.path.basename(artifact_path)
    record.setdefault("written_at", datetime.now(timezone.utc).isoformat())
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
    return path


def read_metadata(artifact_path: str) -> Optional[Dict[str, Any]]:
    path = metadata_path(artifact_path)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def save_model(clf: Any, artifact_path: str, *, task_name: str,
               training_data_digest: str, config: Dict[str, Any],
               evaluation: Dict[str, Any], seed: int,
               random_seed: Optional[int] = None,
               samples: Optional[Dict[str, Any]] = None,
               limitations: Optional[str] = None) -> Dict[str, Any]:
    """Dump an estimator together with its mandatory metadata sidecar."""
    _ensure_dir()
    joblib.dump(clf, artifact_path)
    schema_version = feature_schema_version_for(task_name)
    payload = {
        "task_name": task_name,
        "feature_names": feature_names_for(task_name),
        "feature_schema_version": schema_version,
        "model_config": config,
        "random_seed": seed,
        "data_random_seed": random_seed,
        "training_data_version": training_data_digest,
        "evaluation": evaluation,
        "samples": samples or {},
        "n_features_in": getattr(clf, "n_features_in_", None),
        "sklearn_version": _sklearn_version(),
        "limitations": limitations or "",
    }
    write_metadata(artifact_path, payload)
    return payload


def _sklearn_version() -> str:
    try:
        import sklearn

        return sklearn.__version__
    except Exception:  # pragma: no cover - version reporting must not block IO
        return "unknown"


def validate_artifact(artifact_path: str, task_name: Optional[str] = None,
                      metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return the verified metadata for an artifact, or raise meaningfully."""
    if not os.path.isfile(artifact_path):
        raise ModelNotAvailableError(
            f"Model artifact '{os.path.basename(artifact_path)}' is not present in "
            f"{MODELS_DIR}. Train it first (ml/train_port_scan_model.py or "
            f"POST /api/ml/train) or roll back to a promoted version."
        )

    meta = metadata if metadata is not None else read_metadata(artifact_path)
    if meta is None:
        raise ModelIntegrityError(
            f"Model artifact '{os.path.basename(artifact_path)}' has no "
            f"'{os.path.basename(metadata_path(artifact_path))}' sidecar, so its "
            f"feature schema, seed and evaluation results cannot be verified. "
            f"Re-train and promote it to regenerate provenance."
        )

    task = task_name or meta.get("task_name")
    if not task:
        raise ModelIntegrityError(
            f"Metadata for '{os.path.basename(artifact_path)}' does not record a task_name."
        )

    declared = feature_names_for(task)
    recorded = meta.get("feature_names")
    if recorded and recorded != declared:
        raise ModelIntegrityError(
            f"{task}: artifact was trained on feature set {recorded} but the service "
            f"expects {declared}. Refusing to score features the model never saw."
        )
    expected_version = feature_schema_version_for(task)
    if meta.get("feature_schema_version") not in (None, expected_version):
        raise ModelIntegrityError(
            f"{task}: artifact feature schema version "
            f"{meta.get('feature_schema_version')!r} does not match the service "
            f"schema {expected_version!r}."
        )
    n_features = meta.get("n_features_in")
    if n_features is not None and int(n_features) != len(declared):
        raise ModelIntegrityError(
            f"{task}: artifact exposes {n_features} inputs for a {len(declared)}-feature schema."
        )
    return meta


def load_verified(artifact_path: str, task_name: Optional[str] = None):
    """Validate an artifact's provenance and load it, attaching the metadata."""
    metadata = validate_artifact(artifact_path, task_name)
    try:
        clf = joblib.load(artifact_path)
    except Exception as exc:  # unreadable/corrupt/incompatible pickle
        raise ModelIntegrityError(
            f"Model artifact '{os.path.basename(artifact_path)}' could not be loaded: {exc}"
        ) from exc
    clf._loaded_path = artifact_path
    clf._metadata = metadata
    return clf


def load_model(db: Any, task_name: str, version_string: Optional[str] = None):
    """Load the active (or explicitly requested) model for a task.

    Resolution order: an accepted :class:`ModelVersion` row with a present
    artifact, else the bundled base artifact. Raises
    :class:`ModelNotAvailableError` / :class:`ModelIntegrityError` with an
    actionable message; it never returns ``None`` silently.
    """
    if version_string:
        artifact = version_path(version_string)
        if not os.path.isfile(artifact):
            raise ModelNotAvailableError(
                f"Requested model version {version_string!r} has no artifact in {MODELS_DIR}."
            )
    else:
        artifact = None
        active = _active_version_row(db, task_name) if db is not None else None
        if active is not None:
            candidate = version_path(active.version_string)
            if os.path.isfile(candidate):
                artifact = candidate
        if artifact is None:
            artifact = base_path(task_name)

    return load_verified(artifact, task_name)


def _active_version_row(db: Any, task_name: str):
    from app.models import ModelVersion

    return (
        db.query(ModelVersion)
        .filter(ModelVersion.task_name == task_name, ModelVersion.is_accepted == True)  # noqa: E712
        .order_by(ModelVersion.created_at.desc())
        .first()
    )


def artifact_inventory() -> Dict[str, Any]:
    """Describe what actually exists on disk - including unverified artifacts.

    Used by the readiness diagnostics so the UI can never claim ML coverage that
    is not backed by a loadable artifact plus matching provenance.
    """
    if not os.path.isdir(MODELS_DIR):
        return {"models_dir": MODELS_DIR, "artifacts": [], "unverified": []}

    artifacts, unverified = [], []
    for filename in sorted(os.listdir(MODELS_DIR)):
        if not filename.endswith(".joblib"):
            continue
        path = os.path.join(MODELS_DIR, filename)
        meta = read_metadata(path)
        entry = {
            "filename": filename,
            "size_bytes": os.path.getsize(path),
            "has_metadata": meta is not None,
            "task_name": (meta or {}).get("task_name"),
            "feature_schema_version": (meta or {}).get("feature_schema_version"),
            "training_data_version": (meta or {}).get("training_data_version"),
        }
        (artifacts if meta else unverified).append(entry)
    return {
        "models_dir": MODELS_DIR,
        "artifact_count": len(artifacts) + len(unverified),
        "artifacts": artifacts,
        "unverified": unverified,
    }


__all__ = [
    "AUTH_FEATURE_SCHEMA_VERSION",
    "BASE_ARTIFACTS",
    "FEATURE_SCHEMA_VERSION",
    "MODELS_DIR",
    "ModelIntegrityError",
    "ModelNotAvailableError",
    "REGISTRY_VERSION",
    "TASKS",
    "artifact_inventory",
    "base_path",
    "build_classifier",
    "describe_classifier",
    "load_model",
    "load_verified",
    "metadata_path",
    "read_metadata",
    "save_model",
    "training_data_version",
    "validate_artifact",
    "version_path",
    "write_metadata",
]
