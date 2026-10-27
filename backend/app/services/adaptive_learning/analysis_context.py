"""Learning Analysis Service (spec section 3.A, inputs from section 4).

Assembles a compact, sanitized, DB-grounded analysis context from persisted
records for a completed :class:`EvaluationRun`. This is the *only* thing the LLM
is shown: it never receives raw payloads, credentials, or secrets, and the same
context seeds the reference-validation performed by
:mod:`app.services.adaptive_learning.validator`.

Design guarantees:
    * Only real, persisted identifiers are exposed as referenceable evidence.
    * Secrets and API-key-shaped strings are redacted before hashing/handoff.
    * A deterministic ``context_sha256`` over the redacted context supports
      idempotent re-analysis (spec section 14).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Set

from sqlalchemy.orm import Session as DBSession

from app.models.models import (
    Dataset,
    Detection,
    EvaluationRun,
    LearningExample,
)
from app.services.ml_engine import _get_active_version
from app.services.scenario_simulator.learning_import import (
    _FEATURE_SCHEMA_VERSION,
    _ML_TASK_BY_CATEGORY,
)
from app.services.scenario_simulator.spec import AttackCategory
from ml.features import AUTH_FEATURE_NAMES, FEATURE_NAMES


# Supported attack categories (must match a working detector/eval route).
_SUPPORTED_CATEGORIES: Set[str] = {c.value for c in AttackCategory}

# Heuristic-only categories (analyzable but never ML-retrainable).
_HEURISTIC_ONLY: Set[str] = {"phishing_url"}

# Redaction patterns: never let a secret-shaped string reach the provider or logs.
_SECRET_KEY_PATTERN = re.compile(
    r"(api[_-]?key|authorization|token|secret|password|passwd|credential)", re.IGNORECASE
)
_API_KEY_VALUE_PATTERN = re.compile(r"(sk-[A-Za-z0-9]{8,}|Bearer\s+\S+|AIza[\w-]{8,})")


class AnalysisInputError(Exception):
    """Raised when a request targets an unknown or not-completed EvaluationRun."""

    def __init__(self, message: str, *, not_found: bool = False) -> None:
        super().__init__(message)
        self.not_found = not_found


def _redact(value: Any) -> Any:
    """Recursively strip secret-shaped keys/values from a context structure."""
    if isinstance(value, dict):
        cleaned: Dict[str, Any] = {}
        for key, val in value.items():
            if _SECRET_KEY_PATTERN.search(str(key)):
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = _redact(val)
        return cleaned
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, str):
        return _API_KEY_VALUE_PATTERN.sub("[REDACTED]", value)
    return value


def _registered_features(task_name: Optional[str]) -> List[str]:
    """Return the ground-truth feature names for a model task."""
    if task_name == "port_scan":
        return list(FEATURE_NAMES)
    if task_name in {"brute_force", "credential_stuffing"}:
        return list(AUTH_FEATURE_NAMES)
    return []


def build_analysis_context(evaluation_run_id: str, db: DBSession) -> Dict[str, Any]:
    """Collect and sanitize persisted evidence for one completed evaluation run.

    Raises :class:`AnalysisInputError` (``not_found=True`` for an unknown id,
    ``not_found=False`` for a run that is not in the ``completed`` state).
    """
    eval_run = (
        db.query(EvaluationRun).filter(EvaluationRun.id == evaluation_run_id).first()
    )
    if eval_run is None:
        raise AnalysisInputError("Evaluation run not found.", not_found=True)
    if eval_run.status != "completed":
        raise AnalysisInputError(
            f"Evaluation run is not completed (status='{eval_run.status}').",
            not_found=False,
        )

    dataset = db.query(Dataset).filter(Dataset.id == eval_run.dataset_id).first()
    if dataset is None:
        raise AnalysisInputError("Dataset for this evaluation run no longer exists.", not_found=True)

    attack_category = dataset.scenario_category
    if attack_category not in _SUPPORTED_CATEGORIES:
        # Still analyzable, but flagged so the validator can reject ML-retraining
        # and the analyst can honestly report an unsupported category.
        pass

    task_name = _ML_TASK_BY_CATEGORY.get(attack_category)
    is_heuristic_only = attack_category in _HEURISTIC_ONLY

    # Comparison (expected vs actual). Generic replay runs may lack it.
    comparison: Optional[Dict[str, Any]] = None
    if eval_run.comparison_json:
        try:
            comparison = json.loads(eval_run.comparison_json)
        except (json.JSONDecodeError, TypeError):
            comparison = None

    # Representative detection events from the replay session (real, referenceable ids).
    detections_summary: List[Dict[str, Any]] = []
    allowed_ids: Set[str] = {eval_run.id, dataset.id}
    if eval_run.session_id is not None:
        for det in db.query(Detection).filter(Detection.session_id == eval_run.session_id).all():
            detections_summary.append(
                {"id": str(det.id), "label": det.label, "source": str(det.source)}
            )
            allowed_ids.add(str(det.id))

    # Active model for this task (None => rules-only / no adaptive model active).
    active_model = None
    if task_name is not None:
        version_row = _get_active_version(db, task_name)
        if version_row is not None:
            active_model = {
                "version_string": version_row.version_string,
                "task_name": version_row.task_name,
                "f1_score": version_row.f1_score,
                "precision": version_row.precision,
                "recall": version_row.recall,
                "accuracy": version_row.accuracy,
                "training_samples": version_row.training_samples,
            }
            allowed_ids.add(version_row.version_string)

    # Learning examples already imported from this dataset (referenceable ids).
    learning_example_ids: List[str] = []
    for ex in (
        db.query(LearningExample)
        .filter(LearningExample.source_simulation == dataset.id)
        .limit(50)
        .all()
    ):
        learning_example_ids.append(str(ex.id))
        allowed_ids.add(str(ex.id))

    # The replay's own model_version string is a valid reference too.
    if eval_run.model_version and eval_run.model_version != "rules_only":
        allowed_ids.add(eval_run.model_version)

    context: Dict[str, Any] = {
        "evaluation_run": {
            "id": eval_run.id,
            "dataset_id": eval_run.dataset_id,
            "detector_type": eval_run.detector_type,
            "model_version": eval_run.model_version,
            "events_processed": eval_run.events_processed,
            "detections_output": eval_run.detections_output,
            "true_positives": eval_run.true_positives,
            "false_positives": eval_run.false_positives,
            "false_negatives": eval_run.false_negatives,
            "precision": eval_run.precision,
            "recall": eval_run.recall,
            "f1_score": eval_run.f1_score,
            "status": eval_run.status,
        },
        "dataset": {
            "id": dataset.id,
            "attack_category": attack_category,
            "scenario_category": dataset.scenario_category,
            "dataset_role": dataset.dataset_role,
            "ground_truth_available": bool(dataset.ground_truth_available),
            "is_synthetic": bool(dataset.is_synthetic),
            "is_training_eligible": bool(dataset.is_training_eligible),
            "generator_version": dataset.generator_version,
            "llm_input_sha256": dataset.llm_input_sha256,
        },
        "supported_categories": sorted(_SUPPORTED_CATEGORIES),
        "is_heuristic_only": is_heuristic_only,
        "ml_task": task_name,
        "feature_schema_version": _FEATURE_SCHEMA_VERSION.get(attack_category) if task_name else None,
        "registered_features": _registered_features(task_name),
        "active_model": active_model,
        "comparison": comparison,
        "detections": detections_summary,
        "learning_example_ids": learning_example_ids,
        # Grounding set handed to the validator.
        "referenceable_ids": sorted(allowed_ids),
    }

    redacted = _redact(context)
    canonical = json.dumps(redacted, sort_keys=True, separators=(",", ":"), default=str)
    redacted["context_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return redacted
