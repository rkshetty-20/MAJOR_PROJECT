"""Safely connect validated Studio datasets to the Adaptive Learning workflow
(Milestone 6).

After a Studio dataset has been compiled *and* replayed/evaluated, an analyst may
choose to promote it into the existing learning-example pool so the port-scan /
authentication models can be retrained. This module is the guarded bridge between
the Studio pipeline and ``ml_engine``'s existing lifecycle. It does NOT train or
activate anything itself — it only appends :class:`LearningExample` rows that the
unchanged ``train_and_evaluate_model`` acceptance gate later consumes.

Ground-truth and safety guarantees enforced here:

    * Trusted ground truth only — labels are taken from the spec's design-time
      ``event_templates`` (never from the detector being evaluated, never from an
      LLM's own assertion).
    * Compatible feature schema only — phishing is heuristic-only and can never be
      imported as an ML training example.
    * Appropriate dataset role — only ``training`` datasets are eligible.
      ``validation`` and ``test`` datasets are protected from being pulled into the
      training pool, so an untouched hold-out can never be silently consumed.
    * No cross-partition leakage — the same scenario/campaign cannot be imported
      under two conflicting partition roles.
    * Duplicate protection — a dataset is imported at most once (idempotent).
    * Model activation is left entirely to the existing F1 acceptance gate.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models import Dataset, EvaluationRun, LearningExample
from app.services.scenario_simulator.spec import (
    DatasetRole,
    GroundTruthSource,
    ScenarioSpec,
)
from ml.features import extract_auth_features, extract_features

logger = logging.getLogger(__name__)

# Studio categories that map onto an existing ML task. Phishing is intentionally
# absent: it is heuristic-only and therefore never a training candidate.
_ML_TASK_BY_CATEGORY: Dict[str, str] = {
    "port_scan": "port_scan",
    "brute_force": "brute_force",
    "credential_stuffing": "credential_stuffing",
}

_FEATURE_SCHEMA_VERSION = {
    "port_scan": "1.0",
    "brute_force": "1.0_auth",
    "credential_stuffing": "1.0_auth",
}


class LearningImportError(ValueError):
    """Raised when a dataset cannot be imported for learning (ineligible)."""


def _load_studio_dataset(dataset_id: str, db: Session):
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise LearningImportError("Dataset not found")
    if not dataset.scenario_spec_json:
        raise LearningImportError("Dataset is not a Studio scenario.")
    return dataset


def _latest_completed_run(dataset_id: str, db: Session) -> Optional[EvaluationRun]:
    return (
        db.query(EvaluationRun)
        .filter(
            EvaluationRun.dataset_id == dataset_id,
            EvaluationRun.status == "completed",
        )
        .order_by(EvaluationRun.started_at.desc())
        .first()
    )


def _build_template_label_map(spec: ScenarioSpec) -> Dict[str, tuple]:
    """Map ``template_id -> (label, source)`` from the spec's trusted ground truth."""
    return {
        t.template_id: (int(t.ground_truth_label), t.ground_truth_source)
        for t in spec.event_templates
    }


def _all_templates_verified(spec: ScenarioSpec) -> bool:
    return all(
        t.ground_truth_source != GroundTruthSource.UNVERIFIED for t in spec.event_templates
    )


def _campaign_role_conflict(dataset: Dataset, db: Session) -> Optional[str]:
    """Return the conflicting role if another dataset of the same scenario/campaign
    was already imported into the learning pool under a different partition role.

    This prevents events from the same campaign leaking across train/validation/test
    partitions (e.g. importing a scenario for training after its hold-out sibling was
    used to report an untouched test result).
    """
    imported_sims = {
        row[0]
        for row in db.query(LearningExample.source_simulation).distinct().all()
        if row[0]
    }
    if not imported_sims:
        return None
    siblings = (
        db.query(Dataset)
        .filter(
            Dataset.scenario_id == dataset.scenario_id,
            Dataset.id.in_(imported_sims),
        )
        .all()
    )
    for sib in siblings:
        if sib.dataset_role and dataset.dataset_role and sib.dataset_role != dataset.dataset_role:
            return sib.dataset_role
    return None


def evaluate_learning_eligibility(dataset_id: str, db: Session) -> Dict[str, Any]:
    """Return a structured eligibility report without importing anything."""
    dataset = _load_studio_dataset(dataset_id, db)
    spec = ScenarioSpec(**json.loads(dataset.scenario_spec_json))

    reasons: List[str] = []
    task_name = _ML_TASK_BY_CATEGORY.get(spec.attack_category.value)

    # 1. Category-specific ML support (phishing is heuristic-only).
    if task_name is None:
        reasons.append(
            f"Category '{spec.attack_category.value}' is heuristic-only and not eligible for ML training."
        )

    # 2. Trusted ground truth present and not unverified.
    if not dataset.ground_truth_available:
        reasons.append("Dataset has no trusted ground-truth labels.")
    elif not _all_templates_verified(spec):
        reasons.append("One or more event templates have unverified ground truth.")

    # 3. Appropriate dataset role.
    if dataset.dataset_role != DatasetRole.TRAINING.value:
        reasons.append(
            f"Dataset role '{dataset.dataset_role}' is protected; only 'training' datasets "
            "may be imported for learning."
        )

    # 4. Must have been evaluated (valid event schema exercised against detectors).
    latest_run = _latest_completed_run(dataset_id, db)
    if latest_run is None:
        reasons.append("Dataset has not been successfully replayed/evaluated yet.")

    # 5. Cross-partition campaign leakage guard.
    conflict = _campaign_role_conflict(dataset, db)
    if conflict:
        reasons.append(
            f"Scenario '{dataset.scenario_id}' was already imported under a conflicting "
            f"partition role '{conflict}'; importing it here would leak across partitions."
        )

    already_imported = (
        db.query(LearningExample).filter(LearningExample.source_simulation == dataset.id).count()
    )

    eligible = len(reasons) == 0 and already_imported == 0
    return {
        "dataset_id": dataset.id,
        "scenario_id": dataset.scenario_id,
        "attack_category": dataset.scenario_category,
        "task_name": task_name,
        "dataset_role": dataset.dataset_role,
        "ground_truth_available": dataset.ground_truth_available,
        "is_evaluated": latest_run is not None,
        "already_imported": already_imported,
        "eligible": eligible,
        "can_reimport": already_imported > 0 and len(reasons) == 0,
        "reasons": reasons,
    }


def _group_events_by_source(events: List[Dict[str, Any]], event_type: str) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        if ev.get("type") != event_type:
            continue
        key = ev.get("src_ip") if event_type == "network" else ev.get("source")
        if not key:
            continue
        grouped.setdefault(str(key), []).append(ev)
    return grouped


def _label_from_templates(group_events: List[Dict[str, Any]], label_map: Dict[str, tuple]):
    """Derive a trusted (label, source) for a group from design-time template labels."""
    label = 0
    source = GroundTruthSource.SCENARIO_DESIGN.value
    for ev in group_events:
        entry = label_map.get(ev.get("_template_id"))
        if not entry:
            continue
        ev_label, ev_source = entry
        if ev_label == 1:
            label = 1
            source = ev_source.value
    # When fully benign, surface the benign template's declared source.
    if label == 0:
        for ev in group_events:
            entry = label_map.get(ev.get("_template_id"))
            if entry:
                source = entry[1].value
                break
    return label, source


def import_dataset_learning_examples(dataset_id: str, db: Session) -> Dict[str, Any]:
    """Import a validated, evaluated Studio dataset as learning examples.

    Raises :class:`LearningImportError` if the dataset is not eligible. On success
    appends one :class:`LearningExample` per meaningful source group, marked with the
    dataset id for duplicate protection and provenance.
    """
    eligibility = evaluate_learning_eligibility(dataset_id, db)
    if not eligibility["eligible"]:
        # Idempotent fast-path: already imported and still otherwise valid.
        if eligibility["can_reimport"]:
            return {**eligibility, "imported": 0, "status": "ALREADY_IMPORTED"}
        raise LearningImportError("; ".join(eligibility["reasons"]) or "Dataset is not eligible.")

    dataset = _load_studio_dataset(dataset_id, db)
    spec = ScenarioSpec(**json.loads(dataset.scenario_spec_json))
    task_name = eligibility["task_name"]
    is_auth = task_name in ("brute_force", "credential_stuffing")
    event_type = "auth" if is_auth else "network"

    events = json.loads(dataset.payload_json)
    label_map = _build_template_label_map(spec)

    imported = 0
    for src, group in _group_events_by_source(events, event_type).items():
        label, source = _label_from_templates(group, label_map)
        if is_auth:
            feat = extract_auth_features(group)
            meaningful = feat.get("failed_attempts", 0) > 0 or feat.get("successful_attempts", 0) > 0
        else:
            feat = extract_features(group)
            meaningful = feat.get("events_per_second", 0) > 0 or feat.get("distinct_dest_ports", 0) > 0
        if not meaningful:
            continue

        db.add(
            LearningExample(
                # No session link: provenance is the dataset itself, not an ephemeral replay session.
                session_id=None,
                task_name=task_name,
                label=label,
                feature_json=json.dumps(feat, sort_keys=True),
                source_simulation=dataset.id,
                category=spec.attack_category.value,
                feature_schema_version=_FEATURE_SCHEMA_VERSION[task_name],
                trusted_label_source=source,
                relevant_event_identifiers=json.dumps(
                    sorted({ev.get("_template_id") for ev in group if ev.get("_template_id")})
                ),
            )
        )
        imported += 1

    db.commit()
    logger.info("Imported %d learning example(s) from Studio dataset %s", imported, dataset.id)

    return {
        **evaluate_learning_eligibility(dataset_id, db),
        "imported": imported,
        "status": "IMPORTED",
    }
