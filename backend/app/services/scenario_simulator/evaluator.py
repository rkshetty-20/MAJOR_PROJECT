"""Expected-vs-actual replay evaluation for Studio-compiled datasets (Milestone 4).

Reuses the *existing* detection engines (``rule_engine.evaluate_rules`` and
``ml_engine.evaluate_ml``) unchanged, and adds what the generic replay path
could not do for Studio datasets:

    * Materialize each compiled event into the correct telemetry table —
      network events become ``SuricataEvent`` rows (so the port-scan rule *and*
      the Random-Forest ML path can see them), while auth / phishing events
      become ``SecurityEvent`` rows (so the behavioral auth rules and the offline
      phishing heuristic can see them).
    * Compare ACTUAL detections against the scenario's trusted EXPECTED labels
      taken from ``expected_outcomes`` in the preserved spec. Expected labels are
      authored at design time (IDS signature / scenario design / heuristic policy)
      and are NEVER derived from the detector being evaluated.

Ground-truth integrity is preserved: the evaluation only reads the spec's
expected labels and the engines' actual labels; it never rewrites either.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models import (
    Dataset,
    Detection,
    EvaluationRun,
    SecurityEvent,
    Session as SessionModel,
    SessionStatus,
    SuricataEvent,
)
from app.services.ml_engine import evaluate_ml
from app.services.rule_engine import evaluate_rules
from app.services.scenario_simulator.spec import SYNTHETIC_NO_SIGNATURE, ScenarioSpec

logger = logging.getLogger(__name__)

_DETECTOR_TYPE_BY_CATEGORY = {
    "port_scan": "network",
    "brute_force": "auth",
    "credential_stuffing": "auth",
    "phishing_url": "phishing",
}


def get_dataset_lifecycle(dataset_id: str, db: Session) -> Dict[str, Any]:
    """Return the five kept-separate lifecycle layers + provenance for a dataset.

    The Explorer uses this to show that ground truth, telemetry, detections and
    evaluation are distinct artifacts, each traceable to the scenario plan. Layers
    are read from storage only; nothing here re-derives labels from detector output.
    """
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise ReplayError("Dataset not found")
    if not dataset.scenario_spec_json:
        raise ReplayError("Dataset is not a Studio scenario.")

    spec = ScenarioSpec(**json.loads(dataset.scenario_spec_json))

    # Latest completed evaluation for this dataset (provenance link to its session).
    latest_run = (
        db.query(EvaluationRun)
        .filter(EvaluationRun.dataset_id == dataset_id)
        .order_by(EvaluationRun.started_at.desc())
        .first()
    )

    detections: List[Dict[str, Any]] = []
    if latest_run and latest_run.session_id:
        for d in db.query(Detection).filter(Detection.session_id == latest_run.session_id).all():
            detections.append(
                {
                    "id": d.id,
                    "label": d.label,
                    "source": d.source.value if hasattr(d.source, "value") else str(d.source),
                    "confidence": d.confidence,
                    "explanation": d.explanation,
                }
            )

    comparison = json.loads(latest_run.comparison_json) if (latest_run and latest_run.comparison_json) else None

    return {
        "provenance": {
            "dataset_id": dataset.id,
            "scenario_id": dataset.scenario_id,
            "schema_version": dataset.schema_version,
            "generator_version": dataset.generator_version,
            "dataset_role": dataset.dataset_role,
            "llm_input_sha256": dataset.llm_input_sha256,
            "source": spec.generation_provenance.source,
            "model": spec.generation_provenance.model,
            "correlation_id": spec.generation_provenance.request_correlation_id,
            "created_at": dataset.created_at.isoformat() if dataset.created_at else None,
        },
        "layer_plan": {
            "title": spec.title,
            "description": spec.description,
            "attack_category": spec.attack_category.value,
            "intensity": spec.intensity.value,
            "stages": [s.model_dump(mode="json") for s in spec.stages],
            "entity_templates": [e.model_dump(mode="json") for e in spec.entity_templates],
            "evaluation_objective": spec.evaluation_objective,
        },
        "layer_telemetry": {
            "events_count": dataset.events_count,
            "events": json.loads(dataset.payload_json),
        },
        "layer_ground_truth": {
            "note": "Design-time labels, kept separate from observable telemetry.",
            "per_template": [
                {
                    "template_id": t.template_id,
                    "ground_truth_label": t.ground_truth_label,
                    "ground_truth_source": t.ground_truth_source.value,
                }
                for t in spec.event_templates
            ],
            "expected_outcomes": [o.model_dump(mode="json") for o in spec.expected_outcomes],
            "is_verified": dataset.ground_truth_available,
        },
        "layer_detections": detections,
        "layer_evaluation": {
            "run_id": latest_run.id if latest_run else None,
            "status": latest_run.status if latest_run else None,
            "metrics": {
                "precision": latest_run.precision,
                "recall": latest_run.recall,
                "f1_score": latest_run.f1_score,
            }
            if latest_run
            else None,
            "comparison": comparison,
        },
    }



class ReplayError(ValueError):
    """Raised when a dataset cannot be replayed (missing artifacts, bad payload)."""


def _parse_ts(value: Any, index: Optional[int] = None) -> datetime:
    """Parse a compiled timestamp, refusing to invent one.

    This used to fall back to ``datetime.now(timezone.utc)``. In a replay path that
    is the worst possible default: a corrupted payload silently becomes "traffic
    that happened just now", so the replay stops being reproducible and the
    corruption stays invisible. A missing or unparsable timestamp is a defect in
    the dataset, so it is raised instead of being papered over.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            dt = None
        if dt is not None:
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    where = f"Event {index}" if index is not None else "Event"
    raise ReplayError(
        f"{where} has no parsable timestamp ({value!r}); replay refuses to substitute "
        "wall-clock time because the compiled payload is meant to be deterministic."
    )


def _resolve_scenarios(db: Session) -> Dict[str, int]:
    """Map studio categories to existing Scenario row ids (creates a port_scan row
    so the ML dispatch can find a matching scenario category)."""
    from app.services.simulation_service import _resolve_scenario_record

    scenario_ids: Dict[str, int] = {}
    for key in ("port_scan", "brute_force", "credential_stuffing", "phishing_url"):
        try:
            scenario_ids[key] = _resolve_scenario_record(key, db).id
        except Exception:  # pragma: no cover - defensive
            scenario_ids[key] = 1
    return scenario_ids


def _materialize_events(events: List[Dict[str, Any]], session_id: int, category: str, simulation_id: str, db: Session) -> int:
    created = 0
    for index, ev in enumerate(events):
        etype = ev.get("type")
        ts = _parse_ts(ev.get("timestamp"), index)
        if etype == "network":
            db.add(
                SuricataEvent(
                    session_id=session_id,
                    raw_signature=str(ev.get("raw_signature", SYNTHETIC_NO_SIGNATURE)),
                    src_ip=str(ev.get("src_ip", "unknown")),
                    dest_ip=str(ev.get("dest_ip", "unknown")),
                    dest_port=int(ev["dest_port"]) if ev.get("dest_port") is not None else None,
                    protocol=str(ev.get("protocol", "TCP")),
                    severity=int(ev.get("severity", 2)),
                    timestamp=ts,
                )
            )
            created += 1
        elif etype in ("auth", "phishing"):
            db.add(
                SecurityEvent(
                    session_id=session_id,
                    simulation_id=simulation_id,
                    scenario=category,
                    event_type=str(ev.get("event_type", "replay_event")),
                    timestamp=ts,
                    source=str(ev.get("source", "unknown")),
                    target=str(ev.get("target", "unknown")),
                    device=str(ev.get("device")) if ev.get("device") else None,
                    payload_json=json.dumps(ev.get("payload", {})),
                    detection_status="Clean",
                )
            )
            created += 1
        else:  # pragma: no cover - guarded by compiler shapes
            logger.warning("Ignoring unknown compiled event type '%s'", etype)
    db.commit()
    return created


def _expected_labels(spec: ScenarioSpec) -> List[str]:
    """Trusted, design-time labels. Never derived from detector output."""
    labels: List[str] = []
    for outcome in spec.expected_outcomes:
        for lbl in outcome.expected_detection_labels:
            if lbl not in labels:
                labels.append(lbl)
    return labels


def replay_studio_dataset(dataset_id: str, db: Session) -> Dict[str, Any]:
    """Replay a Studio-compiled dataset and evaluate expected vs actual detections."""
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise ReplayError("Dataset not found")
    if not dataset.scenario_spec_json:
        raise ReplayError("Dataset is not a Studio scenario; use the generic replay path.")

    spec = ScenarioSpec(**json.loads(dataset.scenario_spec_json))
    events = json.loads(dataset.payload_json)
    category = dataset.scenario_category
    detector_type = _DETECTOR_TYPE_BY_CATEGORY.get(category, "network")

    from app.services.ml_engine import _get_active_version
    active_version = _get_active_version(db, "port_scan" if detector_type == "network" else "brute_force")
    model_ver_str = active_version.version_string if active_version else "rules_only"

    eval_run = EvaluationRun(
        id=f"eval_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:6]}",
        dataset_id=dataset_id,
        model_version=model_ver_str,
        detector_type=detector_type,
        started_at=datetime.now(timezone.utc),
        status="running",
    )
    db.add(eval_run)
    db.commit()
    db.refresh(eval_run)

    simulation_id = f"studio_replay_{eval_run.id}"
    scenario_ids = _resolve_scenarios(db)
    replay_session = SessionModel(
        student_id="scenario_studio_replay",
        scenario_id=scenario_ids.get(category, 1),
        status=SessionStatus.RUNNING,
        started_at=datetime.now(timezone.utc),
    )
    db.add(replay_session)
    db.commit()
    db.refresh(replay_session)

    try:
        events_materialized = _materialize_events(events, replay_session.id, category, simulation_id, db)

        evaluate_rules(session_id=replay_session.id, db=db)
        evaluate_ml(session_id=replay_session.id, db=db)

        actual_labels = sorted({
            d.label for d in db.query(Detection).filter(Detection.session_id == replay_session.id).all()
        })

        expected = _expected_labels(spec)
        expected_set, actual_set = set(expected), set(actual_labels)
        tp = sorted(expected_set & actual_set)
        fn = sorted(expected_set - actual_set)   # expected but not detected
        fp = sorted(actual_set - expected_set)   # detected but not expected

        precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else (1.0 if not expected else 0.0)
        recall = len(tp) / (len(tp) + len(fn)) if (tp or fn) else (1.0 if not expected else 0.0)
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        eval_run.events_processed = events_materialized
        eval_run.detections_output = len(actual_labels)
        eval_run.true_positives = len(tp)
        eval_run.false_positives = len(fp)
        eval_run.false_negatives = len(fn)
        eval_run.precision = precision
        eval_run.recall = recall
        eval_run.f1_score = f1
        eval_run.status = "completed"
        eval_run.completed_at = datetime.now(timezone.utc)
        eval_run.session_id = replay_session.id
        eval_run.comparison_json = json.dumps(
            {
                "expected_labels": expected,
                "actual_labels": actual_labels,
                "true_positive_labels": tp,
                "false_negative_labels": fn,
                "false_positive_labels": fp,
            },
            sort_keys=True,
        )

        dataset.is_evaluated = True
        db.commit()

        return {
            "eval_run_id": eval_run.id,
            "dataset_id": dataset_id,
            "scenario_id": spec.scenario_id,
            "detector_type": detector_type,
            "model_version": model_ver_str,
            "session_id": replay_session.id,
            "expected_labels": expected,
            "actual_labels": actual_labels,
            "true_positive_labels": tp,
            "false_negative_labels": fn,
            "false_positive_labels": fp,
            "metrics": {
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
            },
        }
    except Exception as exc:
        logger.exception("Studio replay evaluation failed")
        eval_run.status = "failed"
        eval_run.errors = str(exc)
        db.commit()
        raise ReplayError(str(exc)) from exc
