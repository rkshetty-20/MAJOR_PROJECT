"""Adaptive Learning API — LLM-Assisted Analysis (Milestone 1).

Read/analyze endpoints for the evidence-driven learning loop:

    POST /api/adaptive-learning/analyze        -> analyze a completed EvaluationRun.
    GET  /api/adaptive-learning/analysis-runs  -> list persisted analysis runs.
    GET  /api/adaptive-learning/analysis-runs/{id} -> one run + its recommendations.
    GET  /api/adaptive-learning/recommendations -> list recommendations (read-only).
    GET  /api/adaptive-learning/evaluation-runs -> completed runs selectable for analysis.
    GET  /api/adaptive-learning/capabilities    -> supported categories + feature registry.

The LLM proposes analysis only. It cannot approve, execute, train or activate
anything here — those capabilities arrive in later milestones behind the same
deterministic validators and acceptance gates.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.models.models import AnalysisRun, Dataset, EvaluationRun, Recommendation
from app.services.adaptive_learning.analysis_context import AnalysisInputError
from app.services.adaptive_learning.llm_analyst import analyze_evaluation_run
from app.services.adaptive_learning.recommendation_schema import (
    AnalysisMode,
    AnalysisReport,
)
from app.services.scenario_simulator.learning_import import (
    _FEATURE_SCHEMA_VERSION,
    _ML_TASK_BY_CATEGORY,
)
from app.services.scenario_simulator.spec import AttackCategory
from ml.features import AUTH_FEATURE_NAMES, FEATURE_NAMES

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/adaptive-learning", tags=["Adaptive Learning"])


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evaluation_run_id: str = Field(..., min_length=1, max_length=64)
    mode: AnalysisMode = AnalysisMode.MISSED_DETECTION
    model: Optional[str] = Field(default=None, max_length=128, description="Optional model override.")


def _serialize_recommendation(row: Recommendation) -> dict:
    return {
        "id": row.id,
        "analysis_run_id": row.analysis_run_id,
        "attack_category": row.attack_category,
        "recommendation_type": row.recommendation_type,
        "status": row.status,
        "summary": row.summary,
        "hypothesis": row.hypothesis,
        "confidence": row.confidence,
        "evidence_refs": json.loads(row.evidence_refs_json or "[]"),
        "proposed_change": row.proposed_change,
        "required_features": json.loads(row.required_features_json or "[]"),
        "required_data": row.required_data,
        "expected_benefit": row.expected_benefit,
        "potential_risks": row.potential_risks,
        "validation_plan": row.validation_plan,
        "rejection_reason": row.rejection_reason,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def _serialize_run(row: AnalysisRun) -> dict:
    return {
        "id": row.id,
        "evaluation_run_id": row.evaluation_run_id,
        "dataset_id": row.dataset_id,
        "attack_category": row.attack_category,
        "mode": row.mode,
        "status": row.status,
        "summary": row.summary,
        "findings": json.loads(row.findings_json or "[]"),
        "model": row.model,
        "correlation_id": row.correlation_id,
        "context_sha256": row.context_sha256,
        "provider_status": row.provider_status,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
    }


@router.post("/analyze", summary="Run evidence-backed LLM analysis on a completed evaluation run")
async def analyze(
    payload: AnalyzeRequest,
    db: DBSession = Depends(get_db),
) -> AnalysisReport:
    try:
        return await analyze_evaluation_run(
            evaluation_run_id=payload.evaluation_run_id,
            mode=payload.mode,
            db=db,
            model=payload.model,
        )
    except AnalysisInputError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if exc.not_found else status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.get("/analysis-runs", summary="List persisted analysis runs")
def list_analysis_runs(
    evaluation_run_id: Optional[str] = Query(default=None, max_length=64),
    limit: int = Query(default=20, ge=1, le=100),
    db: DBSession = Depends(get_db),
) -> dict:
    query = db.query(AnalysisRun)
    if evaluation_run_id:
        query = query.filter(AnalysisRun.evaluation_run_id == evaluation_run_id)
    rows = query.order_by(AnalysisRun.created_at.desc()).limit(limit).all()
    return {"analysis_runs": [_serialize_run(r) for r in rows]}


@router.get("/analysis-runs/{analysis_run_id}", summary="Fetch one analysis run with its recommendations")
def get_analysis_run(
    analysis_run_id: str,
    db: DBSession = Depends(get_db),
) -> dict:
    run = db.query(AnalysisRun).filter(AnalysisRun.id == analysis_run_id).first()
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis run not found")
    recs = (
        db.query(Recommendation)
        .filter(Recommendation.analysis_run_id == analysis_run_id)
        .order_by(Recommendation.created_at.asc())
        .all()
    )
    result = _serialize_run(run)
    result["recommendations"] = [_serialize_recommendation(r) for r in recs]
    return result


@router.get("/recommendations", summary="List recommendations (read-only in Milestone 1)")
def list_recommendations(
    analysis_run_id: Optional[str] = Query(default=None, max_length=64),
    status_filter: Optional[str] = Query(default=None, alias="status", max_length=32),
    limit: int = Query(default=50, ge=1, le=200),
    db: DBSession = Depends(get_db),
) -> dict:
    query = db.query(Recommendation)
    if analysis_run_id:
        query = query.filter(Recommendation.analysis_run_id == analysis_run_id)
    if status_filter:
        query = query.filter(Recommendation.status == status_filter)
    rows = query.order_by(Recommendation.created_at.desc()).limit(limit).all()
    return {"recommendations": [_serialize_recommendation(r) for r in rows]}


@router.get("/evaluation-runs", summary="List completed evaluation runs available for analysis")
def list_evaluation_runs(
    limit: int = Query(default=50, ge=1, le=200),
    db: DBSession = Depends(get_db),
) -> dict:
    rows = (
        db.query(EvaluationRun)
        .filter(EvaluationRun.status == "completed")
        .order_by(EvaluationRun.started_at.desc())
        .limit(limit)
        .all()
    )
    categories = {
        d.id: d.scenario_category
        for d in db.query(Dataset).filter(Dataset.id.in_([r.dataset_id for r in rows])).all()
    } if rows else {}
    return {
        "evaluation_runs": [
            {
                "id": r.id,
                "dataset_id": r.dataset_id,
                "attack_category": categories.get(r.dataset_id),
                "detector_type": r.detector_type,
                "model_version": r.model_version,
                "true_positives": r.true_positives,
                "false_positives": r.false_positives,
                "false_negatives": r.false_negatives,
                "precision": r.precision,
                "recall": r.recall,
                "f1_score": r.f1_score,
                "started_at": r.started_at.isoformat() if r.started_at else None,
            }
            for r in rows
        ]
    }


@router.get("/capabilities", summary="Supported categories, feature registry and ML capability")
def get_capabilities() -> dict:
    categories = []
    for cat in AttackCategory:
        task = _ML_TASK_BY_CATEGORY.get(cat.value)
        if task == "port_scan":
            features = list(FEATURE_NAMES)
        elif task in {"brute_force", "credential_stuffing"}:
            features = list(AUTH_FEATURE_NAMES)
        else:
            features = []
        categories.append(
            {
                "attack_category": cat.value,
                "ml_task": task,
                "ml_supported": task is not None,
                "heuristic_only": task is None,
                "feature_schema_version": _FEATURE_SCHEMA_VERSION.get(cat.value),
                "registered_features": features,
            }
        )
    return {
        "supported_modes": [m.value for m in AnalysisMode],
        "recommendation_types": [
            "DATA_QUALITY", "FEATURE_REVIEW", "THRESHOLD_EXPERIMENT", "RULE_REVIEW",
            "MODEL_RETRAINING", "MODEL_EVALUATION", "INSUFFICIENT_EVIDENCE",
        ],
        "categories": categories,
        "milestone": 1,
    }
