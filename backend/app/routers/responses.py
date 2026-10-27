import json
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.models import (
    Session as SessionModel,
    Scenario,
    StudentResponse,
    PerformanceHistory,
)

router = APIRouter(tags=["Responses"])


# ==========================================
# Pydantic Schemas
# ==========================================

class RespondRequest(BaseModel):
    chosen_action: str
    response_time_seconds: float


class RespondResponse(BaseModel):
    is_correct: bool
    points_awarded: int
    chosen_action: str
    response_time_seconds: float
    response_id: int
    feedback: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# Endpoints
# ==========================================

@router.post(
    "/sessions/{id}/respond",
    response_model=RespondResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit student mitigation action",
)
def respond_to_session(
    id: int,
    payload: RespondRequest,
    db: DBSession = Depends(get_db),
) -> RespondResponse:
    """
    Evaluates a student's chosen action against the scenario configuration:
    1. Looks up the session and its linked scenario.
    2. Parses scenario config_json for correct and incorrect responses.
    3. Computes is_correct and calculates points_awarded based on scenario scoring rules.
    4. Persists the StudentResponse row including points_awarded.
    5. Records a PerformanceHistory row for student adaptive modeling.
    6. Returns evaluation results {is_correct, points_awarded}.
    """
    session_obj = db.query(SessionModel).filter(SessionModel.id == id).first()
    if not session_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session with id {id} not found",
        )

    scenario = session_obj.scenario
    if not scenario:
        scenario = db.query(Scenario).filter(Scenario.id == session_obj.scenario_id).first()

    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scenario configuration for this session was not found",
        )

    # Parse scenario config JSON
    config = {}
    if scenario.config_json:
        try:
            config = json.loads(scenario.config_json)
        except json.JSONDecodeError:
            config = {}

    correct_responses = [str(item).strip().lower() for item in config.get("correct_responses", [])]
    incorrect_responses = [str(item).strip().lower() for item in config.get("incorrect_responses", [])]

    normalized_choice = payload.chosen_action.strip().lower()
    is_correct = normalized_choice in correct_responses

    # Calculate points based on scoring configuration
    scoring_rules = config.get("scoring", {})
    correct_response_points = int(scoring_rules.get("correct_response_points", 50))
    fast_response_bonus_seconds = float(scoring_rules.get("fast_response_bonus_seconds", 30))
    fast_response_bonus_points = int(scoring_rules.get("fast_response_bonus_points", 20))

    points_awarded = 0
    if is_correct:
        points_awarded += correct_response_points
        if payload.response_time_seconds <= fast_response_bonus_seconds:
            points_awarded += fast_response_bonus_points

    now = datetime.now(timezone.utc)

    # 1. Record student response in database with points_awarded
    student_response = StudentResponse(
        session_id=session_obj.id,
        chosen_action=payload.chosen_action,
        is_correct=is_correct,
        points_awarded=points_awarded,
        response_time_seconds=payload.response_time_seconds,
        submitted_at=now,
    )
    db.add(student_response)

    # 2. Record performance history entry for adaptive recommendation engine
    perf_history = PerformanceHistory(
        student_id=session_obj.student_id,
        session_id=session_obj.id,
        score_achieved=points_awarded,
        category=scenario.category,
        timestamp=now,
    )
    db.add(perf_history)

    db.commit()
    db.refresh(student_response)
    db.refresh(perf_history)

    feedback_msg = (
        "Action mitigated the security event effectively."
        if is_correct
        else "Incorrect mitigation action chosen for this scenario."
    )

    return RespondResponse(
        is_correct=is_correct,
        points_awarded=points_awarded,
        chosen_action=student_response.chosen_action,
        response_time_seconds=student_response.response_time_seconds,
        response_id=student_response.id,
        feedback=feedback_msg,
    )
