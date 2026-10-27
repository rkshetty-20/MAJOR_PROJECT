import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.database import get_db
from app.models import (
    Session as SessionModel,
    Scenario,
    SessionStatus,
    DetectionSource,
    RiskBand,
)
from app.services.suricata_ingest import ingest_new_events
from app.services.rule_engine import evaluate_rules
from app.services.ml_engine import evaluate_ml
from app.services.risk_engine import compute_risk_score

router = APIRouter(prefix="/sessions", tags=["Sessions"])

# In-memory tracking of the last-seen event timestamp per session_id
_session_last_seen: Dict[int, datetime] = {}


# ==========================================
# Pydantic Schemas
# ==========================================

class CreateSessionRequest(BaseModel):
    student_id: str
    scenario_id: int


class SessionBaseResponse(BaseModel):
    id: int
    student_id: str
    scenario_id: int
    status: SessionStatus
    started_at: datetime
    ended_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class SuricataEventResponse(BaseModel):
    id: int
    session_id: int
    raw_signature: str
    src_ip: str
    dest_ip: str
    dest_port: Optional[int] = None
    protocol: str
    severity: int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class DetectionResponse(BaseModel):
    id: int
    session_id: int
    source: DetectionSource
    label: str
    confidence: float
    explanation: Optional[str] = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class RiskScoreResponse(BaseModel):
    id: int
    session_id: int
    score: int
    band: RiskBand
    contributing_factors: Optional[str] = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class RiskScoreDetailResponse(BaseModel):
    id: int
    session_id: int
    score: int
    band: RiskBand
    contributing_factors: Dict[str, Any]
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class StudentResponseDetail(BaseModel):
    id: int
    session_id: int
    chosen_action: str
    is_correct: bool
    points_awarded: int = 0
    response_time_seconds: float
    submitted_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SessionDetailResponse(BaseModel):
    id: int
    student_id: str
    scenario_id: int
    started_at: datetime
    ended_at: Optional[datetime] = None
    status: SessionStatus
    events: List[SuricataEventResponse] = []
    detections: List[DetectionResponse] = []
    risk_scores: List[RiskScoreResponse] = []
    student_responses: List[StudentResponseDetail] = []

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# Endpoints
# ==========================================

@router.post("", response_model=SessionBaseResponse, status_code=status.HTTP_201_CREATED, summary="Create a new session")
@router.post("/", response_model=SessionBaseResponse, status_code=status.HTTP_201_CREATED, include_in_schema=False)
def create_session(payload: CreateSessionRequest, db: DBSession = Depends(get_db)) -> SessionModel:
    """
    Creates a new evaluation session for a student running a specific scenario.
    Initializes status to 'running' and started_at to current UTC timestamp.
    """
    scenario = db.query(Scenario).filter(Scenario.id == payload.scenario_id).first()
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario with id {payload.scenario_id} not found",
        )

    started_now = datetime.now(timezone.utc)
    new_session = SessionModel(
        student_id=payload.student_id,
        scenario_id=payload.scenario_id,
        status=SessionStatus.RUNNING,
        started_at=started_now,
    )
    db.add(new_session)
    db.commit()
    db.refresh(new_session)

    # Initialize last-seen timestamp to session start time
    _session_last_seen[new_session.id] = started_now

    return new_session


@router.post("/{id}/end", response_model=SessionBaseResponse, summary="End an active session")
def end_session(id: int, db: DBSession = Depends(get_db)) -> SessionModel:
    """
    Marks an active session as completed and records the ended_at timestamp.
    """
    session_obj = db.query(SessionModel).filter(SessionModel.id == id).first()
    if not session_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session with id {id} not found",
        )

    session_obj.status = SessionStatus.COMPLETED
    session_obj.ended_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(session_obj)
    return session_obj


@router.get("/{id}", response_model=SessionDetailResponse, summary="Get full session details")
def get_session(id: int, db: DBSession = Depends(get_db)) -> SessionModel:
    """
    Retrieves full session metadata along with related Suricata events,
    pipeline detections, computed risk scores, and submitted student actions.
    """
    session_obj = db.query(SessionModel).filter(SessionModel.id == id).first()
    if not session_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session with id {id} not found",
        )

    return session_obj


@router.get(
    "/{id}/events/poll",
    response_model=List[SuricataEventResponse],
    summary="Poll newly ingested Suricata alert events for a session",
)
def poll_session_events(
    id: int,
    db: DBSession = Depends(get_db),
) -> List[SuricataEventResponse]:
    """
    Ingests newly generated Suricata alert events from eve.json for the session
    since the last-seen timestamp, stores them in the database, and returns them.
    The frontend polls this endpoint every 2 seconds during active sessions.
    """
    session_obj = db.query(SessionModel).filter(SessionModel.id == id).first()
    if not session_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session with id {id} not found",
        )

    if id in _session_last_seen:
        since_ts = _session_last_seen[id]
    else:
        since_ts = session_obj.started_at

    new_events = ingest_new_events(
        session_id=id,
        eve_json_path=settings.SURICATA_EVE_PATH,
        since_timestamp=since_ts,
        db=db,
    )

    if new_events:
        latest_event_ts = max(e.timestamp for e in new_events)
        _session_last_seen[id] = latest_event_ts
    elif id not in _session_last_seen:
        _session_last_seen[id] = since_ts

    return [SuricataEventResponse.model_validate(e) for e in new_events]


@router.get(
    "/{id}/detections/evaluate",
    response_model=List[DetectionResponse],
    summary="Evaluate detection rules for an active session",
)
def evaluate_session_detections(
    id: int,
    db: DBSession = Depends(get_db),
) -> List[DetectionResponse]:
    """
    Executes the behavioral rule engine against the session's ingested Suricata events.
    Returns any newly generated Detection rows.
    Called by the frontend immediately following /events/poll during active sessions.
    """
    session_obj = db.query(SessionModel).filter(SessionModel.id == id).first()
    if not session_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session with id {id} not found",
        )

    new_detections = evaluate_rules(session_id=id, db=db)
    return [DetectionResponse.model_validate(d) for d in new_detections]


@router.get(
    "/{id}/detections/evaluate-ml",
    response_model=List[DetectionResponse],
    summary="Evaluate machine learning detection for an active session",
)
def evaluate_session_ml_detections(
    id: int,
    db: DBSession = Depends(get_db),
) -> List[DetectionResponse]:
    """
    Executes the offline-trained Random Forest ML detector against the session's
    ingested Suricata events. Returns any newly generated Detection rows.
    Called by the frontend to provide ML-driven threat insights alongside rule detections.
    """
    session_obj = db.query(SessionModel).filter(SessionModel.id == id).first()
    if not session_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session with id {id} not found",
        )

    detection = evaluate_ml(session_id=id, db=db)
    if detection:
        return [DetectionResponse.model_validate(detection)]
    return []


@router.get(
    "/{id}/risk-score",
    response_model=RiskScoreDetailResponse,
    summary="Get current explainable risk score with parsed contributing factors",
)
def get_session_risk_score(
    id: int,
    db: DBSession = Depends(get_db),
) -> RiskScoreDetailResponse:
    """
    Computes or updates the multi-signal fused risk score for the specified session.
    Returns the score, risk band, and transparent contributing factors parsed into a JSON object.
    """
    session_obj = db.query(SessionModel).filter(SessionModel.id == id).first()
    if not session_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session with id {id} not found",
        )

    risk_row = compute_risk_score(session_id=id, db=db)

    # Parse contributing_factors JSON string back into a dict for response
    factors_dict = {}
    if risk_row.contributing_factors:
        try:
            factors_dict = json.loads(risk_row.contributing_factors)
        except Exception:
            factors_dict = {}

    return RiskScoreDetailResponse(
        id=risk_row.id,
        session_id=risk_row.session_id,
        score=risk_row.score,
        band=risk_row.band,
        contributing_factors=factors_dict,
        timestamp=risk_row.timestamp,
    )
