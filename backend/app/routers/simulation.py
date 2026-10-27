import json
import logging
import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.models import (
    SecurityEvent,
    Detection,
    RiskScore,
    SuricataEvent,
    Session as SessionModel,
    SessionStatus,
    RiskBand,
    Incident,
    IncidentStatus,
    IncidentFeedback,
    AnalystDecision,
    Dataset,
)
from app.services.integrity_service import verify_record_integrity
from app.services.simulation_service import (
    run_synthetic_simulation,
    get_available_scenarios,
    SCENARIO_METADATA,
    generate_offline_dataset,
    recommend_next_simulation,
)
from app.services.ml_engine import (
    train_and_evaluate_model,
    get_adaptive_status,
    rollback_model,
    get_ml_readiness,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Attack Simulation & Security Telemetry"])

# Path to machine learning evaluation metrics artifact
METRICS_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "ml",
        "models",
        "port_scan_rf_metrics.json",
    )
)


# ==========================================
# Pydantic Schemas
# ==========================================

class SimulationRunRequest(BaseModel):
    scenario: str = Field(..., description="Attack scenario key, e.g. 'brute_force', 'credential_stuffing', 'port_scan'")
    intensity: Optional[str] = Field(default="medium", description="Attack intensity: 'low', 'medium', 'high'")
    event_count: Optional[int] = Field(default=None, description="Optional custom event count (bounded 1 to 100)")
    delay_ms: Optional[int] = Field(default=None, description="Optional simulated interval between events in milliseconds")
    student_id: Optional[str] = Field(default="simulation_operator", description="Operator/student tracking identity")

    model_config = ConfigDict(extra="ignore")


class SecurityEventResponse(BaseModel):
    id: int
    session_id: Optional[int] = None
    simulation_id: Optional[str] = None
    scenario: str
    event_type: str
    timestamp: Any
    source: str
    target: str
    device: Optional[str] = None
    location: Optional[str] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    detection_status: str
    payload: Optional[Dict[str, Any]] = None
    evidence_hash: Optional[str] = None
    integrity_status: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class DetectionSummary(BaseModel):
    id: int
    session_id: int
    source: str
    label: str
    confidence: float
    explanation: Optional[str] = None
    timestamp: Any
    evidence_hash: Optional[str] = None
    integrity_status: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class SimulationFlowStep(BaseModel):
    step: str
    status: str
    count: Optional[int] = None
    detections: Optional[int] = None
    score: Optional[int] = None
    band: Optional[str] = None


class SimulationRunResponse(BaseModel):
    simulation_id: str
    scenario: str
    scenario_name: str
    session_id: int
    events_generated: int
    status: str
    detections_count: int
    detections: List[Dict[str, Any]]
    risk: Dict[str, Any]
    triggered_rules: List[str]
    mitigation: str
    simulation_flow: List[SimulationFlowStep]


class RealSimulationTimelineStep(BaseModel):
    step: str
    timestamp: str
    status: str
    label: str
    details: Optional[str] = None
    score: Optional[int] = None
    band: Optional[str] = None
    related_id: Optional[int] = None
    severity: Optional[int] = None
    risk_score: Optional[int] = None
    simulation_id: Optional[str] = None


class ScenarioMetadataResponse(BaseModel):
    id: str
    name: str
    category: str
    default_intensity: str
    description: str
    mitigation: str


class RiskOverviewResponse(BaseModel):
    total_assessments: int
    average_score: float
    distribution: Dict[str, int]
    latest_scores: List[Dict[str, Any]]


class InvestigationContextResponse(BaseModel):
    detection: Dict[str, Any]
    related_events: List[SecurityEventResponse]
    risk: Optional[Dict[str, Any]] = None
    timeline: List[RealSimulationTimelineStep]


class OverviewMetricsResponse(BaseModel):
    total_events: int
    detected_threats: int
    high_risk_events: int
    active_simulations: int
    detections_per_event_ratio: str
    false_positive_rate: str
    model_accuracy: str
    model_accuracy_source: Optional[str] = None


class DatasetGenerationRequest(BaseModel):
    scenario: str
    intensity: str = "medium"
    event_count: Optional[int] = None

# ==========================================
# Endpoints
# ==========================================

@router.post(
    "/api/datasets/generate",
    status_code=status.HTTP_201_CREATED,
    summary="Generate an offline exportable dataset",
)
def generate_dataset_endpoint(
    req: DatasetGenerationRequest,
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    try:
        ds = generate_offline_dataset(
            scenario=req.scenario,
            intensity=req.intensity,
            event_count=req.event_count,
            db=db,
        )
        return {
            "id": ds.id,
            "schema_version": ds.schema_version,
            "scenario_category": ds.scenario_category,
            "events_count": ds.events_count,
            "ground_truth_available": ds.ground_truth_available,
            "payload_json": json.loads(ds.payload_json),
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.exception("Dataset generation failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to generate dataset")

@router.get(
    "/api/datasets",
    summary="List generated datasets",
)
def list_datasets(
    db: DBSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    datasets = db.query(Dataset).order_by(Dataset.created_at.desc()).all()
    return [
        {
            "id": d.id,
            "scenario_category": d.scenario_category,
            "events_count": d.events_count,
            "created_at": d.created_at,
            "is_evaluated": d.is_evaluated,
            "ground_truth_available": d.ground_truth_available,
        }
        for d in datasets
    ]

@router.get(
    "/api/datasets/{dataset_id}/export",
    summary="Export a specific dataset",
)
def export_dataset(
    dataset_id: str,
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")
    
    return {
        "metadata": {
            "id": dataset.id,
            "schema_version": dataset.schema_version,
            "scenario": dataset.scenario_category,
            "events_count": dataset.events_count,
            "created_at": dataset.created_at.isoformat(),
            "ground_truth_available": dataset.ground_truth_available,
        },
        "events": json.loads(dataset.payload_json)
    }

@router.post(
    "/api/datasets/{dataset_id}/replay",
    summary="Replay a dataset through detection orchestrator",
)
def replay_dataset_endpoint(
    dataset_id: str,
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    from app.services.simulation_service import run_dataset_replay
    try:
        return run_dataset_replay(dataset_id, db)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception("Replay failed")
        raise HTTPException(status_code=500, detail="Replay failed")

@router.post(
    "/api/simulation/run",
    response_model=SimulationRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute controlled synthetic attack simulation",
)
def run_simulation_endpoint(
    payload: SimulationRunRequest,
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Executes a controlled, synthetic cybersecurity simulation scenario.
    Generates realistic telemetry, submits it through the behavioral rule and ML
    detection engines, and evaluates multi-signal risk scores without hardcoding.
    """
    try:
        result = run_synthetic_simulation(
            scenario=payload.scenario,
            intensity=payload.intensity or "medium",
            event_count=payload.event_count,
            delay_ms=payload.delay_ms,
            student_id=payload.student_id or "simulation_operator",
            db=db,
        )
        return result
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except Exception as exc:
        logger.exception("Error executing simulation: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to complete simulation run.",
        )


@router.get(
    "/api/simulation/scenarios",
    response_model=List[ScenarioMetadataResponse],
    summary="List available synthetic attack simulation scenarios",
)
def list_scenarios_endpoint() -> List[Dict[str, Any]]:
    """Returns catalog of all 10 supported attack simulation scenarios and mitigation rules."""
    return get_available_scenarios()


@router.get(
    "/api/simulation/next-recommendation",
    summary="Get adaptive simulation scenario recommendation based on past simulation outcomes",
)
def get_next_simulation_recommendation(
    operator_id: str = Query(default="simulation_operator", description="Simulation operator or student ID"),
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Computes deterministic next-simulation recommendation based on actual persisted
    simulation telemetry, detections, and risk scores from previous runs.
    """
    try:
        return recommend_next_simulation(operator_id=operator_id, db=db)
    except Exception as exc:
        logger.exception("Failed to compute next simulation recommendation: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to compute adaptive simulation recommendation.",
        )


@router.get(
    "/api/simulation/history",
    summary="List simulation execution history with detections and risk scores",
)
def get_simulation_history(
    operator_id: Optional[str] = Query(default=None, description="Filter by operator/student ID"),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Returns paginated history of past simulation sessions, including scenario,
    status, event counts, detection counts, and risk scores.
    """
    query = db.query(SessionModel)
    if operator_id:
        query = query.filter(SessionModel.student_id == operator_id)

    total_count = query.count()
    sessions = query.order_by(SessionModel.started_at.desc()).offset(offset).limit(limit).all()

    items = []
    for s in sessions:
        scenario_key = None
        first_event = db.query(SecurityEvent).filter(SecurityEvent.session_id == s.id).first()
        if first_event and first_event.scenario:
            scenario_key = first_event.scenario
        elif s.scenario:
            scenario_key = s.scenario.name

        risk = db.query(RiskScore).filter(RiskScore.session_id == s.id).first()
        detections_count = db.query(Detection).filter(Detection.session_id == s.id).count()
        events_count = db.query(SecurityEvent).filter(SecurityEvent.session_id == s.id).count()

        items.append({
            "session_id": s.id,
            "operator_id": s.student_id,
            "scenario": scenario_key or "unknown",
            "scenario_name": SCENARIO_METADATA.get(scenario_key, {}).get("name", scenario_key or "Unknown"),
            "status": s.status.value if hasattr(s.status, "value") else str(s.status),
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "ended_at": s.ended_at.isoformat() if s.ended_at else None,
            "events_count": events_count,
            "detections_count": detections_count,
            "risk_score": risk.score if risk else None,
            "risk_band": (
                risk.band.value if hasattr(risk.band, "value") else str(risk.band)
            ) if risk and risk.band else None,
        })

    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "items": items,
    }


@router.get(
    "/api/events",
    response_model=List[SecurityEventResponse],
    summary="List recent security telemetry events",
)
def list_security_events(
    limit: int = Query(default=50, ge=1, le=200),
    scenario: Optional[str] = None,
    simulation_id: Optional[str] = None,
    risk_level: Optional[str] = None,
    db: DBSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Retrieves recent security telemetry events with parsed JSON payloads."""
    query = db.query(SecurityEvent)
    if scenario:
        query = query.filter(SecurityEvent.scenario == scenario)
    if simulation_id:
        query = query.filter(SecurityEvent.simulation_id == simulation_id)
    if risk_level:
        query = query.filter(SecurityEvent.risk_level == risk_level.upper())

    events = query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()

    results = []
    for ev in events:
        parsed_payload = None
        if ev.payload_json:
            try:
                parsed_payload = json.loads(ev.payload_json)
            except Exception:
                parsed_payload = {"raw": ev.payload_json}

        results.append({
            "id": ev.id,
            "session_id": ev.session_id,
            "simulation_id": ev.simulation_id,
            "scenario": ev.scenario,
            "event_type": ev.event_type,
            "timestamp": ev.timestamp,
            "source": ev.source,
            "target": ev.target,
            "device": ev.device,
            "location": ev.location,
            "risk_score": ev.risk_score,
            "risk_level": ev.risk_level,
            "detection_status": ev.detection_status,
            "payload": parsed_payload,
        })
    return results


@router.get(
    "/api/events/{id}",
    response_model=SecurityEventResponse,
    summary="Get single security telemetry event by ID",
)
def get_security_event_by_id(
    id: int,
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieves detailed telemetry for a single security event."""
    ev = db.query(SecurityEvent).filter(SecurityEvent.id == id).first()
    if not ev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event with ID {id} not found.",
        )

    parsed_payload = None
    if ev.payload_json:
        try:
            parsed_payload = json.loads(ev.payload_json)
        except Exception:
            parsed_payload = {"raw": ev.payload_json}

    return {
        "id": ev.id,
        "session_id": ev.session_id,
        "simulation_id": ev.simulation_id,
        "scenario": ev.scenario,
        "event_type": ev.event_type,
        "timestamp": ev.timestamp,
        "source": ev.source,
        "target": ev.target,
        "device": ev.device,
        "location": ev.location,
        "risk_score": ev.risk_score,
        "risk_level": ev.risk_level,
        "detection_status": ev.detection_status,
        "payload": parsed_payload,
    }


@router.get(
    "/api/detections",
    response_model=List[DetectionSummary],
    summary="List all detection rule and ML engine triggers",
)
def list_detections(
    limit: int = Query(default=50, ge=1, le=200),
    db: DBSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Retrieves list of recent threat detections across rule, ML, and hybrid pipelines."""
    detections = db.query(Detection).order_by(Detection.timestamp.desc()).limit(limit).all()
    results = []
    for d in detections:
        label = d.label
        if d.session and d.session.scenario and d.session.scenario.name == "Combined Multi-Signal Attack":
            label = "Combined Multi-Signal"
            
        results.append({
            "id": d.id,
            "session_id": d.session_id,
            "source": d.source.value if hasattr(d.source, "value") else str(d.source),
            "label": label,
            "confidence": d.confidence,
            "explanation": d.explanation,
            "timestamp": d.timestamp,
            "evidence_hash": d.evidence_hash,
            "integrity_status": verify_record_integrity("Detection", d, db)
        })
    return results


@router.get(
    "/api/investigations/{detection_id}",
    response_model=InvestigationContextResponse,
    summary="Get full investigation context for a detection",
)
def get_investigation_context(
    detection_id: int,
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    """Provides a professional SOC-style investigation view with detection explanations, correlated evidence events, explainable risk breakdown, and attack timeline."""
    detection = db.query(Detection).filter(Detection.id == detection_id).first()
    if not detection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found.",
        )

    session_id = detection.session_id
    
    # Retrieve Risk
    risk_score = db.query(RiskScore).filter(RiskScore.session_id == session_id).order_by(RiskScore.timestamp.desc()).first()
    risk_resp = None
    if risk_score:
        factors = {}
        if risk_score.contributing_factors:
            try:
                factors = json.loads(risk_score.contributing_factors)
            except Exception:
                pass
        
        risk_resp = {
            "score": risk_score.score,
            "band": risk_score.band.value if hasattr(risk_score.band, "value") else str(risk_score.band),
            "contributing_factors": factors
        }

    # Extract correlated events if available
    correlated_metadata = []
    if detection.features:
        try:
            feat_dict = json.loads(detection.features)
            correlated_metadata = feat_dict.get("correlated_events") or []
        except Exception:
            pass

    related_events_resp = []
    simulation_id = None
    
    if correlated_metadata:
        # Load exactly the correlated events
        for meta in correlated_metadata:
            ev_id = meta["event_id"]
            ev_type = meta["type"]
            reason = meta["reason"]
            is_hypothesis = meta.get("is_hypothesis", False)
            
            ev = None
            if ev_type == "SecurityEvent":
                ev = db.query(SecurityEvent).filter(SecurityEvent.id == ev_id).first()
            elif ev_type == "SuricataEvent":
                ev = db.query(SuricataEvent).filter(SuricataEvent.id == ev_id).first()
                
            if not ev:
                continue
                
            if hasattr(ev, "simulation_id") and not simulation_id and ev.simulation_id:
                simulation_id = ev.simulation_id
                
            parsed_payload = None
            raw_payload = getattr(ev, "payload_json", None) or getattr(ev, "raw_signature", None)
            if raw_payload:
                try:
                    parsed_payload = json.loads(raw_payload)
                except Exception:
                    parsed_payload = {"raw": raw_payload}
                    
            related_events_resp.append({
                "id": ev.id,
                "session_id": ev.session_id,
                "simulation_id": getattr(ev, "simulation_id", None),
                "scenario": getattr(ev, "scenario", "Network Intrusion"),
                "event_type": getattr(ev, "event_type", "suricata_alert"),
                "timestamp": ev.timestamp,
                "source": getattr(ev, "source", getattr(ev, "src_ip", None)),
                "target": getattr(ev, "target", getattr(ev, "dest_ip", None)),
                "device": getattr(ev, "device", None),
                "location": getattr(ev, "location", None),
                "risk_score": getattr(ev, "risk_score", getattr(ev, "severity", None)),
                "risk_level": getattr(ev, "risk_level", None),
                "detection_status": getattr(ev, "detection_status", "Detected"),
                "payload": parsed_payload,
                "evidence_hash": ev.evidence_hash,
                "integrity_status": verify_record_integrity(ev_type, ev, db),
                "correlation_reason": reason,
                "is_hypothesis": is_hypothesis
            })
    else:
        # Fallback for old detections without explicit correlation
        sec_events = db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).order_by(SecurityEvent.timestamp.asc()).all()
        for ev in sec_events:
            if not simulation_id and ev.simulation_id:
                simulation_id = ev.simulation_id
            parsed_payload = None
            if ev.payload_json:
                try:
                    parsed_payload = json.loads(ev.payload_json)
                except Exception:
                    parsed_payload = {"raw": ev.payload_json}
            related_events_resp.append({
                "id": ev.id,
                "session_id": ev.session_id,
                "simulation_id": ev.simulation_id,
                "scenario": ev.scenario,
                "event_type": ev.event_type,
                "timestamp": ev.timestamp,
                "source": ev.source,
                "target": ev.target,
                "device": ev.device,
                "location": ev.location,
                "risk_score": ev.risk_score,
                "risk_level": ev.risk_level,
                "detection_status": ev.detection_status,
                "payload": parsed_payload,
                "evidence_hash": ev.evidence_hash,
                "integrity_status": verify_record_integrity("SecurityEvent", ev, db),
                "correlation_reason": "Inferred from session timeframe",
                "is_hypothesis": False
            })
        
    # Retrieve Timeline
    if not simulation_id:
        # Fallback check
        first_sec = db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).first()
        if first_sec and first_sec.simulation_id:
            simulation_id = first_sec.simulation_id
        
    timeline = get_simulation_timeline(simulation_id, db) if simulation_id else []

    display_label = detection.label
    if detection.session and detection.session.scenario and detection.session.scenario.name == "Combined Multi-Signal Attack":
        display_label = "Combined Multi-Signal"
        
    # Dynamically find incident_id
    incident_id = None
    incidents = db.query(Incident).all()
    target_event_id = f"det_{detection.id}"
    for inc in incidents:
        if inc.related_events_json:
            try:
                events = json.loads(inc.related_events_json)
                if any(e.get("event_id") == target_event_id for e in events):
                    incident_id = inc.id
                    break
            except Exception:
                pass
                
    return {
        "detection": {
            "id": detection.id,
            "label": display_label,
            "timestamp": detection.timestamp,
            "confidence": detection.confidence,
            "explanation": detection.explanation,
            "source": detection.source.value if hasattr(detection.source, "value") else str(detection.source),
            "session_id": detection.session_id,
            "evidence_hash": detection.evidence_hash,
            "integrity_status": verify_record_integrity("Detection", detection, db)
        },
        "related_events": related_events_resp,
        "risk": risk_resp,
        "timeline": timeline,
        "incident_id": incident_id
    }


@router.get(
    "/api/risk",
    response_model=RiskOverviewResponse,
    summary="Get overall risk distribution and latest risk scores",
)
def get_risk_distribution(
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    """Computes distribution of risk scores across Low, Medium, High, and Critical bands."""
    scores = db.query(RiskScore).all()
    distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    total_val = 0

    for r in scores:
        band_str = r.band.value.upper() if hasattr(r.band, "value") else str(r.band).upper()
        if band_str in distribution:
            distribution[band_str] += 1
        total_val += r.score

    avg_score = round(total_val / len(scores), 1) if scores else 0.0
    
    recent = (
        db.query(RiskScore)
        .order_by(RiskScore.timestamp.desc())
        .limit(10)
        .all()
    )
    latest_list = [
        {
            "id": r.id,
            "session_id": r.session_id,
            "score": r.score,
            "band": r.band.value if hasattr(r.band, "value") else str(r.band),
            "timestamp": r.timestamp,
        }
        for r in recent
    ]

    return {
        "total_assessments": len(scores),
        "average_score": avg_score,
        "distribution": distribution,
        "latest_scores": latest_list,
    }


@router.get("/api/incidents", summary="Get all incidents")
def get_incidents(db: DBSession = Depends(get_db)):
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).limit(50).all()
    results = []
    for inc in incidents:
        results.append({
            "id": inc.id,
            "title": inc.title,
            "status": inc.status,
            "severity": inc.severity,
            "risk_score": inc.risk_score,
            "created_at": inc.created_at,
            "updated_at": inc.updated_at,
            "source_modules": json.loads(inc.source_modules_json or "[]")
        })
    return results


@router.get("/api/incidents/{incident_id}", summary="Get specific incident details")
def get_incident(incident_id: str, db: DBSession = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    related_events = []
    if inc.related_events_json:
        try:
            related_events = json.loads(inc.related_events_json)
        except Exception:
            pass
            
    feedback = []
    for fb in inc.feedback:
        feedback.append({
            "id": fb.id,
            "analyst_id": fb.analyst_id,
            "decision": fb.decision,
            "rationale": fb.rationale,
            "created_at": fb.created_at
        })
        
    return {
        "id": inc.id,
        "title": inc.title,
        "status": inc.status,
        "severity": inc.severity,
        "risk_score": inc.risk_score,
        "created_at": inc.created_at,
        "updated_at": inc.updated_at,
        "source_modules": json.loads(inc.source_modules_json or "[]"),
        "related_events": related_events,
        "feedback": feedback
    }


class FeedbackSubmit(BaseModel):
    analyst_id: str
    decision: AnalystDecision
    rationale: Optional[str] = None


@router.post("/api/incidents/{incident_id}/feedback", summary="Submit feedback for an incident")
def submit_incident_feedback(incident_id: str, payload: FeedbackSubmit, db: DBSession = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    fb = IncidentFeedback(
        incident_id=inc.id,
        analyst_id=payload.analyst_id,
        decision=payload.decision,
        rationale=payload.rationale
    )
    db.add(fb)
    
    if payload.decision == AnalystDecision.BENIGN:
        inc.status = IncidentStatus.CLOSED
        
    db.commit()
    db.refresh(fb)
    return {"status": "success", "feedback_id": fb.id}


@router.get(
    "/api/overview",
    response_model=OverviewMetricsResponse,
    summary="Get SOC overview dashboard metrics",
)
def get_soc_overview(
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    """Returns high-level SOC dashboard indicators calculated from real database state."""
    total_events = db.query(SecurityEvent).count()
    detected_threats = db.query(Detection).count()
    high_risk_events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.risk_level.in_(["HIGH", "CRITICAL"]))
        .count()
    )
    active_simulations = (
        db.query(SessionModel)
        .filter(SessionModel.status == SessionStatus.RUNNING)
        .count()
    )

    # Ratio of total Detection records to total SecurityEvent records across all sessions.
    # Numerator: Total count of Detection records.
    # Denominator: Total count of SecurityEvent records.
    # Scope: All historical sessions in the development database.
    # Units: Detections per Event (float ratio).
    if total_events > 0:
        ratio = round(detected_threats / total_events, 2)
        detections_per_event_ratio = f"{ratio}"
    else:
        detections_per_event_ratio = "N/A"

    # Ground-truth benign vs. malicious event labels are not yet available; returns N/A until normal traffic baseline is established.
    false_positive_rate = "N/A"

    # Read trained ML model metrics if available; do not fall back to hardcoded numbers
    model_accuracy = "N/A"
    model_accuracy_source: Optional[str] = None

    if os.path.isfile(METRICS_PATH):
        try:
            with open(METRICS_PATH, "r", encoding="utf-8") as f:
                metrics_data = json.load(f)
                raw_accuracy = metrics_data.get("accuracy")
                if raw_accuracy is not None and isinstance(raw_accuracy, (int, float)):
                    acc_val = float(raw_accuracy)
                    if acc_val <= 1.0:
                        model_accuracy = f"{round(acc_val * 100, 1)}%"
                    else:
                        model_accuracy = f"{round(acc_val, 1)}%"
                source_val = metrics_data.get("data_source")
                if source_val:
                    model_accuracy_source = str(source_val)
        except Exception as exc:
            logger.warning("Failed to read ML metrics artifact from %s: %s", METRICS_PATH, exc)
            model_accuracy = "N/A"
            model_accuracy_source = None

    return {
        "total_events": total_events,
        "detected_threats": detected_threats,
        "high_risk_events": high_risk_events,
        "active_simulations": active_simulations,
        "detections_per_event_ratio": detections_per_event_ratio,
        "false_positive_rate": false_positive_rate,
        "model_accuracy": model_accuracy,
        "model_accuracy_source": model_accuracy_source,
    }


@router.get(
    "/api/simulation/{simulation_id}/timeline",
    response_model=List[RealSimulationTimelineStep],
    summary="Get real chronological timeline for a simulation",
)
def get_simulation_timeline(
    simulation_id: str,
    db: DBSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Returns an ordered list of timeline stages based on actual DB timestamps."""
    first_ev = db.query(SecurityEvent).filter(SecurityEvent.simulation_id == simulation_id).first()
    if not first_ev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation {simulation_id} not found."
        )

    # Establish an explicit, validated mapping from simulation ID to its owning session
    integrity = verify_record_integrity("SecurityEvent", first_ev, db)
    if integrity not in ("verified", "verified_legacy"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Simulation integrity validation failed. Cannot map to session reliably."
        )

    session_id = first_ev.session_id
    session = db.query(SessionModel).filter(SessionModel.id == session_id).first()

    timeline = []

    # 1. Simulation started (Priority 0)
    if session and session.started_at:
        timeline.append({
            "step": "simulation_started",
            "timestamp": session.started_at.isoformat(),
            "status": "completed",
            "label": "Simulation started",
            "details": f"Scenario: {session.scenario.name}" if session.scenario else None,
            "simulation_id": simulation_id,
            "_sort_key": (session.started_at, 0, session.id)
        })

    # 2. Events generated (Priority 1)
    events = db.query(SecurityEvent).filter(SecurityEvent.simulation_id == simulation_id).all()
    for ev in events:
        if ev.timestamp:
            timeline.append({
                "step": "event_generated",
                "timestamp": ev.timestamp.isoformat(),
                "status": "completed",
                "label": f"Event: {ev.event_type.replace('_', ' ').capitalize()}",
                "details": f"Source: {ev.source} -> Target: {ev.target}",
                "related_id": ev.id,
                "simulation_id": simulation_id,
                "risk_score": ev.risk_score,
                "_sort_key": (ev.timestamp, 1, ev.id)
            })

    # Suricata events (Priority 1)
    suricata_events = db.query(SuricataEvent).filter(SuricataEvent.session_id == session_id).all()
    for sev in suricata_events:
        if sev.timestamp:
            timeline.append({
                "step": "suricata_event_generated",
                "timestamp": sev.timestamp.isoformat(),
                "status": "completed",
                "label": f"IDS Event: {sev.protocol}",
                "details": f"{sev.src_ip} -> {sev.dest_ip}:{sev.dest_port} | Signature: {sev.raw_signature}",
                "related_id": sev.id,
                "simulation_id": simulation_id,
                "severity": sev.severity,
                "_sort_key": (sev.timestamp, 1, sev.id)
            })

    # 3. Detections (Priority 2)
    detections = db.query(Detection).filter(Detection.session_id == session_id).all()
    for d in detections:
        if d.timestamp:
            source_str = d.source.value if hasattr(d.source, "value") else str(d.source)
            timeline.append({
                "step": "detection_triggered",
                "timestamp": d.timestamp.isoformat(),
                "status": "completed",
                "label": f"[{source_str.upper()} Detection] {d.label}",
                "details": d.explanation,
                "related_id": d.id,
                "simulation_id": simulation_id,
                "_sort_key": (d.timestamp, 2, d.id)
            })

    # 4. Risk Calculated (Priority 3)
    risk = db.query(RiskScore).filter(RiskScore.session_id == session_id).first()
    if risk and risk.timestamp:
        band_str = risk.band.value if hasattr(risk.band, "value") else str(risk.band)
        timeline.append({
            "step": "risk_calculated",
            "timestamp": risk.timestamp.isoformat(),
            "status": "completed",
            "label": f"Risk calculated: {band_str.upper()} ({risk.score}/100)",
            "score": risk.score,
            "band": band_str.upper(),
            "related_id": risk.id,
            "simulation_id": simulation_id,
            "_sort_key": (risk.timestamp, 3, risk.id)
        })

    # Note: Removed fabricated "alert_generated" stage as it is not backed by DB persistence.

    # Sort strict by timestamp, then priority, then DB ID
    timeline.sort(key=lambda x: x["_sort_key"])

    # Remove internal sort key before returning
    for item in timeline:
        item.pop("_sort_key", None)

    return timeline

class MLTrainRequest(BaseModel):
    task_name: str = Field(..., description="ML Task to train, e.g. 'port_scan'")

@router.post(
    "/api/ml/train",
    status_code=status.HTTP_200_OK,
    summary="Trigger Adaptive ML Retraining",
)
def trigger_ml_training(
    payload: MLTrainRequest,
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Triggers the adaptive learning engine to train a new candidate model
    using persisted LearningExample dataset. Evaluates and accepts/rejects.
    """
    try:
        result = train_and_evaluate_model(task_name=payload.task_name, db=db)
        return result
    except Exception as exc:
        logger.exception("Error training ML model: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to train model.",
        )

@router.get(
    "/api/ml/status",
    status_code=status.HTTP_200_OK,
    summary="Get Adaptive ML Engine Status",
)
def get_ml_status(
    task_name: str = "port_scan",
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Returns the current state of the Adaptive Engine.
    """
    try:
        return get_adaptive_status(task_name=task_name, db=db)
    except Exception as exc:
        logger.exception("Error getting ML status: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get ML status.",
        )

class MLRollbackRequest(BaseModel):
    task_name: str = "port_scan"
    version_string: str


@router.get(
    "/api/ml/readiness",
    status_code=status.HTTP_200_OK,
    summary="Report which ML detectors are actually deployed and verifiable",
)
def api_ml_readiness(db: DBSession = Depends(get_db)) -> Dict[str, Any]:
    """Honest capability report: artifact presence, provenance, feature contract.

    Consumers must use this instead of assuming a detector is active - an absent
    artifact and an artifact without verifiable provenance are reported as
    distinct states.
    """
    try:
        return get_ml_readiness(db)
    except Exception as exc:
        logger.exception("Error computing ML readiness: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to report ML readiness.",
        )


@router.post(
    "/api/ml/rollback",
    status_code=status.HTTP_200_OK,
    summary="Rollback to a previously trained ML model version",
)
def api_rollback_ml_model(
    payload: MLRollbackRequest,
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    try:
        return rollback_model(task_name=payload.task_name, target_version=payload.version_string, db=db)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as exc:
        logger.exception("Error during rollback: %s", exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Rollback failed.")

# ==========================================
# Synthetic Training Data Generator
# ==========================================

import random
import uuid
from app.models.models import LearningExample

class GenerateDataRequest(BaseModel):
    scenario: str = Field(..., description="'Normal Traffic' or 'Port Scan'")
    count: int = Field(..., ge=1, le=1000)
    seed: Optional[int] = None

class SyntheticExampleResponse(BaseModel):
    record_id: str
    scenario: str
    label: int
    features: Dict[str, float]
    provenance: str

@router.post(
    "/api/ml/data/generate",
    response_model=List[SyntheticExampleResponse],
    summary="Preview synthetic training data",
)
def generate_training_data_preview(payload: GenerateDataRequest):
    if payload.scenario not in ["Normal Traffic", "Port Scan"]:
        raise HTTPException(status_code=400, detail="Only 'Normal Traffic' and 'Port Scan' are currently supported.")
        
    if payload.seed is not None:
        rng = random.Random(payload.seed)
    else:
        rng = random.Random()
        
    examples = []
    
    for _ in range(payload.count):
        # We need a record ID for identity
        record_id = f"syn_{uuid.UUID(int=rng.getrandbits(128), version=4).hex[:8]}"
        
        if payload.scenario == "Normal Traffic":
            label = 0
            distinct_dest_ports = rng.randint(1, 5)
            events_per_second = round(rng.uniform(0.1, 5.0), 2)
            distinct_dest_ips = rng.randint(1, 3)
            avg_severity = round(rng.uniform(1.0, 2.0), 2)
            protocol_diversity = rng.randint(1, 2)
        elif payload.scenario == "Port Scan":
            label = 1
            distinct_dest_ports = rng.randint(50, 1000)
            events_per_second = round(rng.uniform(10.0, 500.0), 2)
            distinct_dest_ips = rng.randint(1, 100)
            avg_severity = round(rng.uniform(2.0, 4.0), 2)
            protocol_diversity = 1
            
        feature_dict = {
            "distinct_dest_ports": float(distinct_dest_ports),
            "events_per_second": float(events_per_second),
            "distinct_dest_ips": float(distinct_dest_ips),
            "avg_severity": float(avg_severity),
            "protocol_diversity": float(protocol_diversity)
        }
        
        examples.append({
            "record_id": record_id,
            "scenario": payload.scenario,
            "label": label,
            "features": feature_dict,
            "provenance": "synthetic_generator"
        })
        
    return examples

class AddDataRequest(BaseModel):
    examples: List[SyntheticExampleResponse]

@router.post(
    "/api/ml/data/add",
    summary="Add validated examples to the training dataset",
)
def add_training_data(payload: AddDataRequest, db: DBSession = Depends(get_db)):
    added_count = 0
    from ml.features import FEATURE_NAMES
    
    for ex in payload.examples:
        # Strict validation
        if ex.label not in [0, 1]:
            continue
            
        # Validate schema features
        missing = [f for f in FEATURE_NAMES if f not in ex.features]
        if missing:
            continue
            
        # Prevent duplicates by checking if exact feature set already exists
        # Alternatively, we just add it since they are uniquely generated.
        
        db_example = LearningExample(
            task_name="port_scan",
            label=ex.label,
            feature_json=json.dumps(ex.features)
        )
        db.add(db_example)
        added_count += 1
        
    db.commit()
    return {"status": "SUCCESS", "added": added_count}

@router.post(
    "/api/datasets/{dataset_id}/import_learning",
    summary="Import an evaluated dataset into Adaptive Learning",
)
def import_dataset_learning(
    dataset_id: str,
    db: DBSession = Depends(get_db)
):
    from app.services.ml_engine import extract_features, extract_auth_features
    from app.models import Dataset
    
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")
    if not dataset.is_evaluated:
        raise HTTPException(status_code=400, detail="Dataset must be evaluated before import")
        
    events = json.loads(dataset.payload_json)
    added_count = 0
    
    if dataset.scenario_category == "port_scan":
        from collections import defaultdict
        events_by_src = defaultdict(list)
        for ev in events:
            if "src_ip" in ev:
                events_by_src[ev["src_ip"]].append(ev)
                
        for src_ip, ip_events in events_by_src.items():
            feat_dict = extract_features(ip_events)
            db_ex = LearningExample(
                task_name="port_scan",
                label=1,
                feature_json=json.dumps(feat_dict)
            )
            db.add(db_ex)
            added_count += 1
            
    elif dataset.scenario_category in ["brute_force", "credential_stuffing"]:
        from collections import defaultdict
        events_by_src = defaultdict(list)
        for ev in events:
            if "source" in ev:
                events_by_src[ev["source"]].append(ev)
                
        for src_ip, ip_events in events_by_src.items():
            feat_dict = extract_auth_features(ip_events)
            db_ex = LearningExample(
                task_name="brute_force",
                label=1,
                feature_json=json.dumps(feat_dict)
            )
            db.add(db_ex)
            added_count += 1
            
    else:
        raise HTTPException(status_code=400, detail="Unsupported scenario for import")
        
    dataset.is_training_eligible = True
    db.commit()
    return {"status": "SUCCESS", "added": added_count}

@router.get(
    "/api/ml/data",
    summary="Get all learning examples",
)
def get_training_data(db: DBSession = Depends(get_db)):
    examples = db.query(LearningExample).filter(LearningExample.task_name == "port_scan").all()
    results = []
    for ex in examples:
        results.append({
            "id": ex.id,
            "label": ex.label,
            "features": json.loads(ex.feature_json),
            "created_at": ex.created_at.isoformat()
        })
    return results
