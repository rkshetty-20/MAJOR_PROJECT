import json
import logging
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.models.models import (
    Detection, SuricataEvent, SecurityEvent, Incident, IncidentStatus, IncidentFeedback, AnalystDecision
)

logger = logging.getLogger(__name__)

# ===================================================================
# Phase 1: Unified Event Schema
# ===================================================================
class NormalizedEvent(BaseModel):
    schema_version: str = "1.0"
    event_id: str
    event_type: str
    source_module: str
    timestamp: datetime
    user_id: Optional[str] = None
    host_id: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    domain: Optional[str] = None
    session_id: Optional[str] = None
    simulation_id: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[float] = None
    evidence: Optional[Dict[str, Any]] = None


def normalize_suricata_event(ev: SuricataEvent) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"suricata_{ev.id}",
        event_type="network_intrusion",
        source_module="IDS",
        timestamp=ev.timestamp,
        source_ip=ev.src_ip,
        destination_ip=ev.dest_ip,
        session_id=str(ev.session_id) if ev.session_id else None,
        severity=str(ev.severity),
        evidence={"raw_signature": ev.raw_signature, "protocol": ev.protocol, "dest_port": ev.dest_port}
    )


def normalize_security_event(ev: SecurityEvent) -> NormalizedEvent:
    payload = {}
    if ev.payload_json:
        try:
            payload = json.loads(ev.payload_json)
        except json.JSONDecodeError:
            pass

    domain = None
    if ev.event_type == "phishing_url" or (ev.target and ev.target.startswith("http")):
        domain = ev.target

    return NormalizedEvent(
        event_id=f"sec_{ev.id}",
        event_type=ev.event_type,
        source_module="SecurityTelemetry",
        timestamp=ev.timestamp,
        user_id=ev.target if not domain else None,
        host_id=ev.device,
        domain=domain,
        source_ip=payload.get("ip") or ev.source,
        session_id=str(ev.session_id) if ev.session_id else None,
        simulation_id=ev.simulation_id,
        severity=ev.risk_level,
        evidence={"payload": payload, "location": ev.location}
    )


def normalize_detection(det: Detection) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"det_{det.id}",
        event_type="detection_alert",
        source_module=det.source.value if hasattr(det.source, 'value') else str(det.source),
        timestamp=det.timestamp,
        session_id=str(det.session_id) if det.session_id else None,
        confidence=det.confidence,
        evidence={"label": det.label, "explanation": det.explanation, "features": det.features}
    )


# ===================================================================
# Phase 2 & 3: Correlation Engine and Unified Incidents
# ===================================================================

def generate_incident_id() -> str:
    return f"INC-{uuid.uuid4().hex[:8].upper()}"


def _find_active_incident_for_session(db: Session, session_id: str) -> Optional[Incident]:
    # Look for an OPEN incident that contains this session_id in its related events
    # This is a naive lookup; for larger scale we'd use a dedicated join table.
    incidents = db.query(Incident).filter(Incident.status == IncidentStatus.OPEN).all()
    for inc in incidents:
        if not inc.related_events_json: continue
        events = json.loads(inc.related_events_json)
        if any(e.get("session_id") == session_id for e in events):
            return inc
    return None


def run_correlation(db: Session, new_event: NormalizedEvent) -> Incident:
    """
    Accepts a normalized event, determines if it relates to an existing open incident
    (based on session_id, host_id, user_id), or creates a new incident.
    """
    incident = None
    
    # 1. Correlate by Session or Simulation (Deterministic)
    if new_event.session_id:
        incident = _find_active_incident_for_session(db, new_event.session_id)
        
    # 2. (Future) Correlate by shared user_id, host_id, or IP within a time window
    # if not incident and new_event.user_id:
    #    ... look up recent incidents involving user_id ...

    if not incident:
        # Create new incident
        incident = Incident(
            id=generate_incident_id(),
            title=f"Security Incident involving {new_event.event_type}",
            status=IncidentStatus.OPEN,
            severity=new_event.severity or "MEDIUM",
            evidence_summary_json=json.dumps([]),
            related_events_json=json.dumps([]),
            source_modules_json=json.dumps([new_event.source_module]),
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)

    # Attach event to incident
    related_events = json.loads(incident.related_events_json or "[]")
    
    # Prevent duplicates
    if any(e["event_id"] == new_event.event_id for e in related_events):
        return incident

    event_dict = new_event.model_dump()
    event_dict["timestamp"] = event_dict["timestamp"].isoformat()
    
    # Determine relationship
    if len(related_events) == 0:
        event_dict["correlation_reason"] = "Initial event"
    else:
        if new_event.session_id and any(e.get("session_id") == new_event.session_id for e in related_events):
            event_dict["correlation_reason"] = "Shared Session"
        elif new_event.user_id and any(e.get("user_id") == new_event.user_id for e in related_events):
            event_dict["correlation_reason"] = "Shared User ID"
        elif new_event.source_ip and any(e.get("source_ip") == new_event.source_ip for e in related_events):
            event_dict["correlation_reason"] = "Shared Source IP"
        else:
            event_dict["correlation_reason"] = "Rule-derived association"

    related_events.append(event_dict)
    
    # Update modules
    modules = set(json.loads(incident.source_modules_json or "[]"))
    modules.add(new_event.source_module)
    
    # Update Incident Risk
    # Simple risk policy: base score + factor per distinct event
    base_risk = 50.0 if new_event.severity in ["HIGH", "CRITICAL"] else 20.0
    incident.risk_score = min(100.0, base_risk + (len(related_events) * 5.0))
    incident.severity = "CRITICAL" if incident.risk_score > 85 else ("HIGH" if incident.risk_score > 60 else "MEDIUM")
    
    # Re-evaluate title if Phishing is involved
    has_phishing = any(e["event_type"] == "phishing_url" for e in related_events)
    has_intrusion = any(e["event_type"] == "network_intrusion" for e in related_events)
    has_auth = any(e["event_type"] in ["login_attempt", "failed_login", "suspicious_login"] for e in related_events)
    
    if has_phishing and (has_intrusion or has_auth):
        incident.title = "Cross-Module Threat: Phishing followed by Intrusion/Auth Activity"
    elif has_phishing:
        incident.title = "Phishing Campaign Detected"
    elif has_intrusion:
        incident.title = "Network Intrusion Detected"
    
    incident.related_events_json = json.dumps(related_events)
    incident.source_modules_json = json.dumps(list(modules))
    
    db.commit()
    db.refresh(incident)
    return incident
