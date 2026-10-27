import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Set
from sqlalchemy.orm import Session

from app.models import (
    Session as SessionModel,
    SuricataEvent,
    SecurityEvent,
    Detection,
    DetectionSource,
    RiskScore,
    RiskBand,
)

logger = logging.getLogger(__name__)


def compute_risk_score(session_id: int, db: Session) -> RiskScore:
    """
    Computes a transparent, explainable situational risk score (0-100)
    for a learning or simulation session by fusing rule and ML detections with event severity:

    Scoring Formula:
      1. Rule Detection Term:
         +40 if any rule detection exists for the session.
      2. Multi-Signal Rule Diversity Bonus:
         +15 for each additional distinct rule triggered (up to +30),
         demonstrating how multiple signals increase the overall risk.
      3. ML Confidence Term:
         +(ml_confidence * 40) if any ML detection exists, using the highest confidence.
      4. Hybrid Agreement Bonus:
         +10 if both rule and ML detections exist and agree on the same detection label.
      5. Event Severity Term:
         + up to 10 based on average event severity for the session (Suricata or host events),
         scaled inversely (level 1 is most severe).

    Bands:
      - 0-29:   low
      - 30-59:  medium
      - 60-84:  high
      - 85-100: critical

    Stores contributing_factors as a JSON string for full explainability.
    Updates existing RiskScore row if one already exists for this session.
    """
    session = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not session:
        raise ValueError(f"Session with id {session_id} not found")

    # 1. Load all detections for this session
    detections: List[Detection] = (
        db.query(Detection)
        .filter(Detection.session_id == session_id)
        .all()
    )

    rule_detections = [d for d in detections if d.source == DetectionSource.RULE]
    ml_detections = [d for d in detections if d.source == DetectionSource.ML]

    # --- Term 1: Rule Detection (+40 if exists) ---
    rule_detected = len(rule_detections) > 0
    rule_term = 40.0 if rule_detected else 0.0

    # --- Term 2: Multi-Signal Rule Diversity Bonus (+15 per extra rule, max 30) ---
    rule_labels: Set[str] = {d.label for d in rule_detections if d.label}
    multi_signal_bonus = 0.0
    if len(rule_labels) > 1:
        multi_signal_bonus = min(30.0, float(len(rule_labels) - 1) * 15.0)

    # --- Term 3: ML Confidence (+ ml_confidence * 40 using highest confidence) ---
    ml_confidences = [float(d.confidence) for d in ml_detections if d.confidence is not None]
    highest_ml_conf = max(ml_confidences) if ml_confidences else 0.0
    ml_confidence_term = round(highest_ml_conf * 40.0, 1)

    # --- Term 4: Hybrid Agreement Bonus (+10 if both exist and agree on label) ---
    ml_labels: Set[str] = {d.label for d in ml_detections if d.label}
    agreed_labels = rule_labels.intersection(ml_labels)
    agreement_bonus = 0.0
    
    # Avoid double-counting: if they agree, take the max of Rule or ML, and add a bonus.
    if len(agreed_labels) > 0:
        agreement_bonus = 10.0
        if rule_term >= ml_confidence_term:
            ml_confidence_term = 0.0
        else:
            rule_term = 0.0

    # --- Term 5: Event Severity (up to +10, inverse scaled: 1 is most severe) ---
    events: List[SuricataEvent] = (
        db.query(SuricataEvent)
        .filter(SuricataEvent.session_id == session_id)
        .all()
    )

    severities = [float(e.severity) for e in events if e.severity is not None]
    if severities:
        avg_sev = sum(severities) / len(severities)
        # Suricata scale: 1 (Critical), 2 (Medium), 3 (Low), 4 (Info)
        # Linear inverse interpolation: avg_sev=1.0 -> 10.0, avg_sev=4.0 -> 0.0
        severity_term = round(max(0.0, min(10.0, (4.0 - avg_sev) / 3.0 * 10.0)), 1)
    else:
        # Check if SecurityEvents have high/critical risk indicators
        sec_events: List[SecurityEvent] = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.session_id == session_id)
            .all()
        )
        if sec_events:
            has_crit = any(e.risk_level == "CRITICAL" for e in sec_events)
            has_high = any(e.risk_level == "HIGH" for e in sec_events)
            if has_crit:
                severity_term = 10.0
            elif has_high:
                severity_term = 7.0
            else:
                severity_term = 4.0
            avg_sev = 1.0 if has_crit else (2.0 if has_high else 3.0)
        else:
            avg_sev = None
            severity_term = 0.0

    # --- Calculate Total Score & Clamp [0, 100] ---
    raw_total = rule_term + multi_signal_bonus + ml_confidence_term + agreement_bonus + severity_term
    final_score = int(round(max(0.0, min(100.0, raw_total))))

    # --- Map to Risk Band ---
    if final_score < 30:
        band = RiskBand.LOW
    elif final_score < 60:
        band = RiskBand.MEDIUM
    elif final_score < 85:
        band = RiskBand.HIGH
    else:
        band = RiskBand.CRITICAL

    # --- Construct Contributing Factors JSON ---
    contributing_factors: Dict[str, Any] = {
        "rule_detected": int(round(rule_term)),
        "multi_signal_bonus": int(round(multi_signal_bonus)),
        "ml_confidence_term": int(round(ml_confidence_term)),
        "agreement_bonus": int(round(agreement_bonus)),
        "severity_term": int(round(severity_term)),
        "ml_highest_confidence": round(highest_ml_conf, 4) if ml_detections else None,
        "average_severity": round(avg_sev, 2) if avg_sev is not None else None,
        "agreed_labels": list(agreed_labels),
        "triggered_rules": list(rule_labels),
    }

    logger.info(
        "Session %d risk fusion: score=%d, band=%s, factors=%s",
        session_id,
        final_score,
        band.value,
        contributing_factors,
    )

    # --- Persist or Update RiskScore row (avoid duplicates) ---
    risk_row = (
        db.query(RiskScore)
        .filter(RiskScore.session_id == session_id)
        .first()
    )

    if risk_row:
        risk_row.score = final_score
        risk_row.band = band
        risk_row.contributing_factors = json.dumps(contributing_factors)
        risk_row.timestamp = datetime.now(timezone.utc)
    else:
        risk_row = RiskScore(
            session_id=session_id,
            score=final_score,
            band=band,
            contributing_factors=json.dumps(contributing_factors),
            timestamp=datetime.now(timezone.utc),
        )
        db.add(risk_row)

    db.commit()
    db.refresh(risk_row)
    return risk_row
