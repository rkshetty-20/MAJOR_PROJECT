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

# Suricata severity classes: 1 = most severe, 4 = informational.
_SEVERITY_BEST = 1.0
_SEVERITY_WORST = 4.0
_SEVERITY_MAX_POINTS = 10.0


def _is_qualifying_confidence(value: Any) -> bool:
    """A confidence qualifies only if it is a real number in [0, 1].

    NaN/infinity or out-of-range values are excluded from the ML maximum so a
    corrupt detection row cannot silently dominate the fusion score.
    """
    try:
        v = float(value)
    except (TypeError, ValueError):
        return False
    if v != v or v in (float("inf"), float("-inf")):
        return False
    return 0.0 <= v <= 1.0


def _severity_term(
    suricata_events: List[SuricataEvent],
    security_events: List[SecurityEvent],
) -> tuple:
    """Severity contribution ``s`` (0-10 points).

    Primary path: mean Suricata severity inverse-linearly interpolated over the
    1..4 severity-class scale, so avg 1 -> 10 points and avg 4 -> 0 points.

    Fallback path (session has no Suricata events at all): host/security telemetry
    risk band - CRITICAL 10, HIGH 7, otherwise 4.

    No events of either kind: 0 with avg_sev None (term is absent, not zero-priced).

    Returns (term, avg_severity, source) where source is one of
    'suricata' | 'security_events' | 'none'.
    """
    severities = [float(e.severity) for e in suricata_events if e.severity is not None]
    if severities:
        avg_sev = sum(severities) / len(severities)
        span = _SEVERITY_WORST - _SEVERITY_BEST
        raw = (_SEVERITY_WORST - avg_sev) / span * _SEVERITY_MAX_POINTS
        term = max(0.0, min(_SEVERITY_MAX_POINTS, raw))
        return term, avg_sev, "suricata"

    if security_events:
        has_crit = any((e.risk_level or "").upper() == "CRITICAL" for e in security_events)
        has_high = any((e.risk_level or "").upper() == "HIGH" for e in security_events)
        if has_crit:
            return 10.0, 1.0, "security_events"
        if has_high:
            return 7.0, 2.0, "security_events"
        return 4.0, 3.0, "security_events"

    return 0.0, None, "none"


def _band_for_score(score: int) -> RiskBand:
    """Paper severity bands: <30 LOW, 30-59 MEDIUM, 60-84 HIGH, 85-100 CRITICAL."""
    if score < 30:
        return RiskBand.LOW
    if score < 60:
        return RiskBand.MEDIUM
    if score < 85:
        return RiskBand.HIGH
    return RiskBand.CRITICAL


def compute_risk_score(session_id: int, db: Session) -> RiskScore:
    """
    Computes the research-paper risk-fusion score for a session.

    Paper formula (authoritative, single implementation):

        S = round(clamp(r + m + c + a + s, 0, 100))

      r  Rule term: 40 if any qualifying rule detection fires, otherwise 0.
      m  Multi-signal term: min(30, 15 * (n - 1)) where n is the number of
         DISTINCT rule labels (repeated detections of the same label collapse
         into one contribution, so an event cannot be counted twice).
      c  ML term: 40 * highest qualifying ML confidence. A detection with a
         missing/None confidence is not qualifying and contributes 0 to the
         maximum (it is still counted for agreement).
      a  Agreement term: 10 when at least one label is produced by BOTH a rule
         and the ML model, otherwise 0.
      s  Severity term: Suricata-derived severity contribution (see
         _severity_term), with the documented fallback when a session has no
         Suricata events.

    NOTE ON DOUBLE COUNTING: the paper sums all five terms directly; the
    agreement bonus `a` is the ONLY mechanism the paper permits for recognising
    rule/ML concurrence. Terms are therefore never suppressed, zeroed or
    max-replaced against one another.

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

    # --- Term 2: Multi-Signal m = min(30, 15 * (n - 1)) over DISTINCT rule labels ---
    # Distinct labels are sorted so the persisted breakdown is deterministic and
    # repeat detections of one label never inflate n.
    rule_labels: Set[str] = {d.label for d in rule_detections if d.label}
    multi_signal_labels: List[str] = sorted(rule_labels)
    multi_signal_bonus = 0.0
    if len(rule_labels) > 1:
        multi_signal_bonus = min(30.0, float(len(rule_labels) - 1) * 15.0)

    # --- Term 3: ML confidence c = 40 * highest qualifying ML confidence ---
    # Non-numeric / missing confidences are not qualifying; tracked for explainability.
    ml_confidences = [
        float(d.confidence) for d in ml_detections
        if d.confidence is not None and _is_qualifying_confidence(d.confidence)
    ]
    missing_confidence_count = len(ml_detections) - len(ml_confidences)
    highest_ml_conf = max(ml_confidences) if ml_confidences else 0.0
    ml_confidence_term = highest_ml_conf * 40.0

    # --- Term 4: Agreement a = 10 when a rule label and an ML label coincide ---
    # Per the paper this is purely additive: `r` and `c` are NOT suppressed here.
    ml_labels: Set[str] = {d.label for d in ml_detections if d.label}
    agreed_labels: Set[str] = rule_labels.intersection(ml_labels)
    agreement_bonus = 10.0 if len(agreed_labels) > 0 else 0.0

    # --- Term 5: Severity contribution s (Suricata first, documented fallback) ---
    events: List[SuricataEvent] = (
        db.query(SuricataEvent)
        .filter(SuricataEvent.session_id == session_id)
        .all()
    )
    sec_events: List[SecurityEvent] = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.session_id == session_id)
        .all()
    )
    severity_term, avg_sev, severity_source = _severity_term(events, sec_events)

    # --- S = round(clamp(r + m + c + a + s, 0, 100)) ---
    raw_total = rule_term + multi_signal_bonus + ml_confidence_term + agreement_bonus + severity_term
    final_score = int(round(max(0.0, min(100.0, raw_total))))
    clamped = raw_total < 0.0 or raw_total > 100.0

    # --- Map to Risk Band ---
    band = _band_for_score(final_score)

    # --- Transparent breakdown of every term ---
    contributing_factors: Dict[str, Any] = {
        "formula": "S = round(clamp(r + m + c + a + s, 0, 100))",
        "terms": {
            "r": round(rule_term, 4),
            "m": round(multi_signal_bonus, 4),
            "c": round(ml_confidence_term, 4),
            "a": round(agreement_bonus, 4),
            "s": round(severity_term, 4),
        },
        "raw_total": round(raw_total, 4),
        "clamped": clamped,
        # Legacy integer keys retained for existing API consumers / UI cards.
        "rule_detected": int(round(rule_term)),
        "multi_signal_bonus": int(round(multi_signal_bonus)),
        "ml_confidence_term": int(round(ml_confidence_term)),
        "agreement_bonus": int(round(agreement_bonus)),
        "severity_term": int(round(severity_term)),
        "ml_highest_confidence": round(highest_ml_conf, 4) if ml_confidences else None,
        "average_severity": round(avg_sev, 2) if avg_sev is not None else None,
        "severity_source": severity_source,
        "agreed_labels": sorted(agreed_labels),
        "triggered_rules": multi_signal_labels,
        # Duplicate / evidence accounting: shows exactly what was collapsed.
        "rule_detection_count": len(rule_detections),
        "ml_detection_count": len(ml_detections),
        "distinct_rule_labels": len(rule_labels),
        "collapsed_duplicate_rule_detections": max(0, len(rule_detections) - len(rule_labels)),
        "ml_missing_confidence_count": missing_confidence_count,
        "suricata_event_count": len(events),
        "security_event_count": len(sec_events),
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
