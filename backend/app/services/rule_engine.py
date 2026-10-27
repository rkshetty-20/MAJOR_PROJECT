import json
import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from sqlalchemy.orm import Session

from app.models import (
    Session as SessionModel,
    Scenario,
    SuricataEvent,
    SecurityEvent,
    Detection,
    DetectionSource,
    ScenarioCategory,
)
from app.services.phishing_detector import evaluate_phishing_url
from app.services.correlation_engine import run_correlation, normalize_detection


def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371.0  # Earth radius in kilometers
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c



def _normalize_dt(dt: datetime) -> datetime:
    """Normalize datetime to timezone-aware UTC datetime."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _evaluate_port_scan(
    session_id: int,
    config: dict,
    db: Session,
    existing_labels: Set[str],
) -> Optional[Detection]:
    """
    Evaluates the port_scan behavioral rule:
    Groups events by src_ip and slides a window of window_seconds.
    If distinct dest_port count >= threshold_ports, produces a Detection row.
    """
    rule_label = "port_scan_detected"
    if rule_label in existing_labels:
        return None

    behavioral_rule = config.get("behavioral_rule", {})
    threshold_ports = int(behavioral_rule.get("threshold_ports", 15))
    window_seconds = float(behavioral_rule.get("window_seconds", 10))

    events = (
        db.query(SuricataEvent)
        .filter(
            SuricataEvent.session_id == session_id,
            SuricataEvent.dest_port.isnot(None),
        )
        .order_by(SuricataEvent.timestamp.asc())
        .all()
    )

    if not events:
        return None

    # Group events by src_ip
    events_by_src: Dict[str, List[SuricataEvent]] = defaultdict(list)
    for ev in events:
        if ev.src_ip:
            events_by_src[ev.src_ip].append(ev)

    for src_ip, ip_events in events_by_src.items():
        total_events = len(ip_events)

        for i in range(total_events):
            start_time = _normalize_dt(ip_events[i].timestamp)
            distinct_ports: Set[int] = set()

            for j in range(i, total_events):
                current_time = _normalize_dt(ip_events[j].timestamp)
                elapsed_seconds = (current_time - start_time).total_seconds()

                if elapsed_seconds <= window_seconds:
                    if ip_events[j].dest_port is not None:
                        distinct_ports.add(ip_events[j].dest_port)
                else:
                    break

            if len(distinct_ports) >= threshold_ports:
                count = len(distinct_ports)
                display_window = int(window_seconds) if window_seconds.is_integer() else window_seconds
                explanation = (
                    f"Detected {count} distinct ports from {src_ip} within "
                    f"{display_window}s (threshold: {threshold_ports})"
                )

                # Correlation: Gather all events in this window for this source
                correlated = []
                for k in range(i, j + 1):
                    ev = ip_events[k]
                    correlated.append({
                        "event_id": ev.id,
                        "type": "SuricataEvent",
                        "timestamp": ev.timestamp.isoformat(),
                        "reason": f"Targeted port {ev.dest_port} from {src_ip}",
                        "is_hypothesis": False
                    })
                
                features_json = json.dumps({"correlated_events": correlated})

                detection = Detection(
                    session_id=session_id,
                    source=DetectionSource.RULE,
                    label=rule_label,
                    confidence=1.0,
                    explanation=explanation,
                    features=features_json,
                    timestamp=datetime.now(timezone.utc),
                )
                db.add(detection)
                db.commit()
                db.refresh(detection)
                existing_labels.add(rule_label)
                
                try:
                    norm = normalize_detection(detection)
                    run_correlation(db, norm)
                except Exception as e:
                    import logging
                    logging.getLogger(__name__).error(f"Failed to correlate port scan detection: {e}")
                    
                return detection

    return None


def _evaluate_security_events(
    session_id: int,
    db: Session,
    existing_labels: Set[str],
) -> List[Detection]:
    """
    Evaluates rule-based detections against synthetic and live SecurityEvent telemetry
    (brute force, credential stuffing, suspicious login, impossible travel, new device, etc.).
    """
    sec_events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.session_id == session_id)
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )

    if not sec_events:
        return []

    new_detections: List[Detection] = []
    scenarios_present = {e.scenario for e in sec_events}

    def _add_detection(label: str, explanation: str, confidence: float = 1.0, correlated_events: List[Dict] = None):
        if label not in existing_labels:
            feat = json.dumps({"correlated_events": correlated_events}) if correlated_events else None
            det = Detection(
                session_id=session_id,
                source=DetectionSource.RULE,
                label=label,
                confidence=confidence,
                explanation=explanation,
                features=feat,
                timestamp=datetime.now(timezone.utc),
            )
            db.add(det)
            db.commit()
            db.refresh(det)
            existing_labels.add(label)
            new_detections.append(det)
            
            try:
                norm = normalize_detection(det)
                run_correlation(db, norm)
            except Exception as e:
                import logging
                logging.getLogger(__name__).error(f"Failed to correlate security event detection: {e}")

    # 1. Brute Force Login & Sustained Attack
    # Detected by grouping events by target and looking for multiple failed logins
    targets = set(e.target for e in sec_events if e.target)
    for target in targets:
        target_events = sorted([e for e in sec_events if e.target == target], key=lambda x: _normalize_dt(x.timestamp))
        failed = 0
        src = None
        for ev in target_events:
            if "failed" in ev.event_type.lower():
                failed += 1
                if not src:
                    src = ev.source
            elif "success" in ev.event_type.lower() and failed >= 3:
                # Correlate failure burst and success
                corr = [{"event_id": e.id, "type": "SecurityEvent", "timestamp": e.timestamp.isoformat(), "reason": "Failed login attempt"} for e in target_events[:target_events.index(ev)] if "failed" in e.event_type.lower()]
                corr.append({"event_id": ev.id, "type": "SecurityEvent", "timestamp": ev.timestamp.isoformat(), "reason": "Successful login after brute force"})
                
                _add_detection(
                    "brute_force_detected",
                    f"High-velocity authentication failure burst: {failed} failed login attempts from {src} targeting {target}, followed by a successful login",
                    confidence=0.95,
                    correlated_events=corr
                )
                failed = 0 # reset
                break
        
        if failed >= 4 and "brute_force_detected" not in existing_labels:
            corr = [{"event_id": e.id, "type": "SecurityEvent", "timestamp": e.timestamp.isoformat(), "reason": "Sustained failed login attempt"} for e in target_events if "failed" in e.event_type.lower()]
            _add_detection(
                "sustained_attack_no_compromise",
                f"Sustained authentication failures: {failed} failed login attempts from {src} targeting {target} with no successful login",
                confidence=0.85,
                correlated_events=corr
            )

    # 2. Credential Stuffing
    # Detected by grouping events by source and looking for rapid attempts across multiple distinct target accounts.
    auth_events = [e for e in sec_events if e.event_type in ["failed_login", "login_attempt", "failed_authentication"]]
    sources = set(e.source for e in auth_events if e.source)
    for src in sources:
        src_events = sorted([e for e in auth_events if e.source == src], key=lambda x: _normalize_dt(x.timestamp))
        if len(src_events) < 3:
            continue
            
        for i in range(len(src_events)):
            start_time = _normalize_dt(src_events[i].timestamp)
            window_events = []
            for j in range(i, len(src_events)):
                if (_normalize_dt(src_events[j].timestamp) - start_time).total_seconds() <= 300:
                    window_events.append(src_events[j])
                else:
                    break
                    
            unique_targets = set(e.target for e in window_events if e.target)
            if len(window_events) >= 3 and len(unique_targets) >= 3:
                corr = [{"event_id": e.id, "type": "SecurityEvent", "timestamp": e.timestamp.isoformat(), "reason": f"Attempt against account {e.target}"} for e in window_events]
                _add_detection(
                    "credential_stuffing_detected",
                    f"Credential stuffing detected: {src} attempted authentication against {len(unique_targets)} distinct accounts within 5 minutes",
                    confidence=0.96,
                    correlated_events=corr
                )
                break  # Already generated for this source

    # 3. Suspicious Login / Account Takeover
    # Detected when an authentication event deviates significantly from established baseline (both location AND device).
    for target in set(e.target for e in sec_events if e.target):
        target_events = sorted([e for e in sec_events if e.target == target], key=lambda x: _normalize_dt(x.timestamp))
        known_devices = set()
        known_locations = set()
        
        for ev in target_events:
            try:
                payload = json.loads(ev.payload_json or "{}")
                dev_id = payload.get("device_id") or ev.device
            except Exception:
                dev_id = ev.device
            
            loc = ev.location
            
            # Establish baseline from known good events
            if ev.event_type in ["known_device_login", "baseline_login"] or getattr(ev, "detection_status", "") == "Normal":
                if dev_id: known_devices.add(dev_id)
                if loc: known_locations.add(loc)
            
            # Evaluate new login attempts/successes
            elif ev.event_type in ["login_attempt", "successful_login", "suspicious_login"]:
                if known_locations and known_devices:
                    if loc and loc not in known_locations and dev_id and dev_id not in known_devices:
                        # Find baseline events to correlate as hypothesis
                        baseline_events = [e for e in target_events if e.event_type in ["known_device_login", "baseline_login"]]
                        corr = [{"event_id": ev.id, "type": "SecurityEvent", "timestamp": ev.timestamp.isoformat(), "reason": "Suspicious deviating login"}]
                        if baseline_events:
                            corr.append({"event_id": baseline_events[-1].id, "type": "SecurityEvent", "timestamp": baseline_events[-1].timestamp.isoformat(), "reason": "Prior baseline event for comparison", "is_hypothesis": True})
                            
                        _add_detection(
                            "suspicious_login_detected",
                            f"Suspicious login detected for {target}: authentication from {loc} using previously unseen device {dev_id}",
                            confidence=0.90,
                            correlated_events=corr
                        )

    # 4. Impossible Travel
    for target in set(e.target for e in sec_events):
        target_events = sorted([e for e in sec_events if e.target == target and e.event_type == "login_attempt"], key=lambda x: _normalize_dt(x.timestamp))
        for i in range(len(target_events) - 1):
            ev1 = target_events[i]
            ev2 = target_events[i+1]
            try:
                p1 = json.loads(ev1.payload_json or "{}")
                p2 = json.loads(ev2.payload_json or "{}")
                lat1, lon1 = p1.get("lat"), p1.get("lon")
                lat2, lon2 = p2.get("lat"), p2.get("lon")
            except Exception:
                continue

            if lat1 is not None and lon1 is not None and lat2 is not None and lon2 is not None:
                distance_km = haversine(lat1, lon1, lat2, lon2)
                interval_hours = (_normalize_dt(ev2.timestamp) - _normalize_dt(ev1.timestamp)).total_seconds() / 3600.0
                if interval_hours > 0:
                    speed_kmh = distance_km / interval_hours
                    if speed_kmh > 900:
                        interval_minutes = interval_hours * 60
                        corr = [
                            {"event_id": ev1.id, "type": "SecurityEvent", "timestamp": ev1.timestamp.isoformat(), "reason": f"Login attempt from location A (lat {lat1})"},
                            {"event_id": ev2.id, "type": "SecurityEvent", "timestamp": ev2.timestamp.isoformat(), "reason": f"Login attempt from location B (lat {lat2})"}
                        ]
                        _add_detection(
                            "impossible_travel_detected",
                            f"Calculated {distance_km:.0f}km in {interval_minutes:.0f}min = {speed_kmh:.0f}km/h, exceeding plausible travel speed",
                            confidence=0.98,
                            correlated_events=corr
                        )

    # 5. New Device Login
    for target in set(e.target for e in sec_events):
        target_events = sorted([e for e in sec_events if e.target == target], key=lambda x: x.timestamp)
        known_devices = set()
        for ev in target_events:
            try:
                payload = json.loads(ev.payload_json or "{}")
                dev_id = payload.get("device_id")
            except Exception:
                dev_id = None
                
            if ev.event_type == "known_device_login" and dev_id:
                known_devices.add(dev_id)
            elif ev.event_type == "login_attempt" and dev_id:
                if known_devices and dev_id not in known_devices:
                    corr = [{"event_id": ev.id, "type": "SecurityEvent", "timestamp": ev.timestamp.isoformat(), "reason": "Login from unrecognized device"}]
                    _add_detection(
                        "new_device_detected",
                        f"Unrecognized endpoint hardware fingerprint: {dev_id} utilized for the first time by {target}",
                        confidence=0.85,
                        correlated_events=corr
                    )

    # 6. Phishing URL Detection
    # Detect phishing urls using features instead of scenario name
    for ev in sec_events:
        # Assuming event_type == 'phishing_url' or target containing 'http' implies a URL check is needed
        if ev.event_type == "phishing_url" or (ev.target and ev.target.startswith("http")):
            is_phishing, confidence, features, eval_explanation, triggered_rules = evaluate_phishing_url(ev.target)
            if is_phishing:
                explanation = f"Suspicious phishing URL telemetry identified: deceptive domain ({ev.target}). " + eval_explanation
                
                corr = [{"event_id": ev.id, "type": "SecurityEvent", "timestamp": ev.timestamp.isoformat(), "reason": "Phishing URL accessed"}]
                _add_detection(
                    "phishing_url_detected",
                    explanation,
                    confidence=confidence,
                    correlated_events=corr
                )
                # Once we detect it for the session, break
                break

    # 7. Anomalous Login Time
    # Per-user profiles take precedence; any other user with a login_attempt
    # between 00:00 and 06:59 is flagged using the default off-hours window.
    USER_PROFILES = {
        "marketing_lead": {"normal_window_start": 9, "normal_window_end": 18},
    }
    DEFAULT_NORMAL_START = 7
    DEFAULT_NORMAL_END = 22  # 10pm
    for ev in sec_events:
        if ev.event_type != "login_attempt":
            continue
        profile = USER_PROFILES.get(ev.target, {"normal_window_start": DEFAULT_NORMAL_START, "normal_window_end": DEFAULT_NORMAL_END})
        hour = _normalize_dt(ev.timestamp).hour
        start = profile["normal_window_start"]
        end = profile["normal_window_end"]
        if hour < start or hour > end:
            deviation = start - hour if hour < start else hour - end
            corr = [{"event_id": ev.id, "type": "SecurityEvent", "timestamp": ev.timestamp.isoformat(), "reason": f"Login attempt at {hour}:00 UTC"}]
            _add_detection(
                "anomalous_login_time_detected",
                f"Anomalous login time: {ev.target or 'unknown'} authenticated at {hour}:00, which is {deviation} hours outside their normal working window ({start}:00 - {end}:00)",
                confidence=0.80,
                correlated_events=corr
            )

    # 8. Multiple Failed Logins (distinct rule for multiple_failed_logins scenario)
    # Triggered when multiple failed authentication events occur in the multiple_failed_logins scenario.
    is_mfl = any(getattr(e, "scenario", "") == "multiple_failed_logins" for e in sec_events)
    if is_mfl:
        for target in set(e.target for e in sec_events if e.target):
            target_events = [e for e in sec_events if e.target == target]
            failed_evs = [e for e in target_events if "failed" in e.event_type.lower()]
            if len(failed_evs) >= 3:
                src = failed_evs[0].source if failed_evs else "unknown"
                corr = [{
                    "event_id": e.id,
                    "type": "SecurityEvent",
                    "timestamp": e.timestamp.isoformat(),
                    "reason": f"Failed login attempt #{i+1}"
                } for i, e in enumerate(failed_evs)]
                _add_detection(
                    "multiple_failed_logins_detected",
                    f"Multiple failed login threshold exceeded: {len(failed_evs)} consecutive failures from {src} targeting {target}",
                    confidence=0.88,
                    correlated_events=corr
                )

    # 9. Combined Multi-Signal: if both anomalous time AND new device detections fired
    # This is implicitly handled by multi-signal bonus in risk engine; no new rule needed.

    return new_detections


def evaluate_rules(session_id: int, db: Session) -> List[Detection]:
    """
    Evaluates rule-based detections against Suricata events and SecurityEvent telemetry.
    Dispatches rules based on the scenario's category, configuration, and security events.
    Ensures detections are not duplicated if already triggered for the session.

    Args:
        session_id: The ID of the session to evaluate.
        db: Active SQLAlchemy Session.

    Returns:
        List of newly created Detection rows.
    """
    session = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not session:
        return []

    scenario = session.scenario
    if not scenario and session.scenario_id:
        scenario = db.query(Scenario).filter(Scenario.id == session.scenario_id).first()

    # Parse scenario configuration
    config = {}
    if scenario and scenario.config_json:
        try:
            config = json.loads(scenario.config_json)
        except json.JSONDecodeError:
            config = {}

    # Query existing detection labels to prevent duplicates
    existing_detections = db.query(Detection).filter(Detection.session_id == session_id).all()
    existing_labels: Set[str] = {d.label for d in existing_detections}

    new_detections: List[Detection] = []

    # 1. Evaluate Network IDS Suricata Rules
    if scenario and scenario.category == ScenarioCategory.PORT_SCAN:
        detection = _evaluate_port_scan(session_id, config, db, existing_labels)
        if detection:
            new_detections.append(detection)
    else:
        # Also check for port scan events if Suricata events exist
        detection = _evaluate_port_scan(session_id, config, db, existing_labels)
        if detection:
            new_detections.append(detection)

    # 2. Evaluate Host/Auth/Security Event Telemetry
    sec_detections = _evaluate_security_events(session_id, db, existing_labels)
    new_detections.extend(sec_detections)

    return new_detections
