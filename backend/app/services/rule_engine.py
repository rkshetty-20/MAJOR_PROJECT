import json
import logging
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
)
from app.services.phishing_detector import evaluate_phishing_url
from app.services.correlation_engine import run_correlation, normalize_detection

logger = logging.getLogger(__name__)


def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371.0  # Earth radius in kilometers
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


# ---------------------------------------------------------------------------
# Behavioral rule thresholds (research-paper reported configuration).
#
# These are the ONLY tunables for the behavioural engine. They are exposed as
# data so the values a detection was produced under can be persisted with the
# evidence and reproduced later. A scenario's ``config_json.behavioral_rule``
# block may override them explicitly; nothing is altered implicitly.
# ---------------------------------------------------------------------------
BEHAVIORAL_DEFAULTS: Dict[str, float] = {
    "failed_login_burst": 3,            # failures that establish a brute-force pattern
    "sustained_failures": 4,            # failures with no success => sustained attack
    # Repeated-failed-login rule fires on the behaviour (a burst of invalid
    # credentials), not on the dataset label. 5 matches the documented velocity
    # threshold carried in the generated telemetry payload.
    "repeated_failures": 5,
    "repeated_failures_window_seconds": 300.0,
    "credential_stuffing_accounts": 3,  # distinct accounts targeted from one source
    "credential_stuffing_window_seconds": 300.0,
    "impossible_travel_speed_kmh": 900.0,
    "port_scan_threshold_ports": 15,
    "port_scan_window_seconds": 10,
    "normal_window_start": 7,           # default working-hour window (UTC hour)
    "normal_window_end": 22,
    # Per-account working-hour profiles that override the default window.
    # Declared as configuration (not inline logic) so the reported values are
    # visible, auditable and overridable from a scenario's config block.
    "user_profiles": {
        "marketing_lead": {"normal_window_start": 9, "normal_window_end": 18},
    },
}

# Legacy override keys used by the seeded scenario catalogue in
# ``app/routers/scenarios.py`` map onto the canonical registry names above, so an
# existing scenario config can tune a threshold without renaming anything.
_BEHAVIORAL_KEY_ALIASES: Dict[str, str] = {
    "threshold_ports": "port_scan_threshold_ports",
    "window_seconds": "port_scan_window_seconds",
}

# Event types that carry authentication *attempt* semantics for the rules below.
FAILED_EVENT_MARKER = "failed"
SUCCESS_EVENT_MARKER = "success"
AUTH_ATTEMPT_TYPES = {
    "login_attempt", "successful_login", "suspicious_login",
}
BASELINE_LOGIN_TYPES = {"known_device_login", "baseline_login"}


def _rule_config(scenario_config: Optional[Dict]) -> Dict[str, float]:
    """Merge a scenario's explicit overrides over the reported defaults.

    Only keys that already exist in :data:`BEHAVIORAL_DEFAULTS` (possibly reached
    through :data:`_BEHAVIORAL_KEY_ALIASES`) are honoured, and ``None`` values are
    ignored. Unknown keys are reported in the returned mapping under
    ``_unrecognized_overrides`` instead of silently changing behaviour, so the
    thresholds behind every detection stay auditable.
    """
    merged = {k: (dict(v) if isinstance(v, dict) else v)
              for k, v in BEHAVIORAL_DEFAULTS.items()}
    override = (scenario_config or {}).get("behavioral_rule", {}) or {}

    normalized: Dict[str, object] = {}
    for key, value in override.items():
        if key in ("name", "description"):
            continue
        normalized[_BEHAVIORAL_KEY_ALIASES.get(key, key)] = value

    unrecognized = sorted(
        key for key in normalized
        if key not in BEHAVIORAL_DEFAULTS
    )
    for key in merged:
        value = normalized.get(key)
        if value is not None:
            merged[key] = value
    if unrecognized:
        merged["_unrecognized_overrides"] = unrecognized
    return merged


def _is_failure(event_type: Optional[str]) -> bool:
    return FAILED_EVENT_MARKER in (event_type or "").lower()


def _is_success(event_type: Optional[str]) -> bool:
    et = (event_type or "").lower()
    return SUCCESS_EVENT_MARKER in et


def _establishes_baseline(event_type: Optional[str]) -> bool:
    """An authentication that contributes to an account's known-good profile.

    Explicitly independent of ``detection_status``/``scenario``: familiarity is
    earned by observed successful/known-device authentications only.
    """
    et = (event_type or "").lower()
    return et in BASELINE_LOGIN_TYPES or _is_success(et)



def _normalize_dt(dt: Optional[datetime]) -> datetime:
    """Normalize a timestamp to a timezone-aware UTC datetime.

    ``None`` is tolerated and mapped to the epoch so partially populated legacy
    telemetry sorts first instead of raising inside an ordering key. Absent
    timestamps therefore never contribute to a velocity or window calculation.
    """
    if dt is None:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
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
    Groups events by src_ip and slides a window of port_scan_window_seconds.
    If distinct dest_port count >= port_scan_threshold_ports, a Detection row is
    produced. The thresholds used are taken from the resolved rule configuration
    and persisted alongside the evidence, so the verdict is reproducible.
    """
    rule_label = "port_scan_detected"
    if rule_label in existing_labels:
        return None

    cfg = _rule_config(config)
    threshold_ports = int(cfg["port_scan_threshold_ports"])
    window_seconds = float(cfg["port_scan_window_seconds"])

    events = (
        db.query(SuricataEvent)
        .filter(
            SuricataEvent.session_id == session_id,
            SuricataEvent.dest_port.isnot(None),
        )
        .order_by(SuricataEvent.timestamp.asc(), SuricataEvent.id.asc())
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
                
                features_json = json.dumps({
                    "correlated_events": correlated,
                    "rule_config": cfg,
                    "duplicate_events_collapsed": 0,
                })

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
                    logger.error("Failed to correlate port scan detection: %s", e)

                return detection

    return None


def _evaluate_security_events(
    session_id: int,
    db: Session,
    existing_labels: Set[str],
    config: Optional[Dict] = None,
) -> List[Detection]:
    """
    Evaluates the behavioural rule set against SecurityEvent telemetry.

    Input discipline (paper section on behavioural detection):
      * Decisions are taken ONLY from event_type, source, target, device,
        location, payload coordinates and timestamps. The stored ground-truth
        columns ``scenario`` and ``detection_status`` are generator metadata and
        are never read here, so a scenario label cannot leak into a verdict.
      * Events are ordered by (timestamp, id) so out-of-order ingestion cannot
        change the outcome.
      * Byte-identical repetitions of one observation are collapsed to a single
        event (at-least-once delivery). Counting a re-delivered row twice would
        inflate every velocity threshold below.
      * Every detection records the thresholds it was evaluated under plus the
        evidence ids, so the verdict can be reproduced from stored evidence.
    """
    cfg = _rule_config(config)

    sec_events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.session_id == session_id)
        .order_by(SecurityEvent.timestamp.asc(), SecurityEvent.id.asc())
        .all()
    )

    if not sec_events:
        return []

    # Stable, explicitly sorted event stream shared by all rules below.
    sec_events = sorted(sec_events, key=lambda e: (_normalize_dt(e.timestamp), e.id))

    # Collapse exactly-repeated observations before any counting happens.
    seen: Set[tuple] = set()
    unique_events: List[SecurityEvent] = []
    duplicates_collapsed = 0
    for ev in sec_events:
        key = (
            ev.event_type, _normalize_dt(ev.timestamp), ev.source, ev.target,
            ev.device, ev.location, ev.payload_json,
        )
        if key in seen:
            duplicates_collapsed += 1
            continue
        seen.add(key)
        unique_events.append(ev)
    sec_events = unique_events

    new_detections: List[Detection] = []

    def _add_detection(label: str, explanation: str, confidence: float = 1.0, correlated_events: List[Dict] = None):
        if label in existing_labels:
            return
        payload = {
            "correlated_events": correlated_events or [],
            "rule_config": cfg,
            "duplicate_events_collapsed": duplicates_collapsed,
        }
        det = Detection(
            session_id=session_id,
            source=DetectionSource.RULE,
            label=label,
            confidence=confidence,
            explanation=explanation,
            features=json.dumps(payload),
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
            logger.error("Failed to correlate security event detection: %s", e)

    # 1. Brute Force Login & Sustained Attack
    # Detected by grouping events by target and looking for multiple failed logins
    targets = set(e.target for e in sec_events if e.target)
    for target in sorted(targets):
        target_events = [e for e in sec_events if e.target == target]
        failed = 0
        src = None
        compromised = False
        for ev in target_events:
            if _is_failure(ev.event_type):
                failed += 1
                if not src:
                    src = ev.source
            elif _is_success(ev.event_type) and failed >= cfg["failed_login_burst"]:
                # Correlate failure burst and success
                corr = [
                    {"event_id": e.id, "type": "SecurityEvent",
                     "timestamp": e.timestamp.isoformat(), "reason": "Failed login attempt"}
                    for e in target_events[:target_events.index(ev)] if _is_failure(e.event_type)
                ]
                corr.append({"event_id": ev.id, "type": "SecurityEvent", "timestamp": ev.timestamp.isoformat(), "reason": "Successful login after brute force"})

                _add_detection(
                    "brute_force_detected",
                    f"High-velocity authentication failure burst: {failed} failed login attempts from {src} targeting {target}, followed by a successful login",
                    confidence=0.95,
                    correlated_events=corr
                )
                compromised = True
                break

        if failed >= cfg["sustained_failures"] and not compromised:
            corr = [{"event_id": e.id, "type": "SecurityEvent", "timestamp": e.timestamp.isoformat(), "reason": "Sustained failed login attempt"} for e in target_events if _is_failure(e.event_type)]
            _add_detection(
                "sustained_attack_no_compromise",
                f"Sustained authentication failures: {failed} failed login attempts from {src} targeting {target} with no successful login",
                confidence=0.85,
                correlated_events=corr
            )

    # 2. Credential Stuffing
    # Detected by grouping events by source and looking for rapid attempts across multiple distinct target accounts.
    auth_events = [e for e in sec_events if _is_failure(e.event_type) or e.event_type == "login_attempt"]
    sources = sorted({e.source for e in auth_events if e.source})
    stuff_window = float(cfg["credential_stuffing_window_seconds"])
    for src in sources:
        src_events = [e for e in auth_events if e.source == src]
        if len(src_events) < int(cfg["credential_stuffing_accounts"]):
            continue

        for i in range(len(src_events)):
            start_time = _normalize_dt(src_events[i].timestamp)
            window_events = []
            for j in range(i, len(src_events)):
                if (_normalize_dt(src_events[j].timestamp) - start_time).total_seconds() <= stuff_window:
                    window_events.append(src_events[j])
                else:
                    break

            unique_targets = {e.target for e in window_events if e.target}
            if (len(window_events) >= cfg["credential_stuffing_accounts"]
                    and len(unique_targets) >= cfg["credential_stuffing_accounts"]):
                corr = [{"event_id": e.id, "type": "SecurityEvent", "timestamp": e.timestamp.isoformat(), "reason": f"Attempt against account {e.target}"} for e in window_events]
                _add_detection(
                    "credential_stuffing_detected",
                    f"Credential stuffing detected: {src} attempted authentication against {len(unique_targets)} distinct accounts within {int(stuff_window)} seconds",
                    confidence=0.96,
                    correlated_events=corr
                )
                break  # Already generated for this source

    # 3. Suspicious Login / Account Takeover
    # Detected when an authentication event deviates from the established baseline
    # in BOTH location and device. The baseline is built from prior successful /
    # known-good authentications observed in the telemetry itself.
    for target in sorted({e.target for e in sec_events if e.target}):
        target_events = [e for e in sec_events if e.target == target]
        known_devices = set()
        known_locations = set()

        for ev in target_events:
            try:
                payload = json.loads(ev.payload_json or "{}")
                dev_id = payload.get("device_id") or ev.device
            except Exception:
                dev_id = ev.device

            loc = ev.location

            # 1) Evaluate the current authentication against the history
            #    established by STRICTLY EARLIER logins for this account.
            if (
                known_locations
                and known_devices
                and ev.event_type in AUTH_ATTEMPT_TYPES
                and loc and loc not in known_locations
                and dev_id and dev_id not in known_devices
            ):
                baseline_events = [e for e in target_events if _establishes_baseline(e.event_type)]
                corr = [{"event_id": ev.id, "type": "SecurityEvent", "timestamp": ev.timestamp.isoformat(), "reason": "Suspicious deviating login"}]
                if baseline_events:
                    corr.append({"event_id": baseline_events[-1].id, "type": "SecurityEvent", "timestamp": baseline_events[-1].timestamp.isoformat(), "reason": "Prior baseline event for comparison", "is_hypothesis": True})

                _add_detection(
                    "suspicious_login_detected",
                    f"Suspicious login detected for {target}: authentication from {loc} using previously unseen device {dev_id}",
                    confidence=0.90,
                    correlated_events=corr
                )

            # 2) Then fold this event into the known-good history. Baseline
            #    establishment is derived purely from observed authentication
            #    telemetry - no generator ground-truth marker is read.
            if _establishes_baseline(ev.event_type):
                if dev_id:
                    known_devices.add(dev_id)
                if loc:
                    known_locations.add(loc)

    # 4. Impossible Travel
    for target in sorted({e.target for e in sec_events if e.target}):
        target_events = [e for e in sec_events if e.target == target and e.event_type == "login_attempt"]
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
                    if speed_kmh > cfg["impossible_travel_speed_kmh"]:
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
    for target in sorted({e.target for e in sec_events if e.target}):
        target_events = [e for e in sec_events if e.target == target]
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
    # Per-account working-hour profiles take precedence; accounts with no profile
    # are judged against the default window. Profiles come from scenario config
    # (``behavioral_rule.user_profiles``) merged over the reported defaults.
    default_profile = {
        "normal_window_start": int(cfg.get("normal_window_start", 7)),
        "normal_window_end": int(cfg.get("normal_window_end", 22)),
    }
    user_profiles = dict(cfg.get("user_profiles", {}) or {})
    for ev in sec_events:
        if ev.event_type != "login_attempt":
            continue
        profile = user_profiles.get(ev.target, default_profile)
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

    # 8. Multiple Failed Logins
    # Triggered purely from telemetry: a bounded window containing at least
    # `repeated_failures` failed authentications from one source to one account.
    # The generator's `scenario` label is deliberately NOT consulted, so this
    # rule fires on the behaviour rather than on the dataset's name.
    mfl_window = float(cfg["repeated_failures_window_seconds"])
    mfl_count = int(cfg["repeated_failures"])
    pairs = {(e.source, e.target) for e in sec_events if e.source and e.target and _is_failure(e.event_type)}
    for pair in sorted(pairs):
        pair_fails = [e for e in sec_events
                      if (e.source, e.target) == pair and _is_failure(e.event_type)]
        if len(pair_fails) < mfl_count:
            continue
        for i in range(len(pair_fails)):
            start_time = _normalize_dt(pair_fails[i].timestamp)
            window_events = []
            for j in range(i, len(pair_fails)):
                if (_normalize_dt(pair_fails[j].timestamp) - start_time).total_seconds() <= mfl_window:
                    window_events.append(pair_fails[j])
                else:
                    break
            if len(window_events) >= mfl_count:
                span = (_normalize_dt(window_events[-1].timestamp) - start_time).total_seconds()
                corr = [{
                    "event_id": e.id,
                    "type": "SecurityEvent",
                    "timestamp": e.timestamp.isoformat(),
                    "reason": f"Failed login attempt #{k + 1}"
                } for k, e in enumerate(window_events)]
                _add_detection(
                    "multiple_failed_logins_detected",
                    f"Multiple failed login threshold exceeded: {len(window_events)} failed attempts from {pair[0]} targeting {pair[1]} within {span:.0f}s (threshold {mfl_count} in {mfl_window:.0f}s)",
                    confidence=0.88,
                    correlated_events=corr
                )
                break

    # 9. Combined Multi-Signal: no dedicated rule by design - corroboration
    # across distinct labels is expressed by the multi-signal term of the
    # risk-fusion engine (see risk_engine.compute_risk_score).

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

    # 1. Network/port-scan rule. Evaluated from Suricata evidence alone - the
    #    scenario category is never used to decide whether the behaviour is
    #    present, only whether the telemetry exists to be examined.
    detection = _evaluate_port_scan(session_id, config, db, existing_labels)
    if detection:
        new_detections.append(detection)

    # 2. Evaluate Host/Auth/Security Event Telemetry
    sec_detections = _evaluate_security_events(session_id, db, existing_labels, config)
    new_detections.extend(sec_detections)

    return new_detections
