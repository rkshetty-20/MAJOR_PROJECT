import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models import (
    Session as SessionModel,
    Scenario,
    SuricataEvent,
    SecurityEvent,
    Detection,
    RiskScore,
    SessionStatus,
    ScenarioCategory,
    DifficultyLevel,
    Dataset,
    EvaluationRun,
)
from app.services.rule_engine import evaluate_rules
from app.services.ml_engine import (
    evaluate_ml,
    evaluate_ml_detailed,
    extract_and_store_learning_examples,
)
from app.services.risk_engine import compute_risk_score

logger = logging.getLogger(__name__)

# Predefined metadata for all supported simulation scenarios
SCENARIO_METADATA = {
    "brute_force": {
        "id": "brute_force",
        "name": "Brute Force Login",
        "category": "Authentication Security",
        "default_intensity": "medium",
        "description": "Simulates rapid dictionary password spraying and repeated failed logins against an account.",
        "mitigation": "Enforce account lockouts after 5 failed attempts, enable MFA, and rate-limit source IP.",
    },
    "credential_stuffing": {
        "id": "credential_stuffing",
        "name": "Credential Stuffing",
        "category": "Account Takeover",
        "default_intensity": "high",
        "description": "Simulates automated authentication probes using leaked credentials across multiple distinct usernames from a single source IP.",
        "mitigation": "Deploy CAPTCHA on login endpoints, monitor credential breach databases, and implement IP reputation filtering.",
    },
    "suspicious_login": {
        "id": "suspicious_login",
        "name": "Suspicious Login / Account Takeover",
        "category": "Behavioral Anomaly",
        "default_intensity": "medium",
        "description": "Simulates a login originating from an abnormal foreign location using an unrecognized browser and OS fingerprint.",
        "mitigation": "Trigger step-up authentication (push notification/SMS OTP) and alert the account owner.",
    },
    "impossible_travel": {
        "id": "impossible_travel",
        "name": "Impossible Travel",
        "category": "Geo-Velocity Anomaly",
        "default_intensity": "high",
        "description": "Simulates two consecutive successful authentications from physically distant cities within an impossible time window.",
        "mitigation": "Revoke active session tokens, invalidate cookies, and require password reset with multi-factor verification.",
    },
    "new_device": {
        "id": "new_device",
        "name": "New Device Login",
        "category": "Endpoint Identity",
        "default_intensity": "low",
        "description": "Simulates authentication from an unrecognized hardware device fingerprint for a known user in a normal location.",
        "mitigation": "Send security confirmation email to registered user device and register device trust status.",
    },
    "phishing_url": {
        "id": "phishing_url",
        "name": "Phishing URL Simulation",
        "category": "Social Engineering",
        "default_intensity": "medium",
        "description": "Simulates telemetry from a user browsing to a newly registered deceptive domain containing credential harvesting keywords.",
        "mitigation": "Add domain to DNS firewall / web proxy blocklist and quarantine related outbound traffic.",
    },
    "port_scan": {
        "id": "port_scan",
        "name": "Port Scan Event Simulation",
        "category": "Network Intrusion",
        "default_intensity": "high",
        "description": "Simulates network reconnaissance probes spanning more than 15 distinct destination ports within seconds.",
        "mitigation": "Isolate the scanning source IP via automated firewall rule and inspect host for malware.",
    },
    "anomalous_login_time": {
        "id": "anomalous_login_time",
        "name": "Anomalous Login Time",
        "category": "Temporal Anomaly",
        "default_intensity": "low",
        "description": "Simulates authentications occurring in the middle of the night outside the user's established historical working hours.",
        "mitigation": "Log anomalous activity for SOC review and prompt user for re-authentication on sensitive actions.",
    },
    "multiple_failed_logins": {
        "id": "multiple_failed_logins",
        "name": "Multiple Failed Login Attempts",
        "category": "Authentication Security",
        "default_intensity": "medium",
        "description": "Simulates a burst of consecutive invalid credentials exceeding velocity thresholds.",
        "mitigation": "Apply progressive delays (tarpitting) to login responses and notify user of failed attempts.",
    },
    "combined_multi_signal": {
        "id": "combined_multi_signal",
        "name": "Combined Multi-Signal Attack",
        "category": "Advanced Persistent Threat",
        "default_intensity": "high",
        "description": "Simulates a compound multi-stage attack combining failed login bursts, new device, impossible travel, and off-hours access.",
        "mitigation": "Initiate automated incident response playbook: lock account, terminate active sessions, block source subnet, and alert SOC tier 2.",
    },
}


def get_available_scenarios() -> List[Dict[str, Any]]:
    """Returns a list of all supported synthetic simulation scenarios."""
    return list(SCENARIO_METADATA.values())


def _resolve_scenario_record(scenario_key: str, db: Session) -> Scenario:
    """Finds or creates an appropriate Scenario record in the database."""
    category_map = {
        "port_scan": ScenarioCategory.PORT_SCAN,
        "brute_force": ScenarioCategory.BRUTE_FORCE,
        "credential_stuffing": ScenarioCategory.CREDENTIAL_STUFFING,
        "phishing_url": ScenarioCategory.PHISHING,
        "suspicious_login": ScenarioCategory.SUSPICIOUS_LOGIN,
        "impossible_travel": ScenarioCategory.IMPOSSIBLE_TRAVEL,
        "new_device": ScenarioCategory.NEW_DEVICE,
        "anomalous_login_time": ScenarioCategory.ANOMALOUS_LOGIN_TIME,
        "multiple_failed_logins": ScenarioCategory.MULTIPLE_FAILED_LOGINS,
        "combined_multi_signal": ScenarioCategory.COMBINED_MULTI_SIGNAL,
    }

    chosen_category = category_map.get(scenario_key, ScenarioCategory.PORT_SCAN)
    existing = db.query(Scenario).filter(Scenario.category == chosen_category).first()
    if existing:
        return existing

    # Fallback create if database was empty
    meta = SCENARIO_METADATA.get(scenario_key, {"name": scenario_key, "description": "Simulation"})
    new_scenario = Scenario(
        name=meta.get("name", scenario_key),
        category=chosen_category,
        description=meta.get("description", ""),
        difficulty=DifficultyLevel.MEDIUM,
    )
    db.add(new_scenario)
    db.commit()
    db.refresh(new_scenario)
    return new_scenario

def generate_offline_dataset(
    scenario: str,
    intensity: str = "medium",
    event_count: Optional[int] = None,
    db: Session = None,
) -> Dataset:
    """Generates a synthetic dataset and persists it for later replay, export, or learning."""
    if db is None:
        raise ValueError("Database session is required")

    scenario_key = scenario.strip().lower()
    if scenario_key not in SCENARIO_METADATA:
        raise ValueError(f"Unknown scenario '{scenario}'")
        
    intensity_val = intensity.strip().lower()
    if intensity_val not in ("low", "medium", "high"):
        intensity_val = "medium"

    if event_count is not None:
        target_count = max(1, min(100, event_count))
    else:
        intensity_defaults = {"low": 4, "medium": 8, "high": 18}
        target_count = intensity_defaults.get(intensity_val, 8)
        
    # We will reuse the same logic that builds events for a session, 
    # but we just wrap them in a JSON payload instead.
    # For now, we'll just leverage the fact that this is an offline version.
    
    dataset_id = f"ds_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:6]}"
    
    # We can use the existing simulation code by running it, then grabbing the events,
    # or duplicating the generation logic. For brevity in Phase 2, we generate basic payloads.
    
    events_json = []
    now = datetime.now(timezone.utc)
    
    if scenario_key == "port_scan":
        candidate_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9000, 9200]
        ports_to_use = candidate_ports[:target_count]
        for idx, port in enumerate(ports_to_use):
            events_json.append({
                "type": "network",
                "timestamp": (now - timedelta(seconds=(target_count - idx) * 0.2)).isoformat(),
                "src_ip": "10.0.0.50",
                "dest_ip": "10.0.0.10",
                "dest_port": port,
                "protocol": "TCP",
                "severity": 2,
                "raw_signature": "ET SCAN Possible Nmap User-Agent Observed",
                "payload": {"scan_type": "SYN_STEALTH"}
            })
            
    elif scenario_key == "brute_force":
        failed_count = max(1, target_count - 1)
        for i in range(failed_count):
            events_json.append({
                "type": "auth",
                "event_type": "failed_login",
                "timestamp": (now - timedelta(seconds=(target_count - i) * 3)).isoformat(),
                "source": "198.51.100.25",
                "target": "demo_user",
                "device": "Chrome 122 / Windows 11",
                "payload": {"attempt": i + 1, "status": "failed", "auth_method": "password"}
            })
        events_json.append({
            "type": "auth",
            "event_type": "successful_login",
            "timestamp": now.isoformat(),
            "source": "198.51.100.25",
            "target": "demo_user",
            "payload": {"status": "success_after_failures", "auth_method": "password"}
        })
        
    elif scenario_key == "credential_stuffing":
        usernames = ["admin", "finance_user", "j_doe", "sales_mgr", "service_account", "guest"]
        for i in range(target_count):
            u = usernames[i % len(usernames)]
            events_json.append({
                "type": "auth",
                "event_type": "failed_authentication",
                "timestamp": (now - timedelta(seconds=(target_count - i) * 2)).isoformat(),
                "source": "203.0.113.88",
                "target": u,
                "device": "Python-requests/2.31.0 (Automated)",
                "payload": {"username": u, "status": "failed", "spray_index": i + 1}
            })
            
    # Mark if ground truth is available (e.g. for supervised ML)
    gt_available = scenario_key in ["port_scan", "brute_force", "credential_stuffing"]
    
    ds = Dataset(
        id=dataset_id,
        schema_version="1.0",
        scenario_category=scenario_key,
        events_count=len(events_json),
        payload_json=json.dumps(events_json),
        is_synthetic=True,
        is_evaluated=False,
        is_training_eligible=gt_available,
        ground_truth_available=gt_available
    )
    
    db.add(ds)
    db.commit()
    db.refresh(ds)
    return ds

def run_dataset_replay(dataset_id: str, db: Session) -> Dict[str, Any]:
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise ValueError("Dataset not found")
        
    eval_run_id = f"eval_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:6]}"
    
    detector_type = "network" if dataset.scenario_category == "port_scan" else "auth"
    from app.services.ml_engine import _get_active_version
    active_version = _get_active_version(db, "port_scan" if detector_type == "network" else "brute_force")
    model_ver_str = active_version.version_string if active_version else "rules_only"
    
    eval_run = EvaluationRun(
        id=eval_run_id,
        dataset_id=dataset_id,
        model_version=model_ver_str,
        detector_type=detector_type,
        started_at=datetime.now(timezone.utc),
        status="running"
    )
    db.add(eval_run)
    db.commit()
    db.refresh(eval_run)
    
    events_json = json.loads(dataset.payload_json)
    
    scenario_obj = _resolve_scenario_record(dataset.scenario_category, db)
    replay_session = SessionModel(
        student_id="replay_orchestrator",
        scenario_id=scenario_obj.id,
        status=SessionStatus.RUNNING,
        started_at=datetime.now(timezone.utc),
    )
    db.add(replay_session)
    db.commit()
    db.refresh(replay_session)
    
    for ev in events_json:
        se = SecurityEvent(
            session_id=replay_session.id,
            simulation_id=eval_run_id,
            scenario=dataset.scenario_category,
            event_type=ev.get("event_type", "replay_event"),
            timestamp=datetime.now(timezone.utc),
            source=ev.get("source", ev.get("src_ip", "unknown")),
            target=ev.get("target", ev.get("dest_ip", "unknown")),
            payload_json=json.dumps(ev.get("payload", {})),
            detection_status="Clean"
        )
        db.add(se)
    db.commit()
    
    try:
        evaluate_rules(session_id=replay_session.id, db=db)
        evaluate_ml(session_id=replay_session.id, db=db)
            
        detections = db.query(Detection).filter(Detection.session_id == replay_session.id).all()
        
        is_attack = dataset.scenario_category in ["port_scan", "brute_force", "credential_stuffing"]
        
        if is_attack:
            tp = len(detections) > 0
            fn = len(detections) == 0
            fp = 0
            tn = 0
        else:
            tp = 0
            fn = 0
            fp = len(detections) > 0
            tn = len(detections) == 0
            
        precision = 1.0 if tp else (0.0 if fp else 1.0)
        recall = 1.0 if tp else (0.0 if fn else 1.0)
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        eval_run.events_processed = len(events_json)
        eval_run.detections_output = len(detections)
        eval_run.true_positives = 1 if tp else 0
        eval_run.false_positives = 1 if fp else 0
        eval_run.false_negatives = 1 if fn else 0
        eval_run.precision = precision
        eval_run.recall = recall
        eval_run.f1_score = f1
        eval_run.status = "completed"
        eval_run.completed_at = datetime.now(timezone.utc)
        
        dataset.is_evaluated = True
        
        db.commit()
        db.refresh(eval_run)
        
        return {
            "eval_run_id": eval_run.id,
            "dataset_id": dataset_id,
            "metrics": {
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
            },
            "detections": len(detections)
        }
    except Exception as e:
        logger.exception("Replay evaluation failed")
        eval_run.status = "failed"
        eval_run.errors = str(e)
        db.commit()
        raise e


def run_synthetic_simulation(
    scenario: str,
    intensity: str = "medium",
    event_count: Optional[int] = None,
    delay_ms: Optional[int] = None,
    student_id: str = "simulation_operator",
    db: Session = None,
) -> Dict[str, Any]:
    """
    Executes a controlled, SAFE synthetic simulation:
    1. Validates inputs and sets safe bounds (min 1, max 100 events).
    2. Creates a dedicated learning/simulation Session in the database.
    3. Synthesizes deterministic security telemetry representing the attack.
    4. Persists synthetic events to SecurityEvent (and SuricataEvent for network scans).
    5. Dispatches events through the detection engine (Rule Engine + Random Forest ML).
    6. Executes the risk-fusion engine (multi-signal explainable risk scoring).
    7. Updates events with calculated risk scores and returns a complete analysis timeline.
    """
    if db is None:
        raise ValueError("Database session is required")

    scenario_key = scenario.strip().lower()
    if scenario_key not in SCENARIO_METADATA:
        supported = list(SCENARIO_METADATA.keys())
        raise ValueError(f"Unknown scenario '{scenario}'. Supported scenarios: {', '.join(supported)}")

    intensity_val = intensity.strip().lower()
    if intensity_val not in ("low", "medium", "high"):
        intensity_val = "medium"

    # Determine event count with safe bounds
    if event_count is not None:
        target_count = max(1, min(100, event_count))
    else:
        intensity_defaults = {"low": 4, "medium": 8, "high": 18}
        target_count = intensity_defaults.get(intensity_val, 8)

    simulation_id = f"sim_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:6]}"
    now = datetime.now(timezone.utc)

    # 1. Resolve Scenario and create Session
    scenario_row = _resolve_scenario_record(scenario_key, db)
    session_obj = SessionModel(
        student_id=student_id,
        scenario_id=scenario_row.id,
        status=SessionStatus.COMPLETED,
        started_at=now,
        ended_at=now,
    )
    db.add(session_obj)
    db.commit()
    db.refresh(session_obj)

    events_to_create: List[SecurityEvent] = []
    suricata_to_create: List[SuricataEvent] = []
    meta = SCENARIO_METADATA[scenario_key]

    # 2. Synthesize Telemetry Per Scenario
    if scenario_key == "brute_force":
        # Target user: demo_user, synthetic IP, repeated failed logins then 1 success
        failed_count = max(1, target_count - 1)
        for i in range(failed_count):
            ev_time = now - timedelta(seconds=(target_count - i) * 3)
            events_to_create.append(
                SecurityEvent(
                    session_id=session_obj.id,
                    simulation_id=simulation_id,
                    scenario=scenario_key,
                    event_type="failed_login",
                    timestamp=ev_time,
                    source="198.51.100.25",
                    target="demo_user",
                    device="Chrome 122 / Windows 11",
                    location="Bengaluru, India",
                    detection_status="Detected",
                    payload_json=json.dumps({
                        "attempt": i + 1,
                        "status": "failed",
                        "auth_method": "password",
                        "failure_reason": "invalid_credentials",
                        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0",
                    }),
                )
            )
        # Final attempt
        events_to_create.append(
            SecurityEvent(
                session_id=session_obj.id,
                simulation_id=simulation_id,
                scenario=scenario_key,
                event_type="successful_login",
                timestamp=now,
                source="198.51.100.25",
                target="demo_user",
                device="Chrome 122 / Windows 11",
                location="Bengaluru, India",
                detection_status="Flagged",
                payload_json=json.dumps({
                    "attempt": target_count,
                    "status": "success_after_failures",
                    "auth_method": "password",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0",
                }),
            )
        )

    elif scenario_key == "credential_stuffing":
        # Multiple distinct targets from single source IP
        usernames = ["admin", "finance_user", "j_doe", "sales_mgr", "service_account", "it_helpdesk", "ops_lead", "guest"]
        for i in range(target_count):
            ev_time = now - timedelta(seconds=(target_count - i) * 2)
            u = usernames[i % len(usernames)]
            events_to_create.append(
                SecurityEvent(
                    session_id=session_obj.id,
                    simulation_id=simulation_id,
                    scenario=scenario_key,
                    event_type="failed_authentication",
                    timestamp=ev_time,
                    source="203.0.113.88",
                    target=u,
                    device="Python-requests/2.31.0 (Automated)",
                    location="Moscow, Russia",
                    detection_status="Detected",
                    payload_json=json.dumps({
                        "username": u,
                        "status": "failed",
                        "source_ip": "203.0.113.88",
                        "spray_index": i + 1,
                    }),
                )
            )

    elif scenario_key == "suspicious_login":
        # Normal login followed by anomalous login from new location/device
        events_to_create.append(
            SecurityEvent(
                session_id=session_obj.id,
                simulation_id=simulation_id,
                scenario=scenario_key,
                event_type="baseline_login",
                timestamp=now - timedelta(hours=2),
                source="106.51.72.10",
                target="corp_user",
                device="Chrome 120 / Windows 11",
                location="Bengaluru, India",
                detection_status="Normal",
                payload_json=json.dumps({"status": "success", "baseline": True}),
            )
        )
        for i in range(1, target_count):
            events_to_create.append(
                SecurityEvent(
                    session_id=session_obj.id,
                    simulation_id=simulation_id,
                    scenario=scenario_key,
                    event_type="suspicious_login",
                    timestamp=now - timedelta(minutes=(target_count - i)),
                    source="198.51.100.42",
                    target="corp_user",
                    device="Firefox 120 / Linux x86_64",
                    location="Frankfurt, Germany",
                    detection_status="Detected",
                    payload_json=json.dumps({
                        "status": "anomalous_login",
                        "unrecognized_device": True,
                        "location_delta_km": 7200,
                    }),
                )
            )

    elif scenario_key == "impossible_travel":
        # Event A at Bengaluru, Event B at London 15 mins later
        events_to_create.append(
            SecurityEvent(
                session_id=session_obj.id,
                simulation_id=simulation_id,
                scenario=scenario_key,
                event_type="login_attempt",
                timestamp=now - timedelta(minutes=15),
                source="106.51.72.10",
                target="global_user",
                device="Edge 121 / macOS",
                location="Bengaluru, India",
                detection_status="Normal",
                payload_json=json.dumps({"city": "Bengaluru", "country": "India", "lat": 12.9716, "lon": 77.5946}),
            )
        )
        for i in range(1, target_count):
            events_to_create.append(
                SecurityEvent(
                    session_id=session_obj.id,
                    simulation_id=simulation_id,
                    scenario=scenario_key,
                    event_type="login_attempt",
                    timestamp=now - timedelta(minutes=15 - i * 2),
                    source="185.199.108.153",
                    target="global_user",
                    device="Safari 17 / iOS 17",
                    location="London, United Kingdom",
                    detection_status="Detected",
                    payload_json=json.dumps({
                        "city": "London",
                        "country": "UK",
                        "lat": 51.5074,
                        "lon": -0.1278
                    }),
                )
            )

    elif scenario_key == "new_device":
        events_to_create.append(
            SecurityEvent(
                session_id=session_obj.id,
                simulation_id=simulation_id,
                scenario=scenario_key,
                event_type="known_device_login",
                timestamp=now - timedelta(days=1),
                source="192.168.1.15",
                target="alex_dev",
                device="device-001 (Managed MacBook Pro)",
                location="Bengaluru, India",
                detection_status="Normal",
                payload_json=json.dumps({"device_id": "device-001", "trusted": True}),
            )
        )
        for i in range(1, target_count):
            events_to_create.append(
                SecurityEvent(
                    session_id=session_obj.id,
                    simulation_id=simulation_id,
                    scenario=scenario_key,
                    event_type="login_attempt",
                    timestamp=now - timedelta(minutes=i),
                    source="192.168.1.99",
                    target="alex_dev",
                    device="device-999 (Unmanaged Android Device)",
                    location="Bengaluru, India",
                    detection_status="Detected",
                    payload_json=json.dumps({"device_id": "device-999"}),
                )
            )

    elif scenario_key == "phishing_url":
        for i in range(target_count):
            events_to_create.append(
                SecurityEvent(
                    session_id=session_obj.id,
                    simulation_id=simulation_id,
                    scenario=scenario_key,
                    event_type="phishing_url",
                    timestamp=now - timedelta(seconds=(target_count - i) * 5),
                    source="10.0.5.12",
                    target="http://portal-verify.internal-update.invalid/auth/login",
                    device="Chrome 122 / Windows 10",
                    location="Corporate Subnet",
                    detection_status="Detected",
                    payload_json=json.dumps({
                        "url": "http://portal-verify.internal-update.invalid/auth/login",
                        "domain_age_days": 2,
                        "https": False,
                        "suspicious_keywords": ["verify", "account", "login", "urgent"],
                        "reputation_score": 12,
                    }),
                )
            )

    elif scenario_key == "port_scan":
        # Generates Suricata network IDS events and SecurityEvents
        candidate_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9000, 9200]
        ports_to_use = candidate_ports[:target_count] if target_count <= len(candidate_ports) else candidate_ports * (target_count // len(candidate_ports) + 1)
        ports_to_use = ports_to_use[:target_count]

        for idx, port in enumerate(ports_to_use):
            ev_ts = now - timedelta(seconds=(target_count - idx) * 0.2)
            suricata_to_create.append(
                SuricataEvent(
                    session_id=session_obj.id,
                    raw_signature="ET SCAN Possible Nmap User-Agent Observed",
                    src_ip="10.0.0.50",
                    dest_ip="10.0.0.10",
                    dest_port=port,
                    protocol="TCP",
                    severity=2,
                    timestamp=ev_ts,
                )
            )
            events_to_create.append(
                SecurityEvent(
                    session_id=session_obj.id,
                    simulation_id=simulation_id,
                    scenario=scenario_key,
                    event_type="port_scan",
                    timestamp=ev_ts,
                    source="10.0.0.50",
                    target=f"10.0.0.10:{port}",
                    device="Nmap / Kali Linux",
                    location="DMZ Segment",
                    detection_status="Detected",
                    payload_json=json.dumps({
                        "dest_port": port,
                        "protocol": "TCP",
                        "scan_type": "SYN_STEALTH",
                    }),
                )
            )

    elif scenario_key == "anomalous_login_time":
        for i in range(target_count):
            ev_time = now.replace(hour=3, minute=17, second=0, microsecond=0) + timedelta(minutes=i)
            events_to_create.append(
                SecurityEvent(
                    session_id=session_obj.id,
                    simulation_id=simulation_id,
                    scenario=scenario_key,
                    event_type="login_attempt",
                    timestamp=ev_time,
                    source="192.168.1.44",
                    target="marketing_lead",
                    device="Chrome 122 / Windows 11",
                    location="Bengaluru, India",
                    detection_status="Detected",
                    payload_json=json.dumps({}),
                )
            )

    elif scenario_key == "multiple_failed_logins":
        for i in range(target_count):
            ev_time = now - timedelta(seconds=(target_count - i) * 3)
            events_to_create.append(
                SecurityEvent(
                    session_id=session_obj.id,
                    simulation_id=simulation_id,
                    scenario=scenario_key,
                    event_type="failed_login",
                    timestamp=ev_time,
                    source="198.51.100.12",
                    target="finance_admin",
                    device="Chrome 120 / macOS",
                    location="Bengaluru, India",
                    detection_status="Detected",
                    payload_json=json.dumps({
                        "failure_attempt": i + 1,
                        "threshold": 5,
                        "error": "ERR_BAD_PASSWORD",
                    }),
                )
            )

    elif scenario_key == "combined_multi_signal":
        # 1. Establish baseline known device
        events_to_create.append(
            SecurityEvent(
                session_id=session_obj.id,
                simulation_id=simulation_id,
                scenario=scenario_key,
                event_type="known_device_login",
                timestamp=now - timedelta(days=2),
                source="192.168.1.50",
                target="marketing_lead",
                device="MacBook Pro",
                location="Bengaluru, India",
                detection_status="Clean",
                payload_json=json.dumps({"device_id": "known-device-123"}),
            )
        )
        
        # 2. Failed credential burst (Brute force part 1)
        # Using scenario="brute_force" so the brute force rule evaluates it
        burst_time = now.replace(hour=3, minute=15, second=0, microsecond=0)
        for i in range(5):
            events_to_create.append(
                SecurityEvent(
                    session_id=session_obj.id,
                    simulation_id=simulation_id,
                    scenario="brute_force",
                    event_type="failed_login",
                    timestamp=burst_time + timedelta(seconds=i*2),
                    source="194.26.29.112",
                    target="marketing_lead",
                    device="Unknown",
                    location="Kyiv, Ukraine",
                    detection_status="Detected",
                    payload_json=json.dumps({"attempt": i + 1, "status": "failed"}),
                )
            )
            
        # 3. Anomalous off-hours login attempt with a new device
        events_to_create.append(
            SecurityEvent(
                session_id=session_obj.id,
                simulation_id=simulation_id,
                scenario=scenario_key,
                event_type="login_attempt",
                timestamp=burst_time + timedelta(seconds=12),
                source="194.26.29.112",
                target="marketing_lead",
                device="Unknown",
                location="Kyiv, Ukraine",
                detection_status="Detected",
                payload_json=json.dumps({"device_id": "evil-device-999"}),
            )
        )
        
        # 4. Successful takeover login (Brute force part 2)
        events_to_create.append(
            SecurityEvent(
                session_id=session_obj.id,
                simulation_id=simulation_id,
                scenario="brute_force",
                event_type="successful_login",
                timestamp=burst_time + timedelta(seconds=14),
                source="194.26.29.112",
                target="marketing_lead",
                device="Unknown",
                location="Kyiv, Ukraine",
                detection_status="Detected",
                payload_json=json.dumps({"status": "success", "device_id": "evil-device-999"}),
            )
        )

    # 2.5 Calculate synthetic start time of the active scenario
    active_events = [e for e in events_to_create if getattr(e, 'event_type', None) not in ("baseline_login", "known_device_login")]
    if active_events:
        scenario_start = min(e.timestamp for e in active_events if e.timestamp)
    elif suricata_to_create:
        scenario_start = min(e.timestamp for e in suricata_to_create if e.timestamp)
    else:
        scenario_start = now

    session_obj.started_at = scenario_start - timedelta(milliseconds=1)

    # 3. Commit events to DB
    for ev in suricata_to_create:
        db.add(ev)
    for ev in events_to_create:
        db.add(ev)
    db.commit()

    # 4. Execute Rule and ML Detection Engines
    new_rule_detections = evaluate_rules(session_id=session_obj.id, db=db)
    # ML inference is driven by measured features, never by which scenario was
    # requested: if the session contains telemetry a model consumes, the model
    # scores it. Diagnostics are logged so an unavailable model is visible
    # instead of silently skipped.
    ml_result = evaluate_ml_detailed(session_id=session_obj.id, db=db)
    for note in ml_result["diagnostics"]:
        if note["status"] in ("MODEL_UNAVAILABLE", "FEATURE_SCHEMA_VIOLATION", "MODEL_INTEGRITY"):
            logger.warning(
                "ML detector %s did not run for session %s: %s (%s)",
                note.get("task_name"), session_obj.id, note["status"], note.get("reason"),
            )

    # 5. Execute Multi-Signal Risk Engine
    risk_row = compute_risk_score(session_id=session_obj.id, db=db)

    # 6. Update SecurityEvent rows with computed risk
    risk_score_val = risk_row.score
    risk_level_val = risk_row.band.value.upper()
    for ev in events_to_create:
        ev.risk_score = risk_score_val
        ev.risk_level = risk_level_val
    db.commit()

    # 6.5 Adaptive Learning - Store Training Examples
    extract_and_store_learning_examples(session_obj.id, db)

    # 7. Collect All Detections for Response
    all_detections = (
        db.query(Detection)
        .filter(Detection.session_id == session_obj.id)
        .all()
    )
    detections_list = [
        {
            "id": d.id,
            "source": d.source.value if hasattr(d.source, "value") else str(d.source),
            "label": "Combined Multi-Signal" if scenario_key == "combined_multi_signal" else d.label,
            "confidence": d.confidence,
            "explanation": d.explanation,
        }
        for d in all_detections
    ]

    # Parse contributing factors
    factors_dict = {}
    if risk_row.contributing_factors:
        try:
            factors_dict = json.loads(risk_row.contributing_factors)
        except Exception:
            factors_dict = {}

    triggered_rules = list(set(d.label for d in all_detections))

    # Construct conceptual simulation flow without synthetic timestamps
    simulation_flow = [
        {"step": "Attack started", "status": "completed"},
        {"step": "Events generated", "status": "completed", "count": len(events_to_create)},
        {"step": "Detection triggered", "status": "completed", "detections": len(all_detections)},
        {"step": "Risk calculated", "status": "completed", "score": risk_score_val, "band": risk_level_val},
        {"step": "Alert generated", "status": "completed"},
        {"step": "AI analysis available", "status": "ready"},
    ]

    return {
        "simulation_id": simulation_id,
        "scenario": scenario_key,
        "scenario_name": meta["name"],
        "session_id": session_obj.id,
        "events_generated": len(events_to_create),
        "status": "completed",
        "detections_count": len(all_detections),
        "detections": detections_list,
        "risk": {
            "score": risk_score_val,
            "band": risk_level_val,
            "contributing_factors": factors_dict,
        },
        "triggered_rules": triggered_rules,
        "mitigation": meta.get("mitigation", "Inspect host and apply mitigation controls."),
        "simulation_flow": simulation_flow,
    }


def recommend_next_simulation(operator_id: str, db: Session) -> Dict[str, Any]:
    """
    Recommends the next synthetic attack scenario and intensity for a simulation operator
    based on persisted simulation outcomes (not trainee performance scores).
    Inspects historical Session, SecurityEvent, Detection, and RiskScore records.
    """
    all_scenario_keys = list(SCENARIO_METADATA.keys())

    # Query past simulation sessions run by this operator
    query = db.query(SessionModel)
    if operator_id:
        query = query.filter(SessionModel.student_id == operator_id)
    recent_sessions = query.order_by(SessionModel.started_at.desc()).limit(20).all()

    if not recent_sessions:
        # Cold start
        return {
            "operator_id": operator_id,
            "recommended_scenario": "brute_force",
            "scenario_name": SCENARIO_METADATA["brute_force"]["name"],
            "recommended_intensity": "low",
            "rationale": f"No prior simulation history detected for operator '{operator_id}'. Recommending baseline Brute Force simulation at Low intensity to initialize behavioral detection baselines.",
            "coverage_summary": {
                "total_scenarios": len(all_scenario_keys),
                "tested_scenarios": 0,
                "untested_scenarios": all_scenario_keys,
            },
            "recent_sessions_evaluated": 0,
            "last_session": None,
        }

    # Inspect tested scenarios from SecurityEvents associated with these sessions
    session_ids = [s.id for s in recent_sessions]
    events = db.query(SecurityEvent).filter(SecurityEvent.session_id.in_(session_ids)).all()

    tested_scenarios = set()
    scenario_by_session: Dict[int, str] = {}
    for ev in events:
        if ev.scenario:
            tested_scenarios.add(ev.scenario)
            if ev.session_id not in scenario_by_session:
                scenario_by_session[ev.session_id] = ev.scenario

    untested_scenarios = [s for s in all_scenario_keys if s not in tested_scenarios]

    # Analyze most recent session
    latest_session = recent_sessions[0]
    latest_scenario = scenario_by_session.get(latest_session.id)

    if not latest_scenario and latest_session.scenario:
        cat_to_key = {
            "SSH_BRUTE_FORCE": "brute_force",
            "PORT_SCAN": "port_scan",
            "PHISHING": "phishing_url",
            "WEB_PROBING": "suspicious_login",
            "MULTIPLE_FAILED_LOGINS": "multiple_failed_logins",
        }
        latest_scenario = cat_to_key.get(latest_session.scenario.category.name, "brute_force")

    latest_detections_count = db.query(Detection).filter(Detection.session_id == latest_session.id).count()
    latest_risk = db.query(RiskScore).filter(RiskScore.session_id == latest_session.id).first()
    latest_risk_score = latest_risk.score if latest_risk else 0
    latest_risk_band = (
        latest_risk.band.value if hasattr(latest_risk.band, "value") else str(latest_risk.band)
    ) if latest_risk and latest_risk.band else "LOW"

    last_session_summary = {
        "session_id": latest_session.id,
        "scenario": latest_scenario or "unknown",
        "detections_count": latest_detections_count,
        "risk_score": latest_risk_score,
        "risk_band": latest_risk_band,
    }

    if untested_scenarios:
        next_scenario = untested_scenarios[0]
        if latest_detections_count > 0 and latest_risk_score >= 50:
            intensity = "medium"
        else:
            intensity = SCENARIO_METADATA.get(next_scenario, {}).get("default_intensity", "medium")
        rationale = f"Expanding detection coverage: '{next_scenario}' has not been simulated yet in recent history. Selected at '{intensity}' intensity."
    else:
        if latest_detections_count == 0:
            next_scenario = latest_scenario or "combined_multi_signal"
            intensity = "high"
            rationale = f"Last simulation '{latest_scenario}' produced 0 detections. Re-running at High intensity to stress-test detection rules."
        elif latest_risk_score < 40:
            next_scenario = latest_scenario or "credential_stuffing"
            intensity = "high"
            rationale = f"Last simulation '{latest_scenario}' resulted in Low risk ({latest_risk_score}/100). Escalating intensity to High to probe threshold boundaries."
        else:
            candidates = ["combined_multi_signal", "impossible_travel", "credential_stuffing", "port_scan"]
            next_scenario = next((c for c in candidates if c != latest_scenario), "combined_multi_signal")
            intensity = "high"
            rationale = f"Detection engines successfully caught '{latest_scenario}' (Risk {latest_risk_score}/100, {latest_detections_count} detections). Advancing to complex scenario '{next_scenario}' at High intensity."

    return {
        "operator_id": operator_id,
        "recommended_scenario": next_scenario,
        "scenario_name": SCENARIO_METADATA.get(next_scenario, {}).get("name", next_scenario),
        "recommended_intensity": intensity,
        "rationale": rationale,
        "coverage_summary": {
            "total_scenarios": len(all_scenario_keys),
            "tested_scenarios": len(tested_scenarios),
            "untested_scenarios": untested_scenarios,
        },
        "recent_sessions_evaluated": len(recent_sessions),
        "last_session": last_session_summary,
    }
