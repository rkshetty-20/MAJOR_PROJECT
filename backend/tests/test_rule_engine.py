import sys
import os
from datetime import datetime, timezone, timedelta
import json

# Ensure backend directory is in python sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import SessionLocal
from app.models import (
    Scenario,
    Session as SessionModel,
    SuricataEvent,
    SecurityEvent,
    Detection,
    ScenarioCategory,
    SessionStatus,
)
from app.routers.scenarios import seed_scenarios
from app.services.rule_engine import (
    BEHAVIORAL_DEFAULTS,
    PAPER_RULE_LABELS,
    RULE_CONFIDENCES,
    _establishes_baseline,
    _is_failure,
    _is_success,
    _normalize_dt,
    _rule_config,
    evaluate_rules,
)
from app.database import Base, engine

Base.metadata.create_all(bind=engine)


def test_rule_engine_confidences_match_paper_table():
    """Paper Table I: nine behavioural rules, each with a reported confidence.

    The nine values are declared once in ``RULE_CONFIDENCES`` and read by every
    rule, so this test is the machine-checkable link between the paper's table and
    the verdicts the engine emits. The tenth label is the documented extension.
    """
    assert len(PAPER_RULE_LABELS) == 9, "the paper specifies nine behavioural rules"

    expected = {
        "brute_force_detected": 0.95,
        "credential_stuffing_detected": 0.96,
        "suspicious_login_detected": 0.90,
        "impossible_travel_detected": 0.98,
        "new_device_detected": 0.85,
        "phishing_url_detected": None,   # paper column reads "(dynamic)"
        "port_scan_detected": 1.00,
        "anomalous_login_time_detected": 0.80,
        "sustained_attack_no_compromise": 0.85,
    }
    assert set(PAPER_RULE_LABELS) == set(expected)
    for label, confidence in expected.items():
        assert RULE_CONFIDENCES[label] == confidence, label

    # The velocity-scoped repeat rule is an implementation extension: it is
    # declared, it is NOT one of the paper's nine, and its 0.88 is engineering data.
    assert "multiple_failed_logins_detected" not in PAPER_RULE_LABELS
    assert RULE_CONFIDENCES["multiple_failed_logins_detected"] == 0.88


def test_port_scan_rule_detection():
    db = SessionLocal()
    session_id = None
    try:
        # 1. Ensure scenario seeds are present
        seed_scenarios(db)
        port_scan_scenario = (
            db.query(Scenario)
            .filter(Scenario.category == ScenarioCategory.PORT_SCAN)
            .first()
        )
        assert port_scan_scenario is not None, "port_scan scenario not found in database"

        # 2. Create an isolated test session
        session = SessionModel(
            student_id="test_student_rules_eval",
            scenario_id=port_scan_scenario.id,
            status=SessionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        session_id = session.id

        # 3. Insert synthetic SuricataEvent rows: 20 distinct ports from one IP within 5 seconds
        base_time = datetime.now(timezone.utc)
        attacker_ip = "192.168.56.10"
        target_ip = "192.168.56.20"

        synthetic_events = []
        for port in range(1, 21):  # 20 distinct destination ports
            # Spread across 5 seconds (5 / 20 = 0.25s increments)
            ev_time = base_time + timedelta(seconds=(port * 0.25))
            event = SuricataEvent(
                session_id=session_id,
                raw_signature="ET SCAN Potential Port Scan",
                src_ip=attacker_ip,
                dest_ip=target_ip,
                dest_port=port,
                protocol="TCP",
                severity=2,
                timestamp=ev_time,
            )
            synthetic_events.append(event)

        db.add_all(synthetic_events)
        db.commit()

        # 4. First evaluation: should trigger exactly one Detection
        detections = evaluate_rules(session_id=session_id, db=db)
        assert len(detections) == 1, f"Expected 1 detection, got {len(detections)}"

        detection = detections[0]
        assert detection.label == "port_scan_detected"
        assert detection.confidence == 1.0
        assert detection.session_id == session_id
        assert "Detected 20 distinct ports" in detection.explanation
        assert attacker_ip in detection.explanation

        print("First evaluation passed: 1 detection created with label 'port_scan_detected'")
        print(f"Explanation: {detection.explanation}")

        # 5. Second evaluation: should NOT duplicate the detection
        second_eval = evaluate_rules(session_id=session_id, db=db)
        assert len(second_eval) == 0, f"Expected 0 duplicate detections, got {len(second_eval)}"
        print("Second evaluation passed: 0 duplicate detections created")

        # 6. Verify total detections in database for this session is exactly 1
        total_detections = (
            db.query(Detection)
            .filter(Detection.session_id == session_id)
            .count()
        )
        assert total_detections == 1, f"Expected total 1 detection in DB, got {total_detections}"
        print("Database persistence verified: exactly 1 detection recorded for session.")

    finally:
        # Explicit clean up of session and all related rows
        if session_id is not None:
            db.query(Detection).filter(Detection.session_id == session_id).delete()
            db.query(SuricataEvent).filter(SuricataEvent.session_id == session_id).delete()
            db.query(SessionModel).filter(SessionModel.id == session_id).delete()
            db.commit()
        db.close()


def test_new_device_rule_detection():
    db = SessionLocal()
    session_id = None
    try:
        seed_scenarios(db)
        scenario = db.query(Scenario).first()
        
        session = SessionModel(
            student_id="test_new_device",
            scenario_id=scenario.id,
            status=SessionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        session_id = session.id

        # Pinned clock: these events are ``login_attempt`` rows, so behavioural
        # rule 7 (anomalous login time, default window 07-22 UTC) also reads their
        # hour. Using the wall clock made this test fail for every run outside
        # 07:00-22:00 UTC - a pre-existing flakiness unrelated to stage E.
        now = datetime(2026, 5, 4, 12, 0, tzinfo=timezone.utc)  # inside 07-22
        
        # Baseline known device login
        ev1 = SecurityEvent(
            session_id=session_id,
            scenario="new_device",
            event_type="known_device_login",
            timestamp=now - timedelta(days=1),
            source="127.0.0.1",
            target="alex_dev",
            payload_json=json.dumps({"device_id": "device-001"}),
        )
        # Login with a different new device
        ev2 = SecurityEvent(
            session_id=session_id,
            scenario="new_device",
            event_type="login_attempt",
            timestamp=now,
            source="127.0.0.1",
            target="alex_dev",
            payload_json=json.dumps({"device_id": "device-999"}),
        )
        
        db.add_all([ev1, ev2])
        db.commit()
        
        # Evaluate and confirm detection triggers due to calculation
        detections = evaluate_rules(session_id=session_id, db=db)
        assert len(detections) == 1, f"Expected 1 detection for new device, got {len(detections)}"
        assert detections[0].label == "new_device_detected"
        assert "device-999" in detections[0].explanation
        
        # Clean up events
        db.query(Detection).filter(Detection.session_id == session_id).delete()
        db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).delete()
        db.commit()
        db.expunge_all()
        
        # Test inverse: Same device twice should NOT trigger detection
        ev1 = SecurityEvent(
            session_id=session_id,
            scenario="new_device",
            event_type="known_device_login",
            timestamp=now - timedelta(days=1),
            source="127.0.0.1",
            target="alex_dev",
            payload_json=json.dumps({"device_id": "device-001"}),
        )
        ev2 = SecurityEvent(
            session_id=session_id,
            scenario="new_device",
            event_type="login_attempt",
            timestamp=now,
            source="127.0.0.1",
            target="alex_dev",
            payload_json=json.dumps({"device_id": "device-001"}),
        )
        db.add_all([ev1, ev2])
        db.commit()
        
        detections2 = evaluate_rules(session_id=session_id, db=db)
        assert len(detections2) == 0, f"Expected 0 detections for same device, got {len(detections2)}"

        print("New device rule evaluation passed.")
    except Exception as e:
        db.rollback()
        raise e
    finally:
        if session_id is not None:
            db.query(Detection).filter(Detection.session_id == session_id).delete()
            db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).delete()
            db.query(SessionModel).filter(SessionModel.id == session_id).delete()
            db.commit()
        db.close()


def test_anomalous_login_time_rule_detection():
    db = SessionLocal()
    session_id = None
    try:
        seed_scenarios(db)
        scenario = db.query(Scenario).first()
        
        session = SessionModel(
            student_id="test_anomalous_time",
            scenario_id=scenario.id,
            status=SessionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        session_id = session.id

        now = datetime.now(timezone.utc)
        
        # Anomalous time: 03:17 (Profile is 09:00 - 18:00)
        ev_time_bad = now.replace(hour=3, minute=17, second=0, microsecond=0)
        ev_bad = SecurityEvent(
            session_id=session_id,
            scenario="anomalous_login_time",
            event_type="login_attempt",
            timestamp=ev_time_bad,
            source="127.0.0.1",
            target="marketing_lead",
            payload_json=json.dumps({}),
        )
        
        db.add(ev_bad)
        db.commit()
        
        # Evaluate and confirm calculation calculates deviation
        detections = evaluate_rules(session_id=session_id, db=db)
        assert len(detections) == 1, f"Expected 1 detection for anomalous time, got {len(detections)}"
        assert detections[0].label == "anomalous_login_time_detected"
        assert "6 hours outside" in detections[0].explanation # 9 - 3 = 6
        
        # Clean up and test inverse: 14:00 should NOT trigger detection
        db.query(Detection).filter(Detection.session_id == session_id).delete()
        db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).delete()
        db.commit()
        db.expunge_all()
        
        ev_time_good = now.replace(hour=14, minute=0, second=0, microsecond=0)
        ev_good = SecurityEvent(
            session_id=session_id,
            scenario="anomalous_login_time",
            event_type="login_attempt",
            timestamp=ev_time_good,
            source="127.0.0.1",
            target="marketing_lead",
            payload_json=json.dumps({}),
        )
        
        db.add(ev_good)
        db.commit()
        
        detections2 = evaluate_rules(session_id=session_id, db=db)
        assert len(detections2) == 0, f"Expected 0 detections for normal time, got {len(detections2)}"

        print("Anomalous login time rule evaluation passed.")
    except Exception as e:
        db.rollback()
        raise e
    finally:
        if session_id is not None:
            db.query(Detection).filter(Detection.session_id == session_id).delete()
            db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).delete()
            db.query(SessionModel).filter(SessionModel.id == session_id).delete()
            db.commit()
        db.close()

import math

def test_impossible_travel_rule_detection():
    db = SessionLocal()
    session_id = None
    try:
        seed_scenarios(db)
        scenario = db.query(Scenario).first()
        
        session = SessionModel(
            student_id="test_impossible_travel",
            scenario_id=scenario.id,
            status=SessionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        session_id = session.id

        # Pinned clock - see the note in test_new_device_rule_detection. Two of
        # these rows are ``login_attempt`` events, so an unpinned hour outside the
        # default 07-22 window adds a spurious anomalous_login_time detection and
        # breaks the exact-count assertions below.
        now = datetime(2026, 5, 4, 12, 0, tzinfo=timezone.utc)  # inside 07-22
        
        def local_haversine(lat1, lon1, lat2, lon2):
            R = 6371.0
            dlat = math.radians(lat2 - lat1)
            dlon = math.radians(lon2 - lon1)
            a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
            c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
            return R * c
            
        # Case A: Bengaluru to London in 15 mins
        ev1 = SecurityEvent(
            session_id=session_id,
            scenario="impossible_travel",
            event_type="login_attempt",
            timestamp=now - timedelta(minutes=15),
            source="127.0.0.1",
            target="global_user",
            payload_json=json.dumps({"lat": 12.9716, "lon": 77.5946}),
        )
        ev2 = SecurityEvent(
            session_id=session_id,
            scenario="impossible_travel",
            event_type="login_attempt",
            timestamp=now,
            source="127.0.0.1",
            target="global_user",
            payload_json=json.dumps({"lat": 51.5074, "lon": -0.1278}),
        )
        
        db.add_all([ev1, ev2])
        db.commit()
        
        detections = evaluate_rules(session_id=session_id, db=db)
        assert len(detections) == 1, f"Expected 1 detection for impossible travel, got {len(detections)}"
        assert detections[0].label == "impossible_travel_detected"
        
        # Verify the calculation is correct
        expected_dist = local_haversine(12.9716, 77.5946, 51.5074, -0.1278)
        expected_speed = expected_dist / (15.0 / 60.0)
        assert f"Calculated {expected_dist:.0f}km" in detections[0].explanation
        assert f"15min = {expected_speed:.0f}km/h" in detections[0].explanation
        
        # Clean up
        db.query(Detection).filter(Detection.session_id == session_id).delete()
        db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).delete()
        db.commit()
        db.expunge_all()
        
        # Case B: Bengaluru to Chennai (~290km) in 2 hours
        ev1 = SecurityEvent(
            session_id=session_id,
            scenario="impossible_travel",
            event_type="login_attempt",
            timestamp=now - timedelta(hours=2),
            source="127.0.0.1",
            target="global_user",
            payload_json=json.dumps({"lat": 12.9716, "lon": 77.5946}),
        )
        ev2 = SecurityEvent(
            session_id=session_id,
            scenario="impossible_travel",
            event_type="login_attempt",
            timestamp=now,
            source="127.0.0.1",
            target="global_user",
            payload_json=json.dumps({"lat": 13.0827, "lon": 80.2707}), # Chennai
        )
        db.add_all([ev1, ev2])
        db.commit()
        
        detections2 = evaluate_rules(session_id=session_id, db=db)
        assert len(detections2) == 0, f"Expected 0 detections for plausible travel, got {len(detections2)}"
        
        # Clean up
        db.query(Detection).filter(Detection.session_id == session_id).delete()
        db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).delete()
        db.commit()
        db.expunge_all()
        
        # Case C: Same location twice
        ev1 = SecurityEvent(
            session_id=session_id,
            scenario="impossible_travel",
            event_type="login_attempt",
            timestamp=now - timedelta(minutes=5),
            source="127.0.0.1",
            target="global_user",
            payload_json=json.dumps({"lat": 12.9716, "lon": 77.5946}),
        )
        ev2 = SecurityEvent(
            session_id=session_id,
            scenario="impossible_travel",
            event_type="login_attempt",
            timestamp=now,
            source="127.0.0.1",
            target="global_user",
            payload_json=json.dumps({"lat": 12.9716, "lon": 77.5946}),
        )
        db.add_all([ev1, ev2])
        db.commit()
        
        detections3 = evaluate_rules(session_id=session_id, db=db)
        assert len(detections3) == 0, f"Expected 0 detections for zero distance, got {len(detections3)}"

        print("Impossible travel rule evaluation passed.")
    except Exception as e:
        db.rollback()
        raise e
    finally:
        if session_id is not None:
            db.query(Detection).filter(Detection.session_id == session_id).delete()
            db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).delete()
            db.query(SessionModel).filter(SessionModel.id == session_id).delete()
            db.commit()
        db.close()

def test_brute_force_and_sustained_attack_rules():
    db = SessionLocal()
    session_id_1 = None
    session_id_2 = None
    try:
        seed_scenarios(db)
        scenario = db.query(Scenario).first()
        
        # Two sessions for session isolation testing
        session1 = SessionModel(
            student_id="test_bf_1", scenario_id=scenario.id, status=SessionStatus.RUNNING, started_at=datetime.now(timezone.utc)
        )
        session2 = SessionModel(
            student_id="test_bf_2", scenario_id=scenario.id, status=SessionStatus.RUNNING, started_at=datetime.now(timezone.utc)
        )
        db.add_all([session1, session2])
        db.commit()
        db.refresh(session1)
        db.refresh(session2)
        session_id_1 = session1.id
        session_id_2 = session2.id

        now = datetime.now(timezone.utc)
        
        def cleanup():
            db.query(Detection).filter(Detection.session_id.in_([session_id_1, session_id_2])).delete()
            db.query(SecurityEvent).filter(SecurityEvent.session_id.in_([session_id_1, session_id_2])).delete()
            db.commit()
            db.expunge_all()

        # 1. Failures just below threshold (3 failures -> NO detection)
        events = []
        for i in range(3):
            events.append(SecurityEvent(
                session_id=session_id_1, scenario="brute_force", event_type="failed_login",
                timestamp=now - timedelta(seconds=10 - i), source="10.0.0.1", target="userA"
            ))
        db.add_all(events)
        db.commit()
        
        detections = evaluate_rules(session_id_1, db)
        assert len(detections) == 0, f"Expected 0 detections for 3 failures, got {len(detections)}"
        cleanup()

        # 2. Failures exactly at threshold (4 failures -> sustained_attack)
        events = []
        for i in range(4):
            events.append(SecurityEvent(
                session_id=session_id_1, scenario="brute_force", event_type="failed_login",
                timestamp=now - timedelta(seconds=10 - i), source="10.0.0.2", target="userB"
            ))
        db.add_all(events)
        db.commit()
        
        detections = evaluate_rules(session_id_1, db)
        assert len(detections) == 1
        assert detections[0].label == "sustained_attack_no_compromise"
        assert "4 failed login attempts" in detections[0].explanation
        
        # Duplicate suppression test
        detections_dup = evaluate_rules(session_id_1, db)
        assert len(detections_dup) == 0
        cleanup()

        # 3. Failures above threshold (5 failures -> sustained_attack)
        events = []
        for i in range(5):
            events.append(SecurityEvent(
                session_id=session_id_1, scenario="brute_force", event_type="failed_login",
                timestamp=now - timedelta(seconds=10 - i), source="10.0.0.3", target="userC"
            ))
        db.add_all(events)
        db.commit()
        
        detections = evaluate_rules(session_id_1, db)
        labels = {d.label for d in detections}
        # 5 failures now satisfy BOTH the sustained-attack rule and the
        # repeated-failed-login rule from the same evidence. The previous
        # single-label expectation only held because rule 8 was gated on the
        # generator's `scenario` column, i.e. on ground truth leaking into the
        # detector. Corroborating labels are the intended behaviour and are what
        # the risk-fusion multi-signal term is designed to reward.
        assert labels == {"sustained_attack_no_compromise", "multiple_failed_logins_detected"}, labels
        cleanup()

        # 4. Failed attempts (>=3) followed by a successful login -> brute_force
        events = []
        for i in range(3):
            events.append(SecurityEvent(
                session_id=session_id_1, scenario="brute_force", event_type="failed_login",
                timestamp=now - timedelta(seconds=10 - i), source="10.0.0.4", target="userD"
            ))
        events.append(SecurityEvent(
            session_id=session_id_1, scenario="brute_force", event_type="successful_login",
            timestamp=now, source="10.0.0.4", target="userD"
        ))
        db.add_all(events)
        db.commit()
        
        detections = evaluate_rules(session_id_1, db)
        assert len(detections) == 1
        assert detections[0].label == "brute_force_detected"
        cleanup()

        # 5. Session isolation check
        events = []
        for i in range(3):
            events.append(SecurityEvent(
                session_id=session_id_1, scenario="brute_force", event_type="failed_login",
                timestamp=now - timedelta(seconds=10 - i), source="10.0.0.5", target="userE"
            ))
        events.append(SecurityEvent(
            session_id=session_id_2, scenario="brute_force", event_type="failed_login",
            timestamp=now, source="10.0.0.5", target="userE"
        ))
        db.add_all(events)
        db.commit()
        
        assert len(evaluate_rules(session_id_1, db)) == 0
        assert len(evaluate_rules(session_id_2, db)) == 0
        cleanup()

        print("Brute force and sustained attack rules evaluation passed.")
    except Exception as e:
        db.rollback()
        raise e
    finally:
        if session_id_1:
            db.query(Detection).filter(Detection.session_id.in_([session_id_1, session_id_2])).delete()
            db.query(SecurityEvent).filter(SecurityEvent.session_id.in_([session_id_1, session_id_2])).delete()
            db.query(SessionModel).filter(SessionModel.id.in_([session_id_1, session_id_2])).delete()
            db.commit()
        db.close()


def test_combined_multi_signal_detection():
    from app.services.risk_engine import compute_risk_score
    from app.models import RiskBand
    db = SessionLocal()
    session_id = None
    try:
        seed_scenarios(db)
        scenario = db.query(Scenario).first()
        
        session = SessionModel(
            student_id="test_combined_multi_signal",
            scenario_id=scenario.id,
            status=SessionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        session_id = session.id

        now = datetime.now(timezone.utc)
        scenario_key = "combined_multi_signal"
        events_to_create = []

        # 1. Baseline known device
        events_to_create.append(
            SecurityEvent(
                session_id=session_id,
                scenario=scenario_key,
                event_type="known_device_login",
                timestamp=now - timedelta(days=2),
                source="192.168.1.50",
                target="marketing_lead",
                device="MacBook Pro",
                payload_json=json.dumps({"device_id": "known-device-123"}),
            )
        )
        
        # 2. Failed credential burst (brute force)
        burst_time = now.replace(hour=3, minute=15, second=0, microsecond=0)
        for i in range(5):
            events_to_create.append(
                SecurityEvent(
                    session_id=session_id,
                    scenario="brute_force",
                    event_type="failed_login",
                    timestamp=burst_time + timedelta(seconds=i*2),
                    source="194.26.29.112",
                    target="marketing_lead",
                    device="Unknown",
                    payload_json=json.dumps({"attempt": i + 1, "status": "failed"}),
                )
            )
            
        # 3. Anomalous off-hours login attempt with new device
        events_to_create.append(
            SecurityEvent(
                session_id=session_id,
                scenario=scenario_key,
                event_type="login_attempt",
                timestamp=burst_time + timedelta(seconds=12),
                source="194.26.29.112",
                target="marketing_lead",
                device="Unknown",
                payload_json=json.dumps({"device_id": "evil-device-999"}),
            )
        )
        
        # 4. Successful takeover login
        events_to_create.append(
            SecurityEvent(
                session_id=session_id,
                scenario="brute_force",
                event_type="successful_login",
                timestamp=burst_time + timedelta(seconds=14),
                source="194.26.29.112",
                target="marketing_lead",
                device="Unknown",
                payload_json=json.dumps({"status": "success", "device_id": "evil-device-999"}),
            )
        )
        
        db.add_all(events_to_create)
        db.commit()
        
        # Verify the distinct rules evaluate successfully from the raw data
        detections = evaluate_rules(session_id=session_id, db=db)
        labels = {d.label for d in detections}
        assert "brute_force_detected" in labels
        assert "new_device_detected" in labels
        assert "anomalous_login_time_detected" in labels
        # The 5-failure burst in this scenario also legitimately corroborates the
        # repeated-failed-login rule (behaviour-based, no scenario-name gate).
        assert "multiple_failed_logins_detected" in labels
        assert len(detections) == 4, f"Expected 4 detections, got {len(detections)}"
        
        # Compute risk score
        risk_row = compute_risk_score(session_id=session_id, db=db)
        
        # Verify Risk Band
        assert risk_row.band in [RiskBand.HIGH, RiskBand.CRITICAL], f"Risk band is {risk_row.band}, expected HIGH or CRITICAL"
        
        # Verify contributing factors
        factors = json.loads(risk_row.contributing_factors)
        assert factors["multi_signal_bonus"] == 30, f"Expected 30 bonus, got {factors['multi_signal_bonus']}"
        assert set(factors["triggered_rules"]) == {
            "brute_force_detected", "new_device_detected",
            "anomalous_login_time_detected", "multiple_failed_logins_detected",
        }
        
        print("Combined multi signal rule evaluation passed.")
    except Exception as e:
        db.rollback()
        raise e
    finally:
        if session_id is not None:
            from app.models import RiskScore
            db.query(Detection).filter(Detection.session_id == session_id).delete()
            db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).delete()
            db.query(RiskScore).filter(RiskScore.session_id == session_id).delete()
            db.query(SessionModel).filter(SessionModel.id == session_id).delete()
            db.commit()
        db.close()


def test_credential_stuffing_rule_detection():
    db = SessionLocal()
    session_id = None
    try:
        seed_scenarios(db)
        scenario = db.query(Scenario).first()
        
        session = SessionModel(
            student_id="test_credential_stuffing",
            scenario_id=scenario.id,
            status=SessionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        session_id = session.id

        now = datetime.now(timezone.utc)
        
        # Case 1 & 4 (Positive & Anti-Cheat): Multiple accounts, one source, rapid window.
        # Intentionally setting scenario="normal_login" to prove anti-cheat works.
        events = []
        usernames = ["user1", "user2", "user3", "user4", "user5", "user6"]
        for i, u in enumerate(usernames):
            events.append(SecurityEvent(
                session_id=session_id,
                scenario="normal_login",
                event_type="failed_login",
                timestamp=now - timedelta(seconds=10 - i),
                source="10.0.0.10",
                target=u,
                payload_json=json.dumps({"attempt": 1})
            ))
        db.add_all(events)
        db.commit()
        
        detections = evaluate_rules(session_id=session_id, db=db)
        cs_detections = [d for d in detections if d.label == "credential_stuffing_detected"]
        assert len(cs_detections) == 1, f"Expected 1 CS detection, got {len(cs_detections)}"
        
        # Clean up
        db.query(Detection).filter(Detection.session_id == session_id).delete()
        db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).delete()
        db.commit()
        db.expunge_all()

        # Case 2: Negative - Repeated failures against ONE account (Brute force shape)
        events = []
        for i in range(10):
            events.append(SecurityEvent(
                session_id=session_id,
                scenario="normal_login",
                event_type="failed_login",
                timestamp=now - timedelta(seconds=20 - i),
                source="10.0.0.11",
                target="alice",
                payload_json=json.dumps({"attempt": i+1})
            ))
        db.add_all(events)
        db.commit()
        
        detections = evaluate_rules(session_id=session_id, db=db)
        cs_detections = [d for d in detections if d.label == "credential_stuffing_detected"]
        assert len(cs_detections) == 0, f"Expected 0 CS detections for brute force shape, got {len(cs_detections)}"
        
        # Clean up
        db.query(Detection).filter(Detection.session_id == session_id).delete()
        db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).delete()
        db.commit()
        db.expunge_all()

        # Case 3: Negative - Multiple accounts but outside rapid window (1 hour apart)
        events = []
        for i, u in enumerate(usernames):
            events.append(SecurityEvent(
                session_id=session_id,
                scenario="normal_login",
                event_type="failed_login",
                timestamp=now - timedelta(hours=10 - i),
                source="10.0.0.12",
                target=u,
                payload_json=json.dumps({"attempt": 1})
            ))
        db.add_all(events)
        db.commit()
        
        detections = evaluate_rules(session_id=session_id, db=db)
        cs_detections = [d for d in detections if d.label == "credential_stuffing_detected"]
        assert len(cs_detections) == 0, f"Expected 0 CS detections for slow attempts, got {len(cs_detections)}"
        
        print("Credential stuffing rule evaluation passed.")
    except Exception as e:
        db.rollback()
        raise e
    finally:
        if session_id is not None:
            db.query(Detection).filter(Detection.session_id == session_id).delete()
            db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).delete()
            db.query(SessionModel).filter(SessionModel.id == session_id).delete()
            db.commit()
        db.close()


def test_suspicious_login_rule_detection():
    db = SessionLocal()
    session_id = None
    try:
        seed_scenarios(db)
        scenario = db.query(Scenario).first()
        
        session = SessionModel(
            student_id="test_suspicious_login",
            scenario_id=scenario.id,
            status=SessionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        session_id = session.id

        now = datetime.now(timezone.utc)
        
        # Case 1 & 4 (Positive & Anti-Cheat): New device + New location, scenario label removed
        events = [
            SecurityEvent(
                session_id=session_id,
                scenario="normal_login",
                event_type="baseline_login",
                timestamp=now - timedelta(days=1),
                source="1.2.3.4",
                target="userA",
                device="device-1",
                location="Bengaluru",
                detection_status="Normal",
            ),
            SecurityEvent(
                session_id=session_id,
                scenario="normal_login", # Intentionally not suspicious_login
                event_type="successful_login",
                timestamp=now,
                source="5.6.7.8",
                target="userA",
                device="device-999",
                location="London",
            )
        ]
        db.add_all(events)
        db.commit()
        
        detections = evaluate_rules(session_id=session_id, db=db)
        sl_detections = [d for d in detections if d.label == "suspicious_login_detected"]
        assert len(sl_detections) == 1, f"Expected 1 SL detection, got {len(sl_detections)}"
        
        # Clean up
        db.query(Detection).filter(Detection.session_id == session_id).delete()
        db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).delete()
        db.commit()
        db.expunge_all()

        # Case 2: Negative - Known device + known location
        events = [
            SecurityEvent(
                session_id=session_id,
                scenario="normal_login",
                event_type="baseline_login",
                timestamp=now - timedelta(days=1),
                source="1.2.3.4",
                target="userA",
                device="device-1",
                location="Bengaluru",
                detection_status="Normal",
            ),
            SecurityEvent(
                session_id=session_id,
                scenario="normal_login",
                event_type="successful_login",
                timestamp=now,
                source="1.2.3.4",
                target="userA",
                device="device-1",
                location="Bengaluru",
            )
        ]
        db.add_all(events)
        db.commit()
        
        detections = evaluate_rules(session_id=session_id, db=db)
        sl_detections = [d for d in detections if d.label == "suspicious_login_detected"]
        assert len(sl_detections) == 0, f"Expected 0 SL detections, got {len(sl_detections)}"
        
        # Clean up
        db.query(Detection).filter(Detection.session_id == session_id).delete()
        db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).delete()
        db.commit()
        db.expunge_all()

        # Case 3: Negative - Scenario label alone cannot trigger detection
        events = [
            SecurityEvent(
                session_id=session_id,
                scenario="suspicious_login", # Fake out the engine
                event_type="baseline_login",
                timestamp=now - timedelta(days=1),
                source="1.2.3.4",
                target="userA",
                device="device-1",
                location="Bengaluru",
                detection_status="Normal",
            ),
            SecurityEvent(
                session_id=session_id,
                scenario="suspicious_login", # Fake out the engine
                event_type="successful_login",
                timestamp=now,
                source="1.2.3.4",
                target="userA",
                device="device-1",
                location="Bengaluru",
            )
        ]
        db.add_all(events)
        db.commit()
        
        detections = evaluate_rules(session_id=session_id, db=db)
        sl_detections = [d for d in detections if d.label == "suspicious_login_detected"]
        assert len(sl_detections) == 0, f"Expected 0 SL detections, got {len(sl_detections)}"

        print("Suspicious login rule evaluation passed.")
    except Exception as e:
        db.rollback()
        raise e
    finally:
        if session_id is not None:
            db.query(Detection).filter(Detection.session_id == session_id).delete()
            db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).delete()
            db.query(SessionModel).filter(SessionModel.id == session_id).delete()
            db.commit()
        db.close()

def _new_session(db, scenario, student_id):
    sess = SessionModel(
        student_id=student_id,
        scenario_id=scenario.id,
        status=SessionStatus.RUNNING,
        started_at=datetime.now(timezone.utc),
    )
    db.add(sess)
    db.commit()
    db.refresh(sess)
    return sess


def test_multiple_failed_logins_rule_detection():
    """Rule 8 fires on burst behaviour, never on the generator's scenario name."""
    db = SessionLocal()
    session_ids = []
    try:
        seed_scenarios(db)
        scenario = db.query(Scenario).first()
        now = datetime.now(timezone.utc)

        def run(events, offsets, student, src, tgt, spacing=2):
            sess = _new_session(db, scenario, student)
            session_ids.append(sess.id)
            db.add_all([
                SecurityEvent(
                    session_id=sess.id, scenario=events["scenario"],
                    event_type="failed_login",
                    timestamp=now - timedelta(seconds=offsets * spacing),
                    source=src, target=tgt,
                )
                for offsets in range(events["count"])
            ])
            db.commit()
            dets = evaluate_rules(sess.id, db)
            return {d.label for d in dets}

        # 1. Exactly at the documented velocity threshold -> detected
        labels = run({"count": 5, "scenario": "multiple_failed_logins"}, 5, "mfl_at_threshold", "198.51.100.12", "finance_admin")
        assert "multiple_failed_logins_detected" in labels, labels

        # 2. Below threshold -> not detected (sustained also needs 4)
        labels = run({"count": 2, "scenario": "multiple_failed_logins"}, 2, "mfl_below", "198.51.100.13", "finance_admin_b")
        assert "multiple_failed_logins_detected" not in labels, labels

        # 3. ANTI-CHEAT: identical burst but labelled as a benign scenario.
        #    Behaviour must win over the label.
        labels = run({"count": 5, "scenario": "normal_login"}, 5, "mfl_anticheat_disguised", "198.51.100.14", "finance_admin_c")
        assert "multiple_failed_logins_detected" in labels, (
            f"Scenario label must not suppress a real burst, got {labels}"
        )

        # 4. Label alone cannot create a detection (no failure telemetry at all)
        sess = _new_session(db, scenario, "mfl_label_only")
        session_ids.append(sess.id)
        db.add(SecurityEvent(
            session_id=sess.id, scenario="multiple_failed_logins",
            event_type="successful_login", timestamp=now,
            source="198.51.100.99", target="nobody",
        ))
        db.commit()
        assert evaluate_rules(sess.id, db) == [], "ground-truth label alone triggered a detection"

        # 5. Window boundary: 5 failures spread beyond the window -> no MFL
        sess = _new_session(db, scenario, "mfl_outside_window")
        session_ids.append(sess.id)
        db.add_all([
            SecurityEvent(
                session_id=sess.id, scenario="multiple_failed_logins",
                event_type="failed_login",
                timestamp=now - timedelta(seconds=100 * i),
                source="198.51.100.20", target="slow_target",
            )
            for i in range(5)
        ])
        db.commit()
        labels = {d.label for d in evaluate_rules(sess.id, db)}
        assert "multiple_failed_logins_detected" not in labels, (
            f"Spread-out failures must not meet the velocity window, got {labels}"
        )

        # 6. Duplicate ingestion is idempotent
        sess = _new_session(db, scenario, "mfl_duplicate")
        session_ids.append(sess.id)
        rows = [
            SecurityEvent(
                session_id=sess.id, scenario="multiple_failed_logins",
                event_type="failed_login", timestamp=now - timedelta(seconds=2 * i),
                source="198.51.100.30", target="dup_target",
            )
            for i in range(5)
        ]
        db.add_all(rows)
        db.commit()
        first = {d.label for d in evaluate_rules(sess.id, db)}
        second = evaluate_rules(sess.id, db)
        assert "multiple_failed_logins_detected" in first
        assert second == [], f"Re-evaluation must not duplicate detections, got {second}"

        print("Multiple failed logins rule evaluation passed.")
    finally:
        for sid in session_ids:
            db.query(Detection).filter(Detection.session_id == sid).delete()
            db.query(SecurityEvent).filter(SecurityEvent.session_id == sid).delete()
            db.query(SessionModel).filter(SessionModel.id == sid).delete()
        db.commit()
        db.close()


def test_ground_truth_fields_never_reach_behavioural_decisions():
    """Identical behaviour with opposite labels must yield identical verdicts."""
    db = SessionLocal()
    session_ids = []
    try:
        seed_scenarios(db)
        scenario = db.query(Scenario).first()
        # Pinned inside the default 07-22 window: one of the injected rows is a
        # ``login_attempt``, and the verdicts below are compared across sessions,
        # so the hour must not float with the wall clock.
        now = datetime(2026, 5, 4, 12, 0, tzinfo=timezone.utc)

        def deviating_login(label_scenario, label_status):
            sess = _new_session(db, scenario, f"leak_{label_scenario}_{label_status}")
            session_ids.append(sess.id)
            db.add_all([
                SecurityEvent(
                    session_id=sess.id, scenario=label_scenario,
                    event_type="known_device_login", detection_status=label_status,
                    timestamp=now - timedelta(days=1), source="192.0.2.7",
                    target="acct_baseline", device="laptop-known",
                    location="Bengaluru",
                    payload_json=json.dumps({"device_id": "dev-known-1"}),
                ),
                SecurityEvent(
                    session_id=sess.id, scenario=label_scenario,
                    event_type="login_attempt", detection_status=label_status,
                    timestamp=now, source="198.51.100.44",
                    target="acct_baseline", device="laptop-unknown",
                    location="Reykjavik",
                    payload_json=json.dumps({"device_id": "dev-new-77"}),
                ),
            ])
            db.commit()
            return sess.id

        # Same behaviour, contradictory generator labels -> same verdict.
        a = deviating_login("suspicious_login", "Detected")
        b = deviating_login("normal_login", "Clean")
        labels_a = {d.label for d in evaluate_rules(a, db)}
        labels_b = {d.label for d in evaluate_rules(b, db)}
        assert "suspicious_login_detected" in labels_a
        assert labels_a == labels_b, (
            f"Verdict depends on generator metadata: {labels_a} vs {labels_b}"
        )

        # A benign history labelled as an attack must not be detected.
        sess = _new_session(db, scenario, "benign_labelled_as_attack")
        session_ids.append(sess.id)
        db.add_all([
            SecurityEvent(
                session_id=sess.id, scenario="brute_force", detection_status="Detected",
                event_type="known_device_login", timestamp=now - timedelta(hours=2),
                source="192.0.2.9", target="acct_calm", device="ipad",
                location="Bengaluru", payload_json=json.dumps({"device_id": "d1"}),
            ),
            SecurityEvent(
                session_id=sess.id, scenario="phishing_url", detection_status="Detected",
                event_type="successful_login", timestamp=now - timedelta(hours=1),
                source="192.0.2.9", target="acct_calm", device="ipad",
                location="Bengaluru", payload_json=json.dumps({"device_id": "d1"}),
            ),
        ])
        db.commit()
        assert evaluate_rules(sess.id, db) == [], (
            "Attack labels on benign behaviour must not fabricate a detection"
        )
        print("Ground-truth leakage guard passed.")
    finally:
        for sid in session_ids:
            db.query(Detection).filter(Detection.session_id == sid).delete()
            db.query(SecurityEvent).filter(SecurityEvent.session_id == sid).delete()
            db.query(SessionModel).filter(SessionModel.id == sid).delete()
        db.commit()
        db.close()


def test_rule_engine_robustness_edge_cases():
    """Out-of-order arrival, duplicates, missing fields, conflicting signals.

    A fixed clock is used instead of ``datetime.now()`` so the anomalous-login-
    time rule cannot make these assertions depend on the wall clock of the CI
    runner.
    """
    db = SessionLocal()
    session_ids = []
    extra_scenario_ids = []
    try:
        seed_scenarios(db)
        scenario = db.query(Scenario).first()
        now = datetime(2026, 5, 4, 12, 0, tzinfo=timezone.utc)  # inside 07-22

        # 1. Shuffled ingestion order must not change the verdict.
        base = [
            ("failed_login", 0), ("failed_login", 2), ("failed_login", 4),
            ("failed_login", 6), ("failed_login", 8), ("successful_login", 10),
        ]
        results = {}
        for name, order in [("ordered", list(range(len(base)))), ("shuffled", [3, 0, 5, 1, 4, 2])]:
            sess = _new_session(db, scenario, f"order_{name}")
            session_ids.append(sess.id)
            for idx in order:
                et, offset = base[idx]
                db.add(SecurityEvent(
                    session_id=sess.id, scenario="brute_force", event_type=et,
                    timestamp=now + timedelta(seconds=offset),
                    source="198.51.100.50", target="ordering_test",
                ))
            db.commit()
            results[name] = {d.label for d in evaluate_rules(sess.id, db)}
        assert results["ordered"] == results["shuffled"], results
        assert "brute_force_detected" in results["ordered"], results

        # 2. Duplicate rows must not change or multiply the verdict.
        #    Session A holds five distinct failed authentications; session B
        #    holds the same five plus a byte-identical re-delivery of each. A
        #    re-delivered row is one observation, not two, so both must yield the
        #    same verdict and B must report the collapse.
        burst = [dict(event_type="failed_login", timestamp=now + timedelta(seconds=2 * i),
                      source="198.51.100.51", target="dup_order") for i in range(5)]

        sess_a = _new_session(db, scenario, "duplicates_clean")
        session_ids.append(sess_a.id)
        db.add_all([SecurityEvent(session_id=sess_a.id, scenario="brute_force", **kw) for kw in burst])
        db.commit()
        evaluate_rules(sess_a.id, db)
        verdict_a = {(d.label, d.explanation) for d in
                     db.query(Detection).filter(Detection.session_id == sess_a.id).all()}
        assert len(verdict_a) == 2, verdict_a

        sess_b = _new_session(db, scenario, "duplicates_replayed")
        session_ids.append(sess_b.id)
        db.add_all([SecurityEvent(session_id=sess_b.id, scenario="brute_force", **kw) for kw in burst])
        db.add_all([SecurityEvent(session_id=sess_b.id, scenario="brute_force", **kw) for kw in burst])
        db.commit()
        evaluate_rules(sess_b.id, db)
        rows_b = db.query(Detection).filter(Detection.session_id == sess_b.id).all()
        verdict_b = {(d.label, d.explanation) for d in rows_b}
        assert verdict_a == verdict_b, (verdict_a, verdict_b)
        assert len(rows_b) == len({d.label for d in rows_b}), "duplicate Detection rows"
        for d in rows_b:
            assert json.loads(d.features)["duplicate_events_collapsed"] == 5, d.label
        assert evaluate_rules(sess_b.id, db) == [], "re-evaluation must be idempotent"

        # 3. Missing / malformed fields must not crash or invent detections.
        sess = _new_session(db, scenario, "missing_fields")
        session_ids.append(sess.id)
        db.add_all([
            SecurityEvent(session_id=sess.id, scenario="impossible_travel",
                          event_type="login_attempt", timestamp=now,
                          source="", target="", device=None, location=None,
                          payload_json=None, risk_level=None),
            SecurityEvent(session_id=sess.id, scenario="impossible_travel",
                          event_type="login_attempt", timestamp=now + timedelta(seconds=30),
                          source="198.51.100.60", target="geo_test", device="d",
                          location="Nowhere", payload_json="{not json"),
        ])
        db.commit()
        dets = evaluate_rules(sess.id, db)  # must not raise
        assert dets == [], f"Incomplete telemetry invented detections: {[d.label for d in dets]}"

        # Helper guards must tolerate absent values directly.
        assert _is_failure(None) is False and _is_success(None) is False
        assert _establishes_baseline(None) is False
        assert _normalize_dt(None) == datetime(1970, 1, 1, tzinfo=timezone.utc)
        assert _normalize_dt(datetime(2026, 5, 4, 12, 0)) > _normalize_dt(None)
        json.dumps(_rule_config(None))  # resolved config must stay persistable

        # 4. Conflicting signals for one account are all reported, not merged.
        sess = _new_session(db, scenario, "conflicting")
        session_ids.append(sess.id)
        db.add_all([
            SecurityEvent(session_id=sess.id, scenario="new_device", event_type="known_device_login",
                          timestamp=now - timedelta(days=1), source="192.0.2.1", target="conflict_acct",
                          device="old", location="Bengaluru",
                          payload_json=json.dumps({"device_id": "old"})),
            *[SecurityEvent(session_id=sess.id, scenario="new_device", event_type="failed_login",
                            timestamp=now - timedelta(seconds=8 - 2 * i), source="198.51.100.70",
                            target="conflict_acct", device="new", location="London",
                            payload_json=json.dumps({"device_id": "new"}))
              for i in range(5)],
            SecurityEvent(session_id=sess.id, scenario="new_device", event_type="login_attempt",
                          timestamp=now + timedelta(seconds=60), source="198.51.100.70",
                          target="conflict_acct", device="new", location="Bengaluru",
                          payload_json=json.dumps({"device_id": "new", "lat": 12.97, "lon": 77.59})),
            SecurityEvent(session_id=sess.id, scenario="new_device", event_type="login_attempt",
                          timestamp=now + timedelta(seconds=120), source="198.51.100.70",
                          target="conflict_acct", device="new", location="London",
                          payload_json=json.dumps({"device_id": "new", "lat": 51.50, "lon": -0.12})),
        ])
        db.commit()
        labels = {d.label for d in evaluate_rules(sess.id, db)}
        assert labels == {
            "sustained_attack_no_compromise",
            "multiple_failed_logins_detected",
            "impossible_travel_detected",
            "new_device_detected",
            "suspicious_login_detected",
        }, labels

        # 5. Every persisted detection is reproducible: it records the thresholds
        #    it was evaluated under together with the evidence it correlated.
        for d in db.query(Detection).filter(Detection.session_id == sess.id).all():
            parsed = json.loads(d.features)
            assert "rule_config" in parsed and "correlated_events" in parsed, d.label
            assert parsed["duplicate_events_collapsed"] == 0, d.label
            assert parsed["rule_config"]["repeated_failures"] == BEHAVIORAL_DEFAULTS["repeated_failures"]
            assert parsed["correlated_events"], f"{d.label} has no evidence references"
            for ref in parsed["correlated_events"]:
                assert ref["type"] in ("SecurityEvent", "SuricataEvent")
                assert db.get(SecurityEvent, ref["event_id"]) is not None or ref.get("is_hypothesis")

        # 6. Thresholds are explicit and configurable through scenario config.
        #    Lowering the reported repeated-failure threshold to 3 must make the
        #    same 3-failure evidence fire; unknown keys must not alter behaviour.
        custom = Scenario(
            name="Behavioural threshold override probe",
            category=scenario.category,
            difficulty=scenario.difficulty,
            description="Test-only scenario verifying explicit threshold configuration.",
            config_json=json.dumps({"behavioral_rule": {
                "repeated_failures": 3, "not_a_real_threshold": 99, "name": "ignored",
            }}),
        )
        db.add(custom)
        db.commit()
        db.refresh(custom)
        extra_scenario_ids.append(custom.id)

        cfg = _rule_config(json.loads(custom.config_json))
        assert cfg["repeated_failures"] == 3
        assert cfg["_unrecognized_overrides"] == ["not_a_real_threshold"]
        assert "name" not in cfg

        sess = _new_session(db, custom, "override_three_failures")
        session_ids.append(sess.id)
        db.add_all([
            SecurityEvent(session_id=sess.id, scenario="multiple_failed_logins",
                          event_type="failed_login", timestamp=now + timedelta(seconds=2 * i),
                          source="198.51.100.80", target="override_acct")
            for i in range(3)
        ])
        db.commit()
        labels = {d.label for d in evaluate_rules(sess.id, db)}
        assert "multiple_failed_logins_detected" in labels, labels

        # The same evidence under the reported default must NOT fire rule 8.
        sess = _new_session(db, scenario, "default_three_failures")
        session_ids.append(sess.id)
        db.add_all([
            SecurityEvent(session_id=sess.id, scenario="multiple_failed_logins",
                          event_type="failed_login", timestamp=now + timedelta(seconds=2 * i),
                          source="198.51.100.81", target="default_acct")
            for i in range(3)
        ])
        db.commit()
        labels = {d.label for d in evaluate_rules(sess.id, db)}
        assert "multiple_failed_logins_detected" not in labels, labels

        # Defaults must not be mutated by a scenario override (no global leak).
        assert BEHAVIORAL_DEFAULTS["repeated_failures"] == 5
        assert BEHAVIORAL_DEFAULTS["user_profiles"] == {
            "marketing_lead": {"normal_window_start": 9, "normal_window_end": 18}
        }
        print("Rule engine robustness edge cases passed.")
    finally:
        for sid in session_ids:
            db.query(Detection).filter(Detection.session_id == sid).delete()
            db.query(SecurityEvent).filter(SecurityEvent.session_id == sid).delete()
            db.query(SessionModel).filter(SessionModel.id == sid).delete()
        for sc_id in extra_scenario_ids:
            db.query(Scenario).filter(Scenario.id == sc_id).delete()
        db.commit()
        db.close()


if __name__ == "__main__":
    test_port_scan_rule_detection()
    test_new_device_rule_detection()
    test_anomalous_login_time_rule_detection()
    test_impossible_travel_rule_detection()
    test_brute_force_and_sustained_attack_rules()
    test_multiple_failed_logins_rule_detection()
    test_combined_multi_signal_detection()
    test_credential_stuffing_rule_detection()
    test_suspicious_login_rule_detection()
    test_ground_truth_fields_never_reach_behavioural_decisions()
    test_rule_engine_robustness_edge_cases()
    print("\nALL RULE ENGINE TESTS PASSED!")
