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
from app.services.rule_engine import evaluate_rules
from app.database import Base, engine

Base.metadata.create_all(bind=engine)


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

        now = datetime.now(timezone.utc)
        
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

        now = datetime.now(timezone.utc)
        
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
        assert len(detections) == 1
        assert detections[0].label == "sustained_attack_no_compromise"
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
        
        # Verify 3 distinct rules evaluate successfully from the raw data
        detections = evaluate_rules(session_id=session_id, db=db)
        assert len(detections) == 3, f"Expected 3 detections, got {len(detections)}"
        
        labels = {d.label for d in detections}
        assert "brute_force_detected" in labels
        assert "new_device_detected" in labels
        assert "anomalous_login_time_detected" in labels
        
        # Compute risk score
        risk_row = compute_risk_score(session_id=session_id, db=db)
        
        # Verify Risk Band
        assert risk_row.band in [RiskBand.HIGH, RiskBand.CRITICAL], f"Risk band is {risk_row.band}, expected HIGH or CRITICAL"
        
        # Verify contributing factors
        factors = json.loads(risk_row.contributing_factors)
        assert factors["multi_signal_bonus"] == 30, f"Expected 30 bonus, got {factors['multi_signal_bonus']}"
        assert set(factors["triggered_rules"]) == {"brute_force_detected", "new_device_detected", "anomalous_login_time_detected"}
        
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

if __name__ == "__main__":
    test_port_scan_rule_detection()
    test_new_device_rule_detection()
    test_anomalous_login_time_rule_detection()
    test_impossible_travel_rule_detection()
    test_multiple_failed_logins_rule_detection()
    test_combined_multi_signal_detection()
    test_credential_stuffing_rule_detection()
    test_suspicious_login_rule_detection()
    print("\nALL RULE ENGINE TESTS PASSED!")
