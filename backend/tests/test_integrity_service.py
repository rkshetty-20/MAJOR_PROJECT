import pytest
import sys
import os
import json
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import Base, engine, SessionLocal
from app.models import Session as SessionModel, SecurityEvent, Detection, SuricataEvent, ScenarioCategory, SessionStatus, DetectionSource
from app.services.integrity_service import verify_record_integrity, canonicalize_and_hash

# We use the isolated test database from conftest.py
import hashlib

@pytest.fixture(autouse=True)
def setup_env_var():
    os.environ["EVIDENCE_HMAC_KEY"] = "test_secret_key"
    yield
    if "EVIDENCE_HMAC_KEY" in os.environ:
        del os.environ["EVIDENCE_HMAC_KEY"]

@pytest.fixture(scope="module")
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    # Create a test session to attach events to
    session = SessionModel(
        student_id="test_student",
        scenario_id=1,
        started_at=datetime.now(timezone.utc),
        status=SessionStatus.COMPLETED
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    
    yield db, session.id
    
    db.close()


def test_01_unchanged_record_verifies_successfully(setup_db):
    """Test: An unchanged record verifies successfully and handles DB-generated IDs."""
    db, session_id = setup_db
    
    # Create event
    event = SecurityEvent(
        session_id=session_id,
        scenario="port_scan",
        event_type="test_event",
        source="10.0.0.1",
        target="10.0.0.2",
        payload_json='{"key": "value"}'
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    
    # The hash should have been generated after insert, including the DB-generated ID and Timestamp
    assert event.evidence_hash is not None
    assert event.evidence_hash.startswith("v2:")
    assert len(event.evidence_hash) == 47
    
    # Verify using the service
    status = verify_record_integrity("SecurityEvent", event)
    assert status == "verified"

def test_02_changing_payload_produces_mismatch(setup_db):
    """Test: Changing a hashed payload produces a mismatch."""
    db, session_id = setup_db
    
    event = SecurityEvent(
        session_id=session_id,
        scenario="port_scan",
        event_type="test_event",
        source="10.0.0.1",
        target="10.0.0.2",
        payload_json='{"original": "data"}'
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    
    assert verify_record_integrity("SecurityEvent", event) == "verified"
    
    # Tamper with the payload directly in the database
    db.execute(
        SecurityEvent.__table__.update().where(SecurityEvent.id == event.id).values(payload_json='{"tampered": "data"}')
    )
    db.commit()
    
    # Fetch fresh
    tampered_event = db.query(SecurityEvent).filter(SecurityEvent.id == event.id).first()
    
    status = verify_record_integrity("SecurityEvent", tampered_event)
    assert status == "mismatch"
    
    # Test: Verification never repairs a mismatched record automatically
    db.refresh(tampered_event)
    assert tampered_event.evidence_hash != canonicalize_and_hash("SecurityEvent", tampered_event)

def test_03_changing_timestamp_produces_mismatch(setup_db):
    """Test: Changing a timestamp or other covered field produces a mismatch."""
    db, session_id = setup_db
    
    det = Detection(
        session_id=session_id,
        source=DetectionSource.RULE,
        label="test_detection",
        confidence=0.9,
        features="{}"
    )
    db.add(det)
    db.commit()
    db.refresh(det)
    
    assert verify_record_integrity("Detection", det) == "verified"
    
    # Tamper with the timestamp (e.g., attacker trying to hide delay)
    from datetime import timedelta
    new_time = det.timestamp + timedelta(hours=1)
    
    db.execute(
        Detection.__table__.update().where(Detection.id == det.id).values(timestamp=new_time)
    )
    db.commit()
    
    tampered_det = db.query(Detection).filter(Detection.id == det.id).first()
    assert verify_record_integrity("Detection", tampered_det) == "mismatch"

def test_04_missing_hash_reported_explicitly(setup_db):
    """Test: A missing hash is reported explicitly."""
    db, session_id = setup_db
    
    event = SecurityEvent(
        session_id=session_id,
        scenario="port_scan",
        event_type="test_event",
        source="10.0.0.1",
        target="10.0.0.2"
    )
    db.add(event)
    db.commit()
    
    # Manually nullify the hash to simulate legacy records
    db.execute(
        SecurityEvent.__table__.update().where(SecurityEvent.id == event.id).values(evidence_hash=None)
    )
    db.commit()
    
    legacy_event = db.query(SecurityEvent).filter(SecurityEvent.id == event.id).first()
    
    status = verify_record_integrity("SecurityEvent", legacy_event)
    assert status == "missing_hash"

def test_05_session_isolation_preserved(setup_db):
    """Test: Session isolation is preserved."""
    db, session_id_1 = setup_db
    
    # Session 2
    session2 = SessionModel(student_id="test_student2", scenario_id=1)
    db.add(session2)
    db.commit()
    db.refresh(session2)
    session_id_2 = session2.id
    
    event1 = SecurityEvent(session_id=session_id_1, scenario="s1", event_type="e1", source="src", target="dst")
    event2 = SecurityEvent(session_id=session_id_2, scenario="s2", event_type="e2", source="src", target="dst")
    
    db.add_all([event1, event2])
    db.commit()
    
    # Verifying event1 only verifies event1's data, not event2
    assert verify_record_integrity("SecurityEvent", event1) == "verified"
    
    # If someone tries to swap session IDs to attribute an event to another session
    db.execute(
        SecurityEvent.__table__.update().where(SecurityEvent.id == event1.id).values(session_id=session_id_2)
    )
    db.commit()
    
    tampered_event = db.query(SecurityEvent).filter(SecurityEvent.id == event1.id).first()
    assert verify_record_integrity("SecurityEvent", tampered_event) == "mismatch"

def test_06_database_generated_identifiers_handled_correctly(setup_db):
    """Test: Database-generated identifiers are handled correctly."""
    db, session_id = setup_db
    
    event = SuricataEvent(
        session_id=session_id,
        raw_signature="ET MALWARE",
        src_ip="1.1.1.1",
        dest_ip="2.2.2.2",
        dest_port=80,
        protocol="TCP",
        severity=1
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    
    assert event.id is not None
    assert event.timestamp is not None
    assert event.evidence_hash is not None
    
    assert verify_record_integrity("SuricataEvent", event) == "verified"

def test_07_missing_key_fails_closed(setup_db):
    """Test: Missing key causes missing hash on insert and verification_unavailable."""
    db, session_id = setup_db
    
    # Remove key
    if "EVIDENCE_HMAC_KEY" in os.environ:
        del os.environ["EVIDENCE_HMAC_KEY"]
    
    from app.config import settings
    original_key = settings.EVIDENCE_HMAC_KEY
    settings.EVIDENCE_HMAC_KEY = ""
    
    event = SecurityEvent(session_id=session_id, scenario="port_scan", event_type="e3", source="src", target="dst")
    db.add(event)
    
    with pytest.raises(ValueError, match="Evidence signing failed: Cryptographic key material is unavailable."):
        db.commit()
        
    db.rollback()
    
    # Assert that no partially committed unsigned record remains
    record = db.query(SecurityEvent).filter(SecurityEvent.event_type == "e3").first()
    assert record is None
    
    settings.EVIDENCE_HMAC_KEY = original_key

def test_08_legacy_sha256_records(setup_db):
    """Test: Legacy SHA-256 records are verified as 'verified_legacy'."""
    db, session_id = setup_db
    
    event = SecurityEvent(session_id=session_id, scenario="s1", event_type="e1", source="src", target="dst")
    db.add(event)
    db.commit()
    
    # Compute legacy hash
    from app.services.integrity_service import _get_canonical_string
    legacy_hash = hashlib.sha256(_get_canonical_string("SecurityEvent", event).encode('utf-8')).hexdigest()
    
    db.execute(
        SecurityEvent.__table__.update().where(SecurityEvent.id == event.id).values(evidence_hash=legacy_hash)
    )
    db.commit()
    
    legacy_event = db.query(SecurityEvent).filter(SecurityEvent.id == event.id).first()
    assert verify_record_integrity("SecurityEvent", legacy_event) == "verified_legacy"

def test_09_stored_mac_replacement_without_secret(setup_db):
    """Test: Attacker modifying data and creating a new MAC fails without secret."""
    db, session_id = setup_db
    
    event = SecurityEvent(session_id=session_id, scenario="s1", event_type="e1", source="src", target="dst", payload_json='{"real": "data"}')
    db.add(event)
    db.commit()
    db.refresh(event)
    
    # Attacker tampers data
    tampered_payload = '{"fake": "data"}'
    
    # Attacker tries to create a new MAC but doesn't know the secret.
    # Attacker tries using a different secret:
    import hmac, base64
    from app.services.integrity_service import _get_canonical_string
    
    # Temporarily apply tampered payload to object to get canonical string
    event.payload_json = tampered_payload
    canonical_string = _get_canonical_string("SecurityEvent", event)
    
    fake_key = b"wrong_secret"
    fake_mac = hmac.new(fake_key, canonical_string.encode('utf-8'), hashlib.sha256).digest()
    fake_hash = f"v2:{base64.b64encode(fake_mac).decode('ascii')}"
    
    # Update DB with tampered data and fake hash
    db.execute(
        SecurityEvent.__table__.update().where(SecurityEvent.id == event.id).values(payload_json=tampered_payload, evidence_hash=fake_hash)
    )
    db.commit()
    
    tampered_event = db.query(SecurityEvent).filter(SecurityEvent.id == event.id).first()
    assert verify_record_integrity("SecurityEvent", tampered_event) == "mismatch"
def test_10_evidence_chain_valid(setup_db):
    """Test: Two events in sequence form a valid chain."""
    db, session_id = setup_db
    
    event1 = SecurityEvent(session_id=session_id, scenario="s1", event_type="e1", source="src", target="dst")
    db.add(event1)
    db.commit()
    db.refresh(event1)
    
    event2 = SecurityEvent(session_id=session_id, scenario="s1", event_type="e2", source="src", target="dst")
    db.add(event2)
    db.commit()
    db.refresh(event2)
    
    assert event2.previous_hash == event1.evidence_hash
    assert verify_record_integrity("SecurityEvent", event2, db) == "verified"

def test_11_evidence_chain_broken(setup_db):
    """Test: Deleting the first event causes the second event to report a broken chain."""
    db, session_id = setup_db
    
    event1 = SecurityEvent(session_id=session_id, scenario="s1", event_type="e1", source="src", target="dst")
    db.add(event1)
    db.commit()
    db.refresh(event1)
    
    event2 = SecurityEvent(session_id=session_id, scenario="s1", event_type="e2", source="src", target="dst")
    db.add(event2)
    db.commit()
    db.refresh(event2)
    
    # Delete the first event
    db.delete(event1)
    db.commit()
    
    # Reload event2 and verify chain
    db.refresh(event2)
    assert verify_record_integrity("SecurityEvent", event2, db) == "chain_broken"
