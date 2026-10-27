import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database import get_db, Base
from app.models.models import SecurityEvent, Detection

from sqlalchemy.pool import StaticPool

# Setup an in-memory SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_database():
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    # Insert some dummy data
    from app.models.models import DetectionSource
    # We need a session to satisfy foreign key for Detection, though we disabled checks, let's just make one or use a dummy ID if sqlite allows. 
    # Actually SQLite might enforce FKs. Let's create a Session first.
    from app.models.models import Session, Scenario, ScenarioCategory, DifficultyLevel
    scenario = Scenario(name="s", category=ScenarioCategory.PORT_SCAN, difficulty=DifficultyLevel.EASY)
    db.add(scenario)
    db.commit()
    session = Session(student_id="1", scenario_id=scenario.id)
    db.add(session)
    db.commit()

    db.add(SecurityEvent(
        session_id=session.id, 
        scenario="test", 
        event_type="login", 
        source="1.1.1.1", 
        target="admin"
    ))
    db.add(Detection(
        session_id=session.id, 
        source=DetectionSource.RULE, 
        label="brute_force", 
        confidence=0.9
    ))
    db.commit()
    yield
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()

def test_get_system_config():
    response = client.get("/api/system/config")
    assert response.status_code == 200
    data = response.json()
    
    assert "health" in data
    assert data["health"]["database"] == "connected"
    assert data["health"]["api"] == "online"
    
    assert "detection" in data
    assert data["detection"]["phishing_threshold"] == 0.65
    assert "brute_force" in data["detection"]["supported_rules"]
    assert "ml_model_version" in data["detection"]
    
    assert "integrity" in data
    assert "hmac_configured" in data["integrity"]
    
    assert "data" in data
    assert data["data"]["event_count"] == 1
    assert data["data"]["detection_count"] == 1
    assert "retention_policy" in data["data"]
