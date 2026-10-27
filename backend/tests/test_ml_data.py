import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import Base, get_db
from app.models.models import LearningExample

# Setup test DB
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}, poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_database():
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()

def test_generate_synthetic_data_reproducibility():
    payload1 = {"scenario": "Port Scan", "count": 5, "seed": 42}
    response1 = client.post("/api/ml/data/generate", json=payload1)
    assert response1.status_code == 200
    data1 = response1.json()
    
    payload2 = {"scenario": "Port Scan", "count": 5, "seed": 42}
    response2 = client.post("/api/ml/data/generate", json=payload2)
    assert response2.status_code == 200
    data2 = response2.json()
    
    # Assert reproducible outputs with same seed
    for idx in range(5):
        assert data1[idx]["features"]["events_per_second"] == data2[idx]["features"]["events_per_second"]
        assert data1[idx]["features"]["distinct_dest_ports"] == data2[idx]["features"]["distinct_dest_ports"]

def test_generate_synthetic_data_normal_traffic():
    payload = {"scenario": "Normal Traffic", "count": 5}
    response = client.post("/api/ml/data/generate", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    for item in data:
        assert item["label"] == 0
        assert item["scenario"] == "Normal Traffic"
        assert 1 <= item["features"]["distinct_dest_ports"] <= 5
        assert 0.1 <= item["features"]["events_per_second"] <= 5.0

def test_generate_synthetic_data_invalid_scenario():
    payload = {"scenario": "Invalid Scenario", "count": 5}
    response = client.post("/api/ml/data/generate", json=payload)
    assert response.status_code == 400

def test_add_training_data_and_schema_validation():
    payload = {"scenario": "Port Scan", "count": 2, "seed": 42}
    gen_response = client.post("/api/ml/data/generate", json=payload)
    examples = gen_response.json()
    
    # Tamper with one label (invalid label)
    tampered_examples = [examples[0], examples[1]]
    tampered_examples[0]["label"] = 999
    
    add_response = client.post("/api/ml/data/add", json={"examples": tampered_examples})
    assert add_response.status_code == 200
    
    # Only 1 record should be added because label 999 is invalid
    assert add_response.json()["added"] == 1
    
    db_response = client.get("/api/ml/data")
    assert db_response.status_code == 200
    db_data = db_response.json()
    assert len(db_data) == 1
    
    assert "distinct_dest_ports" in db_data[0]["features"]
    assert "events_per_second" in db_data[0]["features"]

def test_ml_status_dataset_readiness():
    # Fetch status when 0 examples
    status_response = client.get("/api/ml/status?task_name=port_scan")
    assert status_response.json()["status"] == "NOT_READY"
    assert status_response.json()["total_examples"] == 0
    
    # Add normal and port scan (10 total to pass NOT_READY)
    examples = []
    normal_gen = client.post("/api/ml/data/generate", json={"scenario": "Normal Traffic", "count": 5}).json()
    scan_gen = client.post("/api/ml/data/generate", json={"scenario": "Port Scan", "count": 5}).json()
    examples.extend(normal_gen)
    examples.extend(scan_gen)
    
    client.post("/api/ml/data/add", json={"examples": examples})
    
    status_response = client.get("/api/ml/status?task_name=port_scan")
    assert status_response.json()["status"] == "READY_FOR_TRAINING"
    assert status_response.json()["total_examples"] == 10

def test_adaptive_learning_integration_and_separation():
    # Insert 10 examples (5 Normal, 5 Port Scan)
    examples = []
    normal_gen = client.post("/api/ml/data/generate", json={"scenario": "Normal Traffic", "count": 10}).json()
    scan_gen = client.post("/api/ml/data/generate", json={"scenario": "Port Scan", "count": 10}).json()
    examples.extend(normal_gen)
    examples.extend(scan_gen)
    client.post("/api/ml/data/add", json={"examples": examples})
    
    train_response = client.post("/api/ml/train", json={"task_name": "port_scan"})
    assert train_response.status_code == 200
    train_data = train_response.json()
    
    assert train_data["training_examples"] == 15 # 75% of 20
    assert train_data["test_examples"] == 5 # 25% of 20
    assert "class_distribution" in train_data
    
    assert train_data["status"] == "ACCEPTED" or train_data["status"] == "REJECTED"
