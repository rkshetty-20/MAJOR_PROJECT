import os
import sys
import json
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import SessionLocal, Base, engine
from app.models import (
    LearningExample,
    ModelVersion,
    Detection,
    RiskScore,
)
from app.routers.scenarios import seed_scenarios
from app.services.simulation_service import run_synthetic_simulation
from app.services.ml_engine import train_and_evaluate_model

# Initialize DB for tests
Base.metadata.create_all(bind=engine)


def test_phishing_e2e():
    db = SessionLocal()
    try:
        seed_scenarios(db)
        
        # 1. Run synthetic phishing simulation
        result = run_synthetic_simulation(
            scenario="phishing_url",
            intensity="low",
            db=db,
        )
        
        sim_id = result["simulation_id"]
        
        # 2. Assert events generated
        assert result["events_generated"] > 0
        
        # 3. Assert Phishing Detection was created
        detections = result["detections"]
        assert any(d["label"] == "phishing_url_detected" for d in detections)
        
        # 4. Assert Risk Fusion worked
        assert result["risk"]["score"] > 0
        
        # 5. Assert Timeline includes detection
        simulation_flow = result["simulation_flow"]
        assert any("Detection triggered" in step["step"] for step in simulation_flow)
        
    finally:
        db.close()


def test_adaptive_learning_e2e():
    db = SessionLocal()
    try:
        seed_scenarios(db)
        
        # 1. Clear previous learning examples for clean test
        db.query(LearningExample).delete()
        db.commit()
        
        # 2. Run simulation that generates learning examples
        for _ in range(5):
            run_synthetic_simulation(
                scenario="port_scan",
                intensity="high",
                db=db,
            )
            run_synthetic_simulation(
                scenario="port_scan",
                intensity="low",
                db=db,
            )
        
        # 3. Verify Learning Examples created
        examples = db.query(LearningExample).all()
        assert len(examples) > 0, "No learning examples were created"
        
        # 4. We need at least 10 for the adaptive engine.
        # It's already 10 (5 loops x 2 port_scans). Let's just run a few other scenarios
        # to ensure they don't break things.
        for _ in range(2):
            run_synthetic_simulation(scenario="brute_force", intensity="medium", db=db)
            run_synthetic_simulation(scenario="suspicious_login", intensity="low", db=db)
        
        examples = db.query(LearningExample).all()
        assert len(examples) >= 10, "Not enough learning examples to train"
        
        # 5. Trigger Adaptive Training
        train_result = train_and_evaluate_model("port_scan", db)
        
        # 6. Verify result
        assert train_result["status"] in ["ACCEPTED", "REJECTED"]
        assert "candidate_metrics" in train_result
        
        if train_result["status"] == "ACCEPTED":
            # 7. Check if ModelVersion was saved
            latest_version = db.query(ModelVersion).filter_by(is_accepted=True).first()
            assert latest_version is not None
            assert latest_version.version_string == train_result["candidate_version"]
            
    finally:
        db.close()

def test_adaptive_learning_status_and_readiness():
    from app.services.ml_engine import get_adaptive_status
    db = SessionLocal()
    try:
        seed_scenarios(db)
        db.query(ModelVersion).delete()
        db.query(LearningExample).delete()
        db.commit()

        # 1. Below minimum data (< 10)
        status = get_adaptive_status("port_scan", db)
        assert status["status"] == "NOT_READY"

        # 2. Exactly minimum data (10), but insufficient class diversity
        for i in range(10):
            db.add(LearningExample(task_name="port_scan", label=0, feature_json="{}"))
        db.commit()
        
        status = get_adaptive_status("port_scan", db)
        assert status["status"] == "INSUFFICIENT_CLASSES"

        # 3. Exactly minimum data (10), with sufficient class diversity (remove 2, add 2 of class 1)
        examples_to_delete = db.query(LearningExample).limit(2).all()
        for ex in examples_to_delete:
            db.delete(ex)
        db.commit()
        for i in range(2):
            db.add(LearningExample(task_name="port_scan", label=1, feature_json="{}"))
        db.commit()

        status = get_adaptive_status("port_scan", db)
        assert status["status"] == "READY_FOR_TRAINING"
        
    finally:
        db.close()
