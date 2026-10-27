from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Dict, Any

from app.database import get_db
from app.models.models import SecurityEvent, Detection
from app.services.ml_engine import get_adaptive_status

router = APIRouter(prefix="/api/system", tags=["System"])

@router.get("/config")
def get_system_config(db: Session = Depends(get_db)) -> Dict[str, Any]:
    # 1. System Health (DB)
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_status = "error"

    # 2. Detection Configuration
    # Hardcoded values from the respective engines
    phishing_threshold = 0.65
    supported_rules = [
        "brute_force",
        "credential_stuffing",
        "anomalous_login_time",
        "new_device",
        "impossible_travel",
        "suspicious_login"
    ]
    
    # ML Status
    ml_status = get_adaptive_status("port_scan", db)

    # 3. Evidence Integrity — read from settings (same source as integrity_service.py)
    from app.config import settings
    hmac_configured = bool(settings.EVIDENCE_HMAC_KEY)

    # 4. Data & Retention
    event_count = db.query(SecurityEvent).count()
    detection_count = db.query(Detection).count()
    
    return {
        "health": {
            "database": db_status,
            "api": "online"
        },
        "detection": {
            "phishing_threshold": phishing_threshold,
            "supported_rules": supported_rules,
            "ml_model_version": ml_status.get("current_version", "v1.0 (Random Forest)"),
            "ml_training_ready": ml_status.get("status") == "READY_FOR_TRAINING"
        },
        "integrity": {
            "hmac_configured": hmac_configured
        },
        "data": {
            "event_count": event_count,
            "detection_count": detection_count,
            "retention_policy": "No automated deletion (Development Default)"
        }
    }
