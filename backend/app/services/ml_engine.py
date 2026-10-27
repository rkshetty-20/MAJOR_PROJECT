import logging
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import joblib
from sqlalchemy.orm import Session

from app.models import (
    Session as SessionModel,
    SuricataEvent,
    Detection,
    DetectionSource,
    LearningExample,
    ModelVersion,
)
from ml.features import extract_features, features_to_vector, extract_auth_features, auth_features_to_vector
import json
import uuid
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)

# Cached model instance in memory
_CACHED_MODEL: Any = None
_MODEL_PATH: str = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "ml",
        "models",
        "port_scan_rf.joblib",
    )
)

_CACHED_AUTH_MODEL: Any = None
_AUTH_MODEL_PATH: str = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "ml",
        "models",
        "brute_force_rf.joblib",
    )
)

def _get_active_version(db: Session, task_name: str = "port_scan"):
    """Return the currently accepted ModelVersion row for a task, or None.

    "Active" means the model that passed the acceptance gate and is in service.
    When no accepted version exists the engine falls back to the bundled base
    model artifact (or rules-only), so callers should treat None as "no adaptive
    model active".
    """
    return (
        db.query(ModelVersion)
        .filter(ModelVersion.task_name == task_name, ModelVersion.is_accepted == True)
        .order_by(ModelVersion.created_at.desc())
        .first()
    )


def _load_model(db: Session, task_name: str = "port_scan") -> Any:
    """Loads the active trained Random Forest model from disk, caching it in memory."""
    global _CACHED_MODEL, _CACHED_AUTH_MODEL

    # Find the active model version in the database
    active_version = _get_active_version(db, task_name)

    is_auth = task_name in ["brute_force", "credential_stuffing"]
    default_path = _AUTH_MODEL_PATH if is_auth else _MODEL_PATH
    cached_ref = _CACHED_AUTH_MODEL if is_auth else _CACHED_MODEL

    model_path_to_load = default_path
    if active_version:
        dynamic_path = os.path.join(os.path.dirname(default_path), f"{active_version.version_string}.joblib")
        if os.path.isfile(dynamic_path):
            model_path_to_load = dynamic_path

    # Check if we already have THIS model loaded
    if cached_ref is not None and getattr(cached_ref, "_loaded_path", None) == model_path_to_load:
        return cached_ref

    if not os.path.isfile(model_path_to_load):
        logger.warning("ML model file not found at %s. Train the model first.", model_path_to_load)
        return None

    try:
        loaded = joblib.load(model_path_to_load)
        loaded._loaded_path = model_path_to_load
        logger.info("Successfully loaded Random Forest %s model from %s", task_name, model_path_to_load)
        if is_auth:
            _CACHED_AUTH_MODEL = loaded
        else:
            _CACHED_MODEL = loaded
        return loaded
    except Exception as exc:
        logger.error("Failed to load ML model from %s: %s", model_path_to_load, exc)
        return None


def evaluate_ml(session_id: int, db: Session) -> Optional[Detection]:
    """
    Evaluates offline-trained Random Forest ML detector against a session's Suricata events:
    1. Loads SuricataEvent rows for the session.
    2. Groups events by src_ip.
    3. Extracts behavioral features matching training-time logic.
    4. Runs .predict_proba on the Random Forest classifier.
    5. If probability of port scan (class 1) exceeds 0.7, creates a Detection row.
    6. Ensures duplicate prevention (only one ML detection per session).

    Args:
        session_id: Active learning session ID.
        db: SQLAlchemy database session.

    Returns:
        The newly created Detection instance, or None if not triggered/already exists.
    """
    session = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not session:
        return None

    scenario = session.scenario
    from app.models import Scenario
    if not scenario and session.scenario_id:
        scenario = db.query(Scenario).filter(Scenario.id == session.scenario_id).first()
    
    scenario_category = scenario.category if scenario else None
    
    # Run auth models if applicable
    from app.models import SecurityEvent
    if scenario_category in ["ssh_brute_force", "web_probing", "multiple_failed_logins", "port_scan"]:
        # Duplicate prevention: check if an ML detection already exists for this session
        existing_ml_detection = (
            db.query(Detection)
            .filter(
                Detection.session_id == session_id,
                Detection.source == DetectionSource.ML,
                Detection.label.in_(["port_scan_detected", "brute_force_detected", "credential_stuffing_detected"]),
            )
            .first()
        )
        if existing_ml_detection:
            return None

        # Network port scan evaluation
        events = (
            db.query(SuricataEvent)
            .filter(SuricataEvent.session_id == session_id)
            .order_by(SuricataEvent.timestamp.asc())
            .all()
        )

        if events:
            model = _load_model(db, "port_scan")
            if model:
                events_by_src: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
                for ev in events:
                    if ev.src_ip:
                        events_by_src[ev.src_ip].append({
                            "src_ip": ev.src_ip,
                            "dest_ip": ev.dest_ip,
                            "dest_port": ev.dest_port,
                            "protocol": ev.protocol,
                            "severity": ev.severity,
                            "timestamp": ev.timestamp,
                            "raw_signature": ev.raw_signature,
                        })

                for src_ip, ip_events in events_by_src.items():
                    feat_dict = extract_features(ip_events)
                    feat_vector = features_to_vector(feat_dict)
                    probabilities = model.predict_proba([feat_vector])[0]
                    class_1_idx = 1 if len(model.classes_) > 1 and model.classes_[1] == 1 else 0
                    prob_scan = float(probabilities[class_1_idx])

                    if prob_scan > 0.7:
                        distinct_ports = int(feat_dict["distinct_dest_ports"])
                        distinct_ips = int(feat_dict["distinct_dest_ips"])
                        confidence_pct = round(prob_scan * 100, 1)

                        explanation = (
                            f"ML model flagged {distinct_ports} distinct ports / "
                            f"{distinct_ips} IPs from {src_ip} as port-scan-like "
                            f"(confidence {confidence_pct}%)"
                        )

                        detection = Detection(
                            session_id=session_id,
                            source=DetectionSource.ML,
                            label="port_scan_detected",
                            confidence=round(prob_scan, 4),
                            explanation=explanation,
                            features=json.dumps(feat_dict),
                            timestamp=datetime.now(timezone.utc),
                        )
                        db.add(detection)
                        db.commit()
                        db.refresh(detection)
                        return detection
                        
        # Auth evaluation
        sec_events = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.session_id == session_id)
            .order_by(SecurityEvent.timestamp.asc())
            .all()
        )
        if sec_events:
            # Group by source
            auth_events_by_src = defaultdict(list)
            for ev in sec_events:
                if ev.source:
                    auth_events_by_src[ev.source].append({
                        "event_type": ev.event_type,
                        "target": ev.target,
                        "device": ev.device,
                        "timestamp": ev.timestamp,
                        "payload_json": ev.payload_json
                    })
                    
            auth_model = _load_model(db, "brute_force")
            if auth_model:
                for src_ip, ip_events in auth_events_by_src.items():
                    feat_dict = extract_auth_features(ip_events)
                    feat_vector = auth_features_to_vector(feat_dict)
                    
                    if feat_dict.get("failed_attempts", 0) > 0 or feat_dict.get("successful_attempts", 0) > 0:
                        probabilities = auth_model.predict_proba([feat_vector])[0]
                        class_1_idx = 1 if len(auth_model.classes_) > 1 and auth_model.classes_[1] == 1 else 0
                        prob_attack = float(probabilities[class_1_idx])

                        if prob_attack > 0.8:
                            confidence_pct = round(prob_attack * 100, 1)
                            label = "brute_force_detected"
                            if feat_dict.get("distinct_targets", 0) >= 3:
                                label = "credential_stuffing_detected"
                                
                            explanation = (
                                f"ML model flagged authentication behavior from {src_ip} as {label} "
                                f"(confidence {confidence_pct}%)"
                            )

                            detection = Detection(
                                session_id=session_id,
                                source=DetectionSource.ML,
                                label=label,
                                confidence=round(prob_attack, 4),
                                explanation=explanation,
                                features=json.dumps(feat_dict),
                                timestamp=datetime.now(timezone.utc),
                            )
                            db.add(detection)
                            db.commit()
                            db.refresh(detection)
                            return detection

def extract_and_store_learning_examples(session_id: int, db: Session) -> int:
    """
    Extracts features from a simulation session and stores them as LearningExample rows.
    """
    session = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not session:
        return 0

    from app.models import SecurityEvent
    
    events = (
        db.query(SuricataEvent)
        .filter(SuricataEvent.session_id == session_id)
        .order_by(SuricataEvent.timestamp.asc())
        .all()
    )
    
    count = 0
    if not events:
        # If no network events, this is a clean/benign network baseline (label 0)
        feat_dict = {
            "distinct_dest_ports": 0,
            "events_per_second": 0,
            "distinct_dest_ips": 0,
            "avg_severity": 0,
            "protocol_diversity": 0
        }
        example = LearningExample(
            session_id=session_id,
            task_name="port_scan",
            label=0,
            feature_json=json.dumps(feat_dict),
            feature_schema_version="1.0"
        )
        db.add(example)
        count += 1
    else:
        events_by_src: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for ev in events:
            if ev.src_ip:
                events_by_src[ev.src_ip].append({
                    "src_ip": ev.src_ip,
                    "dest_ip": ev.dest_ip,
                    "dest_port": ev.dest_port,
                    "protocol": ev.protocol,
                    "severity": ev.severity,
                    "timestamp": ev.timestamp,
                    "raw_signature": ev.raw_signature,
                })

        for src_ip, ip_events in events_by_src.items():
            feat_dict = extract_features(ip_events)
            
            # Derive label independently from the IDS signature rather than the model's input features
            label = 1 if any("SCAN" in ev.get("raw_signature", "").upper() for ev in ip_events) else 0
            
            # Save if there's meaningful network activity
            if feat_dict.get("events_per_second", 0) > 0 or feat_dict.get("distinct_dest_ports", 0) > 0:
                example = LearningExample(
                    session_id=session_id,
                    task_name="port_scan",
                    label=label,
                    feature_json=json.dumps(feat_dict),
                    feature_schema_version="1.0"
                )
                db.add(example)
                count += 1
                
    sec_events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.session_id == session_id)
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )
    
    if sec_events:
        auth_events_by_src = defaultdict(list)
        for ev in sec_events:
            if ev.source and ev.event_type in ["failed_login", "successful_login", "login_attempt", "failed_authentication", "baseline_login", "known_device_login"]:
                auth_events_by_src[ev.source].append({
                    "event_type": ev.event_type,
                    "target": ev.target,
                    "device": ev.device,
                    "timestamp": ev.timestamp,
                    "payload_json": ev.payload_json,
                    "scenario": ev.scenario
                })
        
        for src, ip_events in auth_events_by_src.items():
            feat_dict = extract_auth_features(ip_events)
            
            # Label based on trusted scenario simulation explicitly avoiding rule outputs
            is_brute = any(e.get("scenario") == "brute_force" for e in ip_events)
            is_stuffing = any(e.get("scenario") == "credential_stuffing" for e in ip_events)
            
            label = 1 if (is_brute or is_stuffing) else 0
            task_name = "credential_stuffing" if is_stuffing else "brute_force"
            
            # Save if meaningful auth activity exists
            if feat_dict.get("failed_attempts", 0) > 0 or feat_dict.get("successful_attempts", 0) > 0:
                example = LearningExample(
                    session_id=session_id,
                    task_name=task_name,
                    label=label,
                    feature_json=json.dumps(feat_dict),
                    feature_schema_version="1.0_auth"
                )
                db.add(example)
                count += 1
                
    db.commit()
    return count

def train_and_evaluate_model(task_name: str, db: Session) -> Dict[str, Any]:
    """
    Trains a candidate model, evaluates it. If metrics meet thresholds and beat existing model, saves and versions it.
    """
    examples = db.query(LearningExample).filter(LearningExample.task_name == task_name).all()
    
    if len(examples) < 10:
        return {"status": "NOT_ENOUGH_DATA", "reason": f"Insufficient data: {len(examples)} examples (need 10+)"}
        
    X = []
    y = []
    for ex in examples:
        feat_dict = json.loads(ex.feature_json)
        if task_name in ["brute_force", "credential_stuffing"]:
            X.append(auth_features_to_vector(feat_dict))
        else:
            X.append(features_to_vector(feat_dict))
        y.append(ex.label)
        
    X_array = np.array(X)
    y_array = np.array(y)
    
    # Class distribution check
    unique_classes, counts = np.unique(y_array, return_counts=True)
    class_dist = dict(zip(unique_classes, counts))
    normal_count = int(class_dist.get(0, 0))
    scan_count = int(class_dist.get(1, 0))
    
    if normal_count < 2 or scan_count < 2:
        return {
            "status": "INSUFFICIENT_CLASSES", 
            "reason": f"Requires sufficient examples of both classes. Found Normal: {normal_count}, Port Scan: {scan_count}",
            "class_distribution": {"normal": normal_count, "port_scan": scan_count}
        }
        
    X_train, X_test, y_train, y_test = train_test_split(
        X_array, y_array, test_size=0.25, random_state=42, stratify=y_array
    )
    
    candidate_clf = RandomForestClassifier(n_estimators=100, max_depth=6, min_samples_split=2, random_state=42)
    candidate_clf.fit(X_train, y_train)
    
    y_pred = candidate_clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    
    current_model_version = (
        db.query(ModelVersion)
        .filter(ModelVersion.task_name == task_name, ModelVersion.is_accepted == True)
        .order_by(ModelVersion.created_at.desc())
        .first()
    )
    
    current_f1 = current_model_version.f1_score if current_model_version and current_model_version.f1_score else 0.0
    previous_active_version = current_model_version.version_string if current_model_version else "base_model"
    
    version_string = f"v_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:4]}"
    candidate_path = os.path.join(os.path.dirname(_MODEL_PATH), f"{version_string}.joblib")
    os.makedirs(os.path.dirname(candidate_path), exist_ok=True)
    joblib.dump(candidate_clf, candidate_path)

    is_accepted = False
    status_msg = "REJECTED"
    threshold = 0.85
    f1_diff = f1 - current_f1
    
    # Acceptance Gate Criteria
    if f1 > threshold and f1 >= current_f1:
        is_accepted = True
        status_msg = "ACCEPTED"
        reason = f"Candidate F1 ({f1:.2f}) > {threshold} and candidate F1 >= active F1 ({current_f1:.2f})."
        
        # Demote older accepted models
        db.query(ModelVersion).filter(ModelVersion.task_name == task_name).update({"is_accepted": False})
        
    else:
        if f1 <= threshold:
            reason = f"Candidate F1 ({f1:.2f}) did not exceed threshold {threshold}."
        else:
            reason = f"Candidate F1 ({f1:.2f}) was lower than active F1 ({current_f1:.2f})."
            
        global _CACHED_MODEL
    
    new_version = ModelVersion(
        version_string=version_string,
        task_name=task_name,
        is_accepted=is_accepted,
        accuracy=accuracy,
        f1_score=f1,
        precision=precision,
        recall=recall,
        training_samples=len(y_train),
    )
    db.add(new_version)
    db.commit()
    db.refresh(new_version)
    
    return {
        "status": status_msg,
        "candidate_version": version_string,
        "previous_active_version": previous_active_version,
        "active_model_version": version_string if is_accepted else previous_active_version,
        "decision": status_msg,
        "reason": reason,
        "threshold": threshold,
        "f1_difference": f1_diff,
        "training_examples": len(y_train),
        "test_examples": len(y_test),
        "class_distribution": {"normal": normal_count, "port_scan": scan_count},
        "candidate_metrics": {
            "accuracy": accuracy,
            "f1_score": f1,
            "precision": precision,
            "recall": recall,
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
        },
        "active_metrics": {
            "f1_score": current_f1
        },
        "adapted_at": datetime.now(timezone.utc).isoformat()
    }

def get_adaptive_status(task_name: str, db: Session) -> Dict[str, Any]:
    """
    Returns the comprehensive state of the adaptive ML engine.
    Tracks total vs new learning examples, active model status, and candidate history.
    """
    active_model = (
        db.query(ModelVersion)
        .filter(ModelVersion.task_name == task_name, ModelVersion.is_accepted == True)
        .order_by(ModelVersion.created_at.desc())
        .first()
    )
    
    total_examples = db.query(LearningExample).filter(LearningExample.task_name == task_name).count()
    
    if active_model:
        new_examples = db.query(LearningExample).filter(
            LearningExample.task_name == task_name,
            LearningExample.created_at > active_model.created_at
        ).count()
    else:
        new_examples = total_examples
        
    last_candidate = (
        db.query(ModelVersion)
        .filter(ModelVersion.task_name == task_name)
        .order_by(ModelVersion.created_at.desc())
        .first()
    )
    
    history_records = (
        db.query(ModelVersion)
        .filter(ModelVersion.task_name == task_name)
        .order_by(ModelVersion.created_at.desc())
        .limit(10)
        .all()
    )
    history = []
    for r in history_records:
        history.append({
            "version": r.version_string,
            "f1_score": r.f1_score,
            "is_accepted": r.is_accepted,
            "created_at": r.created_at.isoformat(),
            "training_samples": r.training_samples
        })

    from sqlalchemy import func
    class_dist = dict(db.query(LearningExample.label, func.count(LearningExample.label))
                        .filter(LearningExample.task_name == task_name)
                        .group_by(LearningExample.label)
                        .all())
    normal_count = class_dist.get(0, 0)
    scan_count = class_dist.get(1, 0)

    # Determine explicit status
    status = "NO_NEW_DATA"
    if total_examples < 10:
        status = "NOT_READY"
    elif normal_count < 2 or scan_count < 2:
        status = "INSUFFICIENT_CLASSES"
    elif new_examples > 0:
        status = "NEW_DATA_AVAILABLE"
        if new_examples >= 5:
            status = "READY_FOR_TRAINING"

    return {
        "task_name": task_name,
        "current_version": active_model.version_string if active_model else "base_model",
        "total_examples": total_examples,
        "new_examples": new_examples,
        "training_samples": active_model.training_samples if active_model else 0,
        "metrics": {
            "f1_score": active_model.f1_score if active_model else 0.0,
            "accuracy": active_model.accuracy if active_model else 0.0,
            "precision": active_model.precision if active_model else 0.0,
            "recall": active_model.recall if active_model else 0.0,
        } if active_model else None,
        "last_trained": last_candidate.created_at.isoformat() if last_candidate else None,
        "last_decision": "ACCEPTED" if last_candidate and last_candidate.is_accepted else "REJECTED" if last_candidate else None,
        "status": status,
        "history": history
    }

def rollback_model(task_name: str, target_version: str, db: Session) -> Dict[str, Any]:
    """Rolls back the active model to a previously trained model version."""
    target = db.query(ModelVersion).filter(ModelVersion.version_string == target_version, ModelVersion.task_name == task_name).first()
    if not target:
        raise ValueError(f"Model version {target_version} not found.")
    
    target_path = os.path.join(os.path.dirname(_MODEL_PATH), f"{target_version}.joblib")
    if not os.path.isfile(target_path):
        raise ValueError(f"Artifact for version {target_version} not found on disk.")
        
    # Deactivate current
    db.query(ModelVersion).filter(ModelVersion.task_name == task_name).update({"is_accepted": False})
    
    # Activate target
    target.is_accepted = True
    db.commit()
    
    # Clear cache
    global _CACHED_MODEL
    _CACHED_MODEL = None
    
    return {"status": "SUCCESS", "active_version": target_version, "message": f"Successfully rolled back to {target_version}"}

