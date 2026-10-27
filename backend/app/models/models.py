import enum
from datetime import datetime
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Float,
    Boolean,
    DateTime,
    ForeignKey,
    Enum as SQLEnum,
    func,
    event,
)
import hashlib
from sqlalchemy.orm import relationship

from app.database import Base


# ==========================================
# Enums
# ==========================================

class ScenarioCategory(str, enum.Enum):
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    SUSPICIOUS_LOGIN = "suspicious_login"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    NEW_DEVICE = "new_device"
    PHISHING = "phishing"
    ANOMALOUS_LOGIN_TIME = "anomalous_login_time"
    MULTIPLE_FAILED_LOGINS = "multiple_failed_logins"
    COMBINED_MULTI_SIGNAL = "combined_multi_signal"

    # Legacy aliases kept for backward-compatible DB reads
    SSH_BRUTE_FORCE = "ssh_brute_force"
    WEB_PROBING = "web_probing"
    SQL_INJECTION = "sql_injection"


class DifficultyLevel(str, enum.Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


class SessionStatus(str, enum.Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    ABANDONED = "abandoned"


class DetectionSource(str, enum.Enum):
    RULE = "rule"
    ML = "ml"
    HYBRID = "hybrid"


class RiskBand(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class AnalystDecision(str, enum.Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


# ==========================================
# Models
# ==========================================

class Dataset(Base):
    """Offline, exportable dataset capturing a deterministic simulation payload."""
    __tablename__ = "datasets"

    id = Column(String(64), primary_key=True, index=True)
    schema_version = Column(String(16), nullable=False, default="1.0")
    scenario_category = Column(String(128), nullable=False)
    events_count = Column(Integer, default=0)
    payload_json = Column(Text, nullable=False)  # JSONL or JSON representing events
    created_at = Column(DateTime, default=func.now(), nullable=False)
    is_synthetic = Column(Boolean, default=True)
    is_evaluated = Column(Boolean, default=False)
    is_training_eligible = Column(Boolean, default=False)
    ground_truth_available = Column(Boolean, default=False)

    # --- Attack Scenario Studio provenance (nullable; deterministic datasets leave these unset) ---
    # Links a compiled dataset back to the validated scenario plan that produced it.
    scenario_id = Column(String(128), nullable=True, index=True)
    # Versioned generator that compiled the telemetry (e.g. "scenario-studio-1.0").
    generator_version = Column(String(32), nullable=True)
    # Partition role protecting train/eval separation ("training" | "validation" | "test").
    dataset_role = Column(String(16), nullable=True)
    # SHA-256 of the analyst prompt that seeded an LLM proposal (never the raw prompt).
    llm_input_sha256 = Column(String(64), nullable=True)
    # Full validated scenario specification (ground truth + expected outcomes) preserved
    # as the authoritative reference for replay evaluation and learning-provenance.
    scenario_spec_json = Column(Text, nullable=True)

class EvaluationRun(Base):
    """Execution of a specific detector against a Dataset."""
    __tablename__ = "evaluation_runs"

    id = Column(String(64), primary_key=True, index=True)
    dataset_id = Column(String(64), ForeignKey("datasets.id"), nullable=False)
    model_version = Column(String(64), nullable=True)
    detector_type = Column(String(64), nullable=False)
    events_processed = Column(Integer, default=0)
    detections_output = Column(Integer, default=0)
    true_positives = Column(Integer, nullable=True)
    false_positives = Column(Integer, nullable=True)
    false_negatives = Column(Integer, nullable=True)
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    started_at = Column(DateTime, default=func.now(), nullable=False)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(32), default="running")
    errors = Column(Text, nullable=True)

    # --- Attack Scenario Studio linkage (nullable; generic replay leaves these unset) ---
    # Replay session whose detections produced this run's results (provenance link).
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=True, index=True)
    # Full expected-vs-actual comparison (labels, TP/FP/FN sets) for the Explorer.
    comparison_json = Column(Text, nullable=True)
    
class Scenario(Base):
    """Attack scenario configuration and metadata."""
    __tablename__ = "scenarios"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    category = Column(
        SQLEnum(ScenarioCategory, values_callable=lambda x: [e.value for e in x], name="scenario_category"),
        nullable=False,
        index=True,
    )
    description = Column(Text, nullable=True)
    difficulty = Column(
        SQLEnum(DifficultyLevel, values_callable=lambda x: [e.value for e in x], name="difficulty_level"),
        nullable=False,
    )
    config_json = Column(Text, nullable=True)

    # Relationships
    sessions = relationship("Session", back_populates="scenario", cascade="all, delete-orphan")


class Session(Base):
    """Interactive learning and evaluation session for a student."""
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    student_id = Column(String(255), nullable=False, index=True)
    scenario_id = Column(Integer, ForeignKey("scenarios.id"), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    ended_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(
        SQLEnum(SessionStatus, values_callable=lambda x: [e.value for e in x], name="session_status"),
        default=SessionStatus.RUNNING,
        nullable=False,
    )

    # Relationships
    scenario = relationship("Scenario", back_populates="sessions")
    events = relationship("SuricataEvent", back_populates="session", cascade="all, delete-orphan")
    detections = relationship("Detection", back_populates="session", cascade="all, delete-orphan")
    risk_scores = relationship("RiskScore", back_populates="session", cascade="all, delete-orphan")
    student_responses = relationship("StudentResponse", back_populates="session", cascade="all, delete-orphan")
    performance_histories = relationship("PerformanceHistory", back_populates="session", cascade="all, delete-orphan")
    security_events = relationship("SecurityEvent", back_populates="session", cascade="all, delete-orphan")


class SuricataEvent(Base):
    """Network intrusion event captured from Suricata IDS."""
    __tablename__ = "suricata_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=False, index=True)
    raw_signature = Column(String(512), nullable=False)
    src_ip = Column(String(64), nullable=False)
    dest_ip = Column(String(64), nullable=False)
    dest_port = Column(Integer, nullable=True)
    protocol = Column(String(32), nullable=False)
    severity = Column(Integer, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    evidence_hash = Column(String(128), nullable=True)
    previous_hash = Column(String(128), nullable=True)

    # Relationship
    session = relationship("Session", back_populates="events")


class Detection(Base):
    """Detection output from rules, ML engine, or hybrid pipeline."""
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=False, index=True)
    source = Column(
        SQLEnum(DetectionSource, values_callable=lambda x: [e.value for e in x], name="detection_source"),
        nullable=False,
    )
    label = Column(String(255), nullable=False)
    confidence = Column(Float, nullable=False)
    explanation = Column(Text, nullable=True)
    features = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    evidence_hash = Column(String(128), nullable=True)
    previous_hash = Column(String(128), nullable=True)
    expected_attack_detected = Column(Boolean, nullable=True)
    classification_status = Column(String(32), nullable=True)

    # Relationship
    session = relationship("Session", back_populates="detections")


class RiskScore(Base):
    """Computed situational risk assessment for a session."""
    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=False, index=True)
    score = Column(Integer, nullable=False)
    band = Column(
        SQLEnum(RiskBand, values_callable=lambda x: [e.value for e in x], name="risk_band"),
        nullable=False,
    )
    contributing_factors = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationship
    session = relationship("Session", back_populates="risk_scores")


class StudentResponse(Base):
    """Mitigation or defensive action submitted by a student."""
    __tablename__ = "student_responses"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=False, index=True)
    chosen_action = Column(String(255), nullable=False)
    is_correct = Column(Boolean, nullable=False)
    points_awarded = Column(Integer, nullable=False, default=0)
    response_time_seconds = Column(Float, nullable=False)
    submitted_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationship
    session = relationship("Session", back_populates="student_responses")


class PerformanceHistory(Base):
    """Historical score records of students across scenarios."""
    __tablename__ = "performance_histories"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    student_id = Column(String(255), nullable=False, index=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=False, index=True)
    score_achieved = Column(Integer, nullable=False)
    category = Column(
        SQLEnum(ScenarioCategory, values_callable=lambda x: [e.value for e in x], name="scenario_category"),
        nullable=False,
    )
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationship
    session = relationship("Session", back_populates="performance_histories")


class SecurityEvent(Base):
    """Synthetic and live security telemetry event (logins, phishing, network, host anomalies)."""
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=True, index=True)
    simulation_id = Column(String(128), nullable=True, index=True)
    scenario = Column(String(128), nullable=False, index=True)
    event_type = Column(String(128), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    source = Column(String(255), nullable=False)
    target = Column(String(255), nullable=False)
    device = Column(String(255), nullable=True)
    location = Column(String(255), nullable=True)
    risk_score = Column(Integer, nullable=True)
    risk_level = Column(String(32), nullable=True)
    detection_status = Column(String(64), nullable=False, default="Detected")
    payload_json = Column(Text, nullable=True)
    evidence_hash = Column(String(128), nullable=True)
    previous_hash = Column(String(128), nullable=True)

    # Relationship
    session = relationship("Session", back_populates="security_events")


class ModelVersion(Base):
    """Tracks versions of trained machine learning models for adaptive learning."""
    __tablename__ = "model_versions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    version_string = Column(String(64), nullable=False, unique=True, index=True)
    task_name = Column(String(128), nullable=False, index=True)
    is_accepted = Column(Boolean, nullable=False, default=False)
    accuracy = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    training_samples = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class LearningExample(Base):
    """Stores telemetry features and labels for adaptive ML training."""
    __tablename__ = "learning_examples"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=True, index=True)
    task_name = Column(String(128), nullable=False, index=True)
    label = Column(Integer, nullable=False)  # 0 = normal, 1 = attack (or other multiclass mapping)
    feature_json = Column(Text, nullable=False)  # Extracted feature dictionary
    source_simulation = Column(String(128), nullable=True)
    category = Column(String(64), nullable=True)
    feature_schema_version = Column(String(32), nullable=True, default="1.0")
    trusted_label_source = Column(String(64), nullable=True)
    relevant_event_identifiers = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationship
    session = relationship("Session")


class AnalysisRun(Base):
    """Persisted LLM learning-analysis of a completed EvaluationRun (Milestone 1).

    The LLM is an analyst only; this row records the evidence-backed context that
    was analyzed and the outcome of the analysis. It never grants the LLM any
    database-write or model-activation authority.
    """
    __tablename__ = "analysis_runs"

    id = Column(String(64), primary_key=True, index=True)
    evaluation_run_id = Column(String(64), ForeignKey("evaluation_runs.id"), nullable=False, index=True)
    dataset_id = Column(String(64), ForeignKey("datasets.id"), nullable=True, index=True)
    attack_category = Column(String(64), nullable=True)
    mode = Column(String(64), nullable=False)
    # completed | failed | provider_unavailable
    status = Column(String(32), nullable=False, default="running")
    summary = Column(Text, nullable=True)
    model = Column(String(128), nullable=True)
    correlation_id = Column(String(64), nullable=True)
    context_sha256 = Column(String(64), nullable=True)
    findings_json = Column(Text, nullable=True)
    # ok | unavailable | invalid
    provider_status = Column(String(32), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class Recommendation(Base):
    """A single validated, evidence-linked recommendation from an AnalysisRun.

    Recommendations are stored SEPARATELY from active rules/models/labels. They
    carry no enforcement power: activation and rule edits remain deterministic,
    audited subsystem concerns. Ids, timestamps and status are server-assigned.
    """
    __tablename__ = "recommendations"

    id = Column(String(64), primary_key=True, index=True)
    analysis_run_id = Column(String(64), ForeignKey("analysis_runs.id"), nullable=False, index=True)
    attack_category = Column(String(64), nullable=True)
    recommendation_type = Column(String(64), nullable=False)
    # pending_review | ... (approve/reject workflow arrives in Milestone 2)
    status = Column(String(32), nullable=False, default="pending_review")
    summary = Column(Text, nullable=False)
    hypothesis = Column(Text, nullable=True)
    # qualitative LLM self-report: low | medium | high (NOT a calibrated probability)
    confidence = Column(String(16), nullable=True)
    evidence_refs_json = Column(Text, nullable=True)
    proposed_change = Column(Text, nullable=True)
    required_features_json = Column(Text, nullable=True)
    required_data = Column(Text, nullable=True)
    expected_benefit = Column(Text, nullable=True)
    potential_risks = Column(Text, nullable=True)
    validation_plan = Column(Text, nullable=True)
    rejection_reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Incident(Base):
    """Unified incident grouping correlated events from multiple detection engines."""
    __tablename__ = "incidents"

    id = Column(String(128), primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    status = Column(
        SQLEnum(IncidentStatus, values_callable=lambda x: [e.value for e in x], name="incident_status"),
        default=IncidentStatus.OPEN,
        nullable=False,
    )
    severity = Column(String(32), nullable=True)
    risk_score = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Stores unified normalized events and correlation reasons
    evidence_summary_json = Column(Text, nullable=True)
    related_events_json = Column(Text, nullable=True)
    source_modules_json = Column(Text, nullable=True)

    feedback = relationship("IncidentFeedback", back_populates="incident", cascade="all, delete-orphan")


class IncidentFeedback(Base):
    """Analyst review feedback for incidents."""
    __tablename__ = "incident_feedback"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    incident_id = Column(String(128), ForeignKey("incidents.id"), nullable=False, index=True)
    analyst_id = Column(String(255), nullable=False)
    decision = Column(
        SQLEnum(AnalystDecision, values_callable=lambda x: [e.value for e in x], name="analyst_decision"),
        nullable=False,
    )
    rationale = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    incident = relationship("Incident", back_populates="feedback")


from datetime import datetime, timezone

def ensure_timestamp(mapper, connection, target):
    if target.timestamp is None:
        target.timestamp = datetime.now(timezone.utc)

def hash_after_insert(mapper, connection, target):
    """
    SQLAlchemy after_insert listener that HMAC-signs every inserted evidence record.

    Fail-closed contract
    --------------------
    - If the HMAC key is absent (ValueError from canonicalize_and_hash), the exception
      propagates up through SQLAlchemy's event system and causes the enclosing
      db.commit() to roll back.  No unsigned record is ever persisted.
    - Any other unexpected signing failure is wrapped in a RuntimeError and also
      propagates to roll back the transaction.
    - HMAC key material is never included in raised messages.
    """
    import logging
    from app.services.integrity_service import canonicalize_and_hash
    from sqlalchemy import select

    _log = logging.getLogger(__name__)
    record_type = target.__class__.__name__
    table = mapper.local_table

    # Evidence Chaining: Get previous hash for the same session
    cache_key = f"last_hash_{table.name}_{target.session_id}"
    if cache_key in connection.info:
        previous_hash = connection.info[cache_key]
    else:
        # Query DB for the most recent hash in this session before this record
        stmt = select(table.c.evidence_hash).where(
            table.c.session_id == target.session_id,
            table.c.id < target.id
        ).order_by(table.c.id.desc()).limit(1)
        previous_hash = connection.execute(stmt).scalar()

    target.previous_hash = previous_hash

    # Because target.id is auto-generated by the database, we can only safely hash it
    # in after_insert.  Any failure here MUST propagate so the commit rolls back.
    try:
        evidence_hash = canonicalize_and_hash(record_type, target)
    except ValueError:
        # Missing or empty HMAC key — propagate as-is so the transaction rolls back.
        # The caller (simulation service / test) will receive a clear error.
        _log.error(
            "HMAC signing failed for %s id=%s: HMAC key is not configured. "
            "Transaction will be rolled back.",
            record_type, getattr(target, 'id', '?')
        )
        raise  # re-raise: SQLAlchemy rolls back the enclosing transaction
    except Exception as exc:
        _log.error(
            "Unexpected error during HMAC signing for %s id=%s: %s. "
            "Transaction will be rolled back.",
            record_type, getattr(target, 'id', '?'), type(exc).__name__
        )
        raise RuntimeError(
            f"Evidence integrity signing failed for {record_type}: {type(exc).__name__}"
        ) from exc

    # Update cache for subsequent inserts in this transaction
    connection.info[cache_key] = evidence_hash

    # Issue a direct UPDATE to avoid triggering recursive flushes
    connection.execute(
        table.update().where(table.c.id == target.id).values(
            previous_hash=previous_hash,
            evidence_hash=evidence_hash
        )
    )
    # Update the local instance state so it's consistent for the rest of the transaction
    target.evidence_hash = evidence_hash

# Attach listeners to cover ID and timestamp safely
for model in [SuricataEvent, Detection, SecurityEvent]:
    event.listen(model, 'before_insert', ensure_timestamp)
    event.listen(model, 'after_insert', hash_after_insert)

