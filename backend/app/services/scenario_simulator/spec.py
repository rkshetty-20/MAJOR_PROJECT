"""Versioned scenario specification schema for the LLM Attack Scenario Simulator.

This module defines the strict, self-contained contract that an LLM (or the
deterministic fallback generator) must satisfy before any telemetry is compiled
or any database record is written. It is intentionally free of DB and provider
dependencies so it can be unit-tested in isolation.

Design principles (from the project brief):
    * "LLM proposes; deterministic services execute." The LLM never writes DB
      rows or chooses backend functions; it only fills this schema.
    * Ground truth is kept separate from observable model features.
    * Event counts, durations, token budgets and retries are bounded.
    * Unknown fields are rejected (strict validation).
    * All entity/stage/event references must resolve.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


# ==========================================
# Bounds & constants (single source of truth)
# ==========================================

SCENARIO_SPEC_SCHEMA_VERSION = "1.0"

# Event / duration / token / retry bounds. The event-count upper bound mirrors
# the existing deterministic simulator (see simulation_service.run_synthetic_simulation)
# so replay behaviour stays consistent across the platform.
MIN_EVENT_COUNT = 1
MAX_EVENT_COUNT = 100
MIN_DURATION_SECONDS = 1
MAX_DURATION_SECONDS = 86_400  # 24h ceiling for a synthetic scenario window
MAX_STAGES = 12
MAX_EVENT_TEMPLATES = 60
MAX_ENTITY_TEMPLATES = 40
MAX_EXPECTED_DETECTIONS = 12
MAX_LLM_OUTPUT_TOKENS = 2048
MAX_VALIDATION_REPAIR_ATTEMPTS = 2  # bounded repair; never retry indefinitely


# ==========================================
# Enums
# ==========================================

class AttackCategory(str, enum.Enum):
    """Attack categories with a working generator, detector route and eval path.

    Values intentionally mirror the existing SCENARIO_METADATA keys in
    ``simulation_service`` so generated scenarios flow into the same engines.
    """

    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    PHISHING_URL = "phishing_url"


class Intensity(str, enum.Enum):
    """Mirrors the existing (low, medium, high) intensity convention."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class StageType(str, enum.Enum):
    """Conceptual lifecycle stage classifications.

    These describe *planned* structure only and must never be presented as
    persisted telemetry (see brief: distinguish conceptual stages from real
    events).
    """

    BENIGN_BASELINE = "benign_baseline"
    RECON = "recon"
    INITIAL_ACCESS = "initial_access"
    LATERAL_OR_ESCALATION = "lateral_or_escalation"
    EXFIL_OR_IMPACT = "exfil_or_impact"
    BENIGN_NOISE = "benign_noise"


class GroundTruthSource(str, enum.Enum):
    """How a trusted label is derived. Never from the detector being evaluated."""

    IDS_SIGNATURE = "ids_signature"        # e.g. Suricata "ET SCAN" signature
    SCENARIO_DESIGN = "scenario_design"    # deterministic, seeded label policy
    HEURISTIC_POLICY = "heuristic_policy"  # offline phishing heuristic policy
    UNVERIFIED = "unverified"              # no defensible label; excluded from training


class DatasetRole(str, enum.Enum):
    """Partition role to prevent train/test leakage across the workflow."""

    TRAINING = "training"
    VALIDATION = "validation"
    TEST = "test"


class EventCategory(str, enum.Enum):
    """Normalized event families mapped onto existing telemetry tables.

    ``network``   -> SuricataEvent-shaped records
    ``auth``      -> SecurityEvent auth records
    ``phishing``  -> SecurityEvent phishing_url records
    """

    NETWORK = "network"
    AUTH = "auth"
    PHISHING = "phishing"


# ==========================================
# Detector routing (preserve existing paths)
# ==========================================

class DetectorRoute(BaseModel):
    """Describes which existing detection path a category uses.

    ``ml_supported`` reflects whether an adaptive-ML inference path exists in
    ``ml_engine.evaluate_ml`` for this category. Note: a *base* auth model
    artifact may be absent on disk (brute_force_rf.joblib), in which case the
    auth ML path safely no-ops and rules carry detection — see the audit note.
    ``heuristic_only`` marks categories that are not ML-enabled.
    """

    model_config = ConfigDict(extra="forbid")

    rule_engine: bool = True
    ml_supported: bool = False
    heuristic_only: bool = False
    ml_task_name: Optional[str] = None
    feature_schema: str = ""


# Supported-category registry: discovered from the actual codebase.
CATEGORY_REGISTRY: Dict[AttackCategory, DetectorRoute] = {
    AttackCategory.PORT_SCAN: DetectorRoute(
        rule_engine=True,
        ml_supported=True,
        heuristic_only=False,
        ml_task_name="port_scan",
        feature_schema="network",
    ),
    AttackCategory.BRUTE_FORCE: DetectorRoute(
        rule_engine=True,
        ml_supported=True,
        heuristic_only=False,
        ml_task_name="brute_force",
        feature_schema="auth",
    ),
    AttackCategory.CREDENTIAL_STUFFING: DetectorRoute(
        rule_engine=True,
        ml_supported=True,
        heuristic_only=False,
        ml_task_name="credential_stuffing",
        feature_schema="auth",
    ),
    AttackCategory.PHISHING_URL: DetectorRoute(
        rule_engine=True,
        ml_supported=False,
        heuristic_only=True,
        ml_task_name=None,
        feature_schema="phishing_heuristic",
    ),
}

# Event categories that each attack category may legitimately emit. Used by the
# safety/feasibility validator to prevent mis-routing (e.g. phishing URLs into
# the auth model, auth events into the port-scan feature extractor).
CATEGORY_ALLOWED_EVENT_CATEGORIES: Dict[AttackCategory, set] = {
    AttackCategory.PORT_SCAN: {EventCategory.NETWORK},
    AttackCategory.BRUTE_FORCE: {EventCategory.AUTH},
    AttackCategory.CREDENTIAL_STUFFING: {EventCategory.AUTH},
    AttackCategory.PHISHING_URL: {EventCategory.PHISHING},
}


def is_supported_category(value: str) -> bool:
    return value in {c.value for c in AttackCategory}


def get_detector_route(category: AttackCategory) -> DetectorRoute:
    return CATEGORY_REGISTRY[category]


# ==========================================
# Sub-structures
# ==========================================

class EntityTemplate(BaseModel):
    """A reusable synthetic entity (source IP, target account, device, URL)."""

    model_config = ConfigDict(extra="forbid")

    entity_id: str = Field(..., min_length=1, max_length=64)
    # One of: source_ip | target_account | device | host | url | dest_ip
    kind: str = Field(..., min_length=1, max_length=32)
    # Stable synthetic value/label (never a real credential or external target).
    value: str = Field(..., min_length=1, max_length=255)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class ScenarioStage(BaseModel):
    """A planned conceptual stage of the scenario lifecycle."""

    model_config = ConfigDict(extra="forbid")

    stage_id: str = Field(..., min_length=1, max_length=64)
    stage_type: StageType
    description: str = Field(..., min_length=1, max_length=500)
    # IDs of prior stages this stage depends on (must resolve, acyclic).
    depends_on: List[str] = Field(default_factory=list)
    # Planned event template IDs that belong to this stage.
    planned_event_template_ids: List[str] = Field(default_factory=list)
    expected_observable_behavior: str = Field(..., min_length=1, max_length=500)


class EventTemplate(BaseModel):
    """A deterministic template for generating one class of event.

    Ground truth lives on ``ground_truth_label`` / ``ground_truth_source`` and is
    kept separate from ``features`` (the observable values fed to detectors).
    """

    model_config = ConfigDict(extra="forbid")

    template_id: str = Field(..., min_length=1, max_length=64)
    stage_id: str = Field(..., min_length=1, max_length=64)
    event_category: EventCategory

    # Relative offset from scenario start; deterministic timestamp generation.
    time_offset_seconds: float = Field(..., ge=0)

    # References into entity_templates.
    source_ref: Optional[str] = None
    target_ref: Optional[str] = None

    # Category-specific observable features ONLY (no labels, no ground truth).
    features: Dict[str, Any] = Field(default_factory=dict)

    # Ground truth maintained separately from features.
    ground_truth_label: int = Field(..., ge=0, le=1)  # 0=benign, 1=attack
    ground_truth_source: GroundTruthSource = GroundTruthSource.SCENARIO_DESIGN

    repetition: int = Field(default=1, ge=1, le=MAX_EVENT_COUNT)


class ExpectedOutcome(BaseModel):
    """Trusted expectation the evaluation compares detections against."""

    model_config = ConfigDict(extra="forbid")

    # Detection labels the scenario *should* trigger (from rule/ML engine), if any.
    expected_detection_labels: List[str] = Field(default_factory=list, max_length=MAX_EXPECTED_DETECTIONS)
    # Whether the scenario is fundamentally malicious (drives TP/FN vs FP/TN).
    is_malicious: bool
    rationale: str = Field(..., min_length=1, max_length=500)


class GenerationProvenance(BaseModel):
    """Provenance of how the spec was produced (LLM proposal or deterministic)."""

    model_config = ConfigDict(extra="forbid")

    generator_version: str = Field(..., min_length=1, max_length=32)
    source: str = Field(..., min_length=1, max_length=32)  # "llm" | "deterministic"
    model: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    request_correlation_id: Optional[str] = None
    llm_input_sha256: Optional[str] = Field(default=None, description="SHA-256 of the analyst prompt (never the raw prompt).")


# ==========================================
# Top-level scenario specification
# ==========================================

class ScenarioSpec(BaseModel):
    """The versioned, strict, bounded scenario proposal.

    A ScenarioSpec is a *plan*. It carries no executable code and cannot choose
    endpoints or functions. Downstream services validate references, safety and
    feasibility (M2), then deterministically compile it into telemetry (M3).
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCENARIO_SPEC_SCHEMA_VERSION
    scenario_id: str = Field(..., min_length=1, max_length=128)
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=1000)

    attack_category: AttackCategory
    intensity: Intensity = Intensity.MEDIUM

    duration_seconds: int = Field(..., ge=MIN_DURATION_SECONDS, le=MAX_DURATION_SECONDS)
    event_count: int = Field(..., ge=MIN_EVENT_COUNT, le=MAX_EVENT_COUNT)
    seed: int = Field(..., description="Deterministic seed for reproducible telemetry.")

    stages: List[ScenarioStage] = Field(..., min_length=1, max_length=MAX_STAGES)
    event_templates: List[EventTemplate] = Field(..., min_length=1, max_length=MAX_EVENT_TEMPLATES)
    entity_templates: List[EntityTemplate] = Field(default_factory=list, max_length=MAX_ENTITY_TEMPLATES)

    expected_outcomes: List[ExpectedOutcome] = Field(..., min_length=1)
    evaluation_objective: str = Field(..., min_length=1, max_length=500)

    ground_truth_source: GroundTruthSource = GroundTruthSource.SCENARIO_DESIGN
    dataset_role: DatasetRole = DatasetRole.VALIDATION

    benign_to_malicious_ratio: Optional[float] = Field(
        default=None, ge=0.0, le=1.0,
        description="Fraction of generated events that should be benign (0.0-1.0).",
    )

    generation_provenance: GenerationProvenance

    # ---- field validators ----

    @field_validator("schema_version")
    @classmethod
    def _check_schema_version(cls, v: str) -> str:
        if v != SCENARIO_SPEC_SCHEMA_VERSION:
            raise ValueError(f"Unsupported schema_version '{v}' (expected '{SCENARIO_SPEC_SCHEMA_VERSION}')")
        return v

    @field_validator("attack_category", mode="before")
    @classmethod
    def _check_supported_category(cls, v: Any) -> Any:
        # Reject unknown categories with a clear message before enum coercion.
        val = v.value if isinstance(v, AttackCategory) else v
        if not is_supported_category(str(val)):
            supported = sorted(c.value for c in AttackCategory)
            raise ValueError(f"Unsupported attack_category '{v}'. Supported: {supported}")
        return v

    @field_validator("event_templates")
    @classmethod
    def _check_event_count_consistency(cls, templates: List[EventTemplate], info) -> List[EventTemplate]:
        # Total planned events (sum of repetitions) must not exceed the declared
        # event_count upper bound.
        total = sum(t.repetition for t in templates)
        declared = info.data.get("event_count")
        if declared is not None and total > declared:
            raise ValueError(
                f"Sum of event template repetitions ({total}) exceeds declared event_count ({declared})"
            )
        return templates

    # ---- model validator (cross-field reference integrity) ----

    @model_validator(mode="after")
    def _validate_references_and_routing(self) -> "ScenarioSpec":
        # 1. Unique IDs
        stage_ids = [s.stage_id for s in self.stages]
        if len(stage_ids) != len(set(stage_ids)):
            raise ValueError("Duplicate stage_id values in scenario")
        template_ids = [t.template_id for t in self.event_templates]
        if len(template_ids) != len(set(template_ids)):
            raise ValueError("Duplicate event template_id values in scenario")
        entity_ids = [e.entity_id for e in self.entity_templates]
        if len(entity_ids) != len(set(entity_ids)):
            raise ValueError("Duplicate entity_template entity_id values in scenario")

        stage_id_set = set(stage_ids)
        entity_id_set = set(entity_ids)

        # 2. Stage dependency references resolve
        for s in self.stages:
            for dep in s.depends_on:
                if dep not in stage_id_set:
                    raise ValueError(f"Stage '{s.stage_id}' depends on unknown stage '{dep}'")

        # 3. Stage dependency graph must be acyclic
        _assert_stages_acyclic(self.stages)

        # 4. Event template references resolve (stage, entities)
        allowed_event_cats = CATEGORY_ALLOWED_EVENT_CATEGORIES[self.attack_category]
        for t in self.event_templates:
            if t.stage_id not in stage_id_set:
                raise ValueError(f"Event template '{t.template_id}' references unknown stage '{t.stage_id}'")
            if t.source_ref is not None and t.source_ref not in entity_id_set:
                raise ValueError(f"Event template '{t.template_id}' references unknown source entity '{t.source_ref}'")
            if t.target_ref is not None and t.target_ref not in entity_id_set:
                raise ValueError(f"Event template '{t.template_id}' references unknown target entity '{t.target_ref}'")
            # 5. Correct detector routing: only allow category-appropriate event types
            if t.event_category not in allowed_event_cats:
                raise ValueError(
                    f"Event template '{t.template_id}' emits '{t.event_category.value}' which is not valid "
                    f"for attack_category '{self.attack_category.value}' (allowed: "
                    f"{sorted(c.value for c in allowed_event_cats)})"
                )

        # 6. Planned stage references to templates resolve
        template_id_set = set(template_ids)
        for s in self.stages:
            for tid in s.planned_event_template_ids:
                if tid not in template_id_set:
                    raise ValueError(f"Stage '{s.stage_id}' plans unknown event template '{tid}'")

        # 7. At least one template must be non-unverified ground truth to be evaluable,
        #    otherwise all labels must be flagged UNVERIFIED (excluded from training).
        if self.dataset_role == DatasetRole.TRAINING:
            if any(t.ground_truth_source == GroundTruthSource.UNVERIFIED for t in self.event_templates):
                raise ValueError("Training-role datasets may not contain UNVERIFIED ground-truth labels")

        return self


def _assert_stages_acyclic(stages: List[ScenarioStage]) -> None:
    """Iterative DFS cycle detection over the stage dependency graph."""
    deps = {s.stage_id: set(s.depends_on) for s in stages}
    visiting: set = set()
    visited: set = set()

    def visit(node: str, path: List[str]) -> None:
        if node in visited:
            return
        if node in visiting:
            raise ValueError(f"Cyclic stage dependency detected: {' -> '.join(path + [node])}")
        visiting.add(node)
        for dep in deps.get(node, set()):
            visit(dep, path + [node])
        visiting.discard(node)
        visited.add(node)

    for sid in deps:
        visit(sid, [])
