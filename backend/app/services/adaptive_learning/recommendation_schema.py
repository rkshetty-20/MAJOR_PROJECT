"""Strict structured-recommendation schema (spec section 5).

The LLM returns a :class:`RecommendationDraft` describing *only* the fields it is
allowed to author. Server-owned identity, status and timestamp fields live on
:class:`Recommendation`, which is built by the persistence layer after the draft
passes the :mod:`app.services.adaptive_learning.validator`. This split makes it
impossible for the model to invent ids, forge a decision, or set its own status.

Every model here rejects unknown fields (``extra="forbid"``) so a malformed or
over-specified provider response fails closed.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ==========================================
# Controlled enums (single source of truth)
# ==========================================

class RecommendationType(str, enum.Enum):
    """The only recommendation kinds the system understands."""

    DATA_QUALITY = "DATA_QUALITY"
    FEATURE_REVIEW = "FEATURE_REVIEW"
    THRESHOLD_EXPERIMENT = "THRESHOLD_EXPERIMENT"
    RULE_REVIEW = "RULE_REVIEW"
    MODEL_RETRAINING = "MODEL_RETRAINING"
    MODEL_EVALUATION = "MODEL_EVALUATION"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class AnalysisMode(str, enum.Enum):
    """The six analysis operations from spec section 4."""

    MISSED_DETECTION = "MISSED_DETECTION"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    DATASET_QUALITY = "DATASET_QUALITY"
    FEATURE_IMPROVEMENT = "FEATURE_IMPROVEMENT"
    MODEL_EVALUATION = "MODEL_EVALUATION"
    NEXT_EXPERIMENT = "NEXT_EXPERIMENT"


class EvidenceKind(str, enum.Enum):
    """Entity types a recommendation may cite as supporting evidence."""

    EVALUATION_RUN = "evaluation_run"
    DATASET = "dataset"
    EVENT = "event"
    MODEL_VERSION = "model_version"
    LEARNING_EXAMPLE = "learning_example"


class Confidence(str, enum.Enum):
    """Qualitative LLM self-report. NOT a calibrated probability of correctness."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RecommendationStatus(str, enum.Enum):
    """Server-assigned lifecycle state (approve/reject arrives in Milestone 2)."""

    PENDING_REVIEW = "pending_review"


class ProviderStatus(str, enum.Enum):
    """Outcome of the provider interaction for graceful UI degradation."""

    OK = "ok"
    UNAVAILABLE = "unavailable"
    INVALID = "invalid"


# ==========================================
# Evidence reference
# ==========================================

class EvidenceRef(BaseModel):
    """A pointer to a persisted record. The ``id`` is validated against the DB."""

    model_config = ConfigDict(extra="forbid")

    kind: EvidenceKind
    id: str = Field(..., min_length=1, max_length=128)
    detail: Optional[str] = Field(default=None, max_length=500)


# ==========================================
# LLM-authored draft (no server-owned fields)
# ==========================================

class RecommendationDraft(BaseModel):
    """What the LLM is allowed to produce for a single recommendation.

    Deliberately omits ``recommendation_id``, ``analysis_run_id``, ``status`` and
    ``created_at``: those are assigned by the server, never the model.
    """

    model_config = ConfigDict(extra="forbid")

    attack_category: str = Field(..., min_length=1, max_length=64)
    recommendation_type: RecommendationType
    summary: str = Field(..., min_length=1, max_length=1000)
    evidence_refs: List[EvidenceRef] = Field(default_factory=list)
    hypothesis: Optional[str] = Field(default=None, max_length=2000)
    confidence: Confidence = Confidence.LOW
    proposed_change: Optional[str] = Field(default=None, max_length=2000)
    required_features: List[str] = Field(default_factory=list)
    required_data: Optional[str] = Field(default=None, max_length=2000)
    expected_benefit: Optional[str] = Field(default=None, max_length=2000)
    potential_risks: Optional[str] = Field(default=None, max_length=2000)
    validation_plan: Optional[str] = Field(default=None, max_length=2000)


class AnalysisDraft(BaseModel):
    """Top-level JSON object the LLM must return for an analysis request."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(..., min_length=1, max_length=2000)
    findings: List[str] = Field(default_factory=list)
    recommendations: List[RecommendationDraft] = Field(default_factory=list)


# ==========================================
# Server-assembled persisted recommendation
# ==========================================

class Recommendation(BaseModel):
    """A validated recommendation with server-assigned identity fields."""

    model_config = ConfigDict(extra="forbid")

    recommendation_id: str
    analysis_run_id: str
    attack_category: str
    recommendation_type: RecommendationType
    summary: str
    evidence_refs: List[EvidenceRef] = Field(default_factory=list)
    hypothesis: Optional[str] = None
    confidence: Confidence = Confidence.LOW
    proposed_change: Optional[str] = None
    required_features: List[str] = Field(default_factory=list)
    required_data: Optional[str] = None
    expected_benefit: Optional[str] = None
    potential_risks: Optional[str] = None
    validation_plan: Optional[str] = None
    status: RecommendationStatus = RecommendationStatus.PENDING_REVIEW
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_draft(
        cls,
        draft: RecommendationDraft,
        *,
        recommendation_id: str,
        analysis_run_id: str,
    ) -> "Recommendation":
        return cls(
            recommendation_id=recommendation_id,
            analysis_run_id=analysis_run_id,
            **draft.model_dump(),
        )


class AnalysisReport(BaseModel):
    """The structured result returned to the caller/UI for one analysis run."""

    model_config = ConfigDict(extra="forbid")

    analysis_run_id: str
    evaluation_run_id: str
    mode: AnalysisMode
    summary: str
    findings: List[str] = Field(default_factory=list)
    recommendations: List[Recommendation] = Field(default_factory=list)
    model: Optional[str] = None
    correlation_id: Optional[str] = None
    provider_status: ProviderStatus = ProviderStatus.OK
