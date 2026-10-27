"""Recommendation Validator (spec sections 3.C and 5).

Grounds every LLM-produced recommendation against the persisted, sanitized
evidence context before it may be stored. The model is never trusted to have
told the truth about identifiers, features or capabilities — this module checks.

Rejection rules (a failing recommendation is dropped, never persisted):
    * ``attack_category`` must be a supported category present in the context.
    * Every ``evidence_refs[].id`` must be a referenceable id from the context.
    * Every ``required_features`` entry must exist in the registered feature
      schema for the task (empty feature list is fine; a fabricated one is not).
    * ``MODEL_RETRAINING`` requires a supported ML task (heuristic-only
      categories such as phishing_url cannot request retraining).
    * Prompt-injection markers in free-text fields cause the recommendation to
      be dropped: instructions embedded in event/analyst content never override
      the analysis policy (spec sections 5 and 13).

``INSUFFICIENT_EVIDENCE`` is always allowed and is the correct output whenever
the model cannot ground a stronger claim.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from app.services.adaptive_learning.recommendation_schema import (
    RecommendationDraft,
    RecommendationType,
)

# Conservative instruction-override markers. A recommendation containing these is
# treated as a prompt-injection attempt and dropped rather than repaired.
_INJECTION_MARKERS = (
    "ignore previous",
    "ignore all previous",
    "disregard the",
    "override the system",
    "system prompt",
    "you are now",
    "new instructions:",
    "reveal your instructions",
)


def _contains_injection(text: str) -> bool:
    lowered = (text or "").lower()
    return any(marker in lowered for marker in _INJECTION_MARKERS)


def validate_draft(
    draft: RecommendationDraft,
    context: Dict[str, Any],
) -> Tuple[bool, str]:
    """Return ``(ok, reason)`` for a single draft against the evidence context."""
    referenceable = set(context.get("referenceable_ids", []))
    supported = set(context.get("supported_categories", []))
    registered_features = set(context.get("registered_features", []))
    ml_task = context.get("ml_task")
    heuristic_only = bool(context.get("is_heuristic_only"))

    # 1. Prompt-injection guard on free text.
    for field_value in (draft.summary, draft.hypothesis, draft.proposed_change):
        if field_value and _contains_injection(field_value):
            return False, "recommendation text contains an instruction-override marker (possible prompt injection)."

    # 2. Attack category must be supported and match the analyzed dataset.
    ctx_category = context.get("dataset", {}).get("attack_category")
    if draft.attack_category not in supported:
        return False, f"unsupported attack_category '{draft.attack_category}'."
    if ctx_category and draft.attack_category != ctx_category:
        # The recommendation must be about the category that was actually evaluated.
        return False, "recommendation category does not match the analyzed dataset category."

    # 3. Evidence references must resolve to real, persisted identifiers.
    #    INSUFFICIENT_EVIDENCE is the honest "I cannot conclude" output and is
    #    allowed to carry no evidence refs at all.
    if draft.recommendation_type != RecommendationType.INSUFFICIENT_EVIDENCE:
        if not draft.evidence_refs:
            return False, "recommendation provides no evidence references."
    for ref in draft.evidence_refs:
        if ref.id not in referenceable:
            return False, f"evidence reference id '{ref.id}' (kind={ref.kind.value}) is not a known record."

    # 4. Required features must exist in the registered schema (no invention).
    if ml_task is not None:
        for feat in draft.required_features:
            if feat not in registered_features:
                return False, f"required feature '{feat}' is not in the registered feature schema."

    # 5. Capability gating: cannot ask for ML retraining on a heuristic-only path.
    if draft.recommendation_type == RecommendationType.MODEL_RETRAINING:
        if heuristic_only or ml_task is None:
            return False, "category is heuristic-only and cannot be ML-retrained."

    return True, ""


def validate_recommendations(
    drafts: List[RecommendationDraft],
    context: Dict[str, Any],
) -> Tuple[List[RecommendationDraft], List[Dict[str, str]], List[str]]:
    """Split drafts into accepted and rejected, and emit corrections for repair.

    Returns ``(accepted, rejected, corrections)`` where ``corrections`` are
    human-readable messages the analyst layer can feed back to the model on a
    bounded repair attempt.
    """
    accepted: List[RecommendationDraft] = []
    rejected: List[Dict[str, str]] = []
    corrections: List[str] = []

    for draft in drafts:
        ok, reason = validate_draft(draft, context)
        if ok:
            accepted.append(draft)
        else:
            rejected.append(
                {"recommendation_type": draft.recommendation_type.value, "reason": reason}
            )
            corrections.append(
                f"Recommendation of type {draft.recommendation_type.value} was rejected: {reason} "
                "Re-issue it only with real, context-provided evidence ids and registered features, "
                "or return a single INSUFFICIENT_EVIDENCE recommendation."
            )

    return accepted, rejected, corrections
