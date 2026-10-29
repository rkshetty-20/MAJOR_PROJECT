"""Deterministic lexical scoring of a URL.

The public surface is deliberately small:

* :func:`score_url` - the current, self-describing result (contract fields,
  evidence, provenance).
* :func:`evaluate_phishing_url` - the historical five-tuple kept for the
  behavioural rule engine and existing API consumers.
* :func:`evaluate_url_phishing` - the tiered response (legitimate /
  suspicious / phishing) used by ``POST /api/detect/url``.

Scoring is a sum of declared indicator weights, capped per indicator and then
capped in total at ``CONFIDENCE_CAP``. There is no model, no fitting and no
network call anywhere in this module.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from app.services.phishing.contract import (
    ALL_INDICATORS,
    CONFIDENCE_CAP,
    EXTENDED_INDICATORS,
    LEXICAL_INDICATORS,
    MAX_SINGLE_INDICATOR_CONTRIBUTION,
    PHISHING_THRESHOLD,
    SCORER_NAME,
    SCORER_VERSION,
    SUSPICIOUS_THRESHOLD,
    classify,
    fuse_contribution,
    indicator_spec,
    provenance,
    registry_summary,
    saturate,
)
from app.services.phishing.url_features import MalformedURLError, extract_features

__all__ = [
    "MalformedURLError",
    "evaluate_phishing_url",
    "evaluate_url_phishing",
    "indicator_spec",
    "registry_summary",
    "score_url",
    "summarise_indicators",
]


def _render(spec: Dict[str, Any], features: Dict[str, Any]) -> str:
    """Fill the explanation template from the measured features."""
    template = spec["explanation"]
    values = {}
    for key in spec["inputs"]:
        value = features.get(key)
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(item) for item in value)
        values[key] = value
    try:
        return template.format(**values)
    except (KeyError, IndexError):  # pragma: no cover - template/input drift
        return template


def _fired_indicator(spec: Dict[str, Any], features: Dict[str, Any], contribution: float) -> Dict[str, Any]:
    """One fired indicator, with both the legacy and the contract-shaped fields."""
    used = {key: features.get(key) for key in spec["inputs"]}
    return {
        # Legacy keys (unchanged shape, still consumed by the API response and UI)
        "id": spec["id"],
        "name": spec["name"],
        "explanation": _render(spec, features),
        "contribution": round(contribution, 4),
        "feature_values": dict(used),
        # Contract keys added in stage E
        "category": spec["category"],
        "version": spec["version"],
        "weight": spec["weight"],
        "weight_kind": spec["weight_kind"],
        "severity": spec["severity"],
        "matching": spec["matching"],
        "inputs_used": sorted(spec["inputs"]),
        "mitre_attack": spec["mitre"],
    }


def score_url(url: str, include_extended: bool = False) -> Dict[str, Any]:
    """Score one URL and return a fully self-describing verdict.

    Raises :class:`MalformedURLError` (a ``ValueError``) for inputs that cannot
    be analysed; ``.reason`` is one of the codes declared in
    :mod:`app.services.phishing.url_features`.
    """
    features = extract_features(url)

    raw_score = 0.0
    fired: List[Dict[str, Any]] = []
    registry = dict(LEXICAL_INDICATORS)
    if include_extended:
        # Both extended specs join the evaluated set whenever the tiered view is
        # requested. Their predicates gate on the measured features, so this
        # changes no score - it only makes ``evaluated_indicators`` the honest
        # count of specs consulted (12) instead of a number that moved with the
        # input shape.
        registry.update(EXTENDED_INDICATORS)

    for spec in registry.values():
        if not spec["predicate"](features):
            continue
        contribution = fuse_contribution(spec, features)
        if contribution <= 0:
            continue
        raw_score += contribution
        fired.append(_fired_indicator(spec, features, contribution))

    confidence = saturate(raw_score)

    return {
        "url": features["url"],
        "verdict": classify(confidence),
        "is_phishing": confidence >= PHISHING_THRESHOLD,
        "confidence": confidence,
        "raw_indicator_sum": round(raw_score, 4),
        "features": features,
        "indicators": fired,
        "evaluated_indicators": len(registry),
        "thresholds": {"phishing": PHISHING_THRESHOLD, "suspicious": SUSPICIOUS_THRESHOLD},
        "confidence_cap": CONFIDENCE_CAP,
        "max_single_indicator_contribution": MAX_SINGLE_INDICATOR_CONTRIBUTION,
        "scorer": SCORER_NAME,
        "version": SCORER_VERSION,
        "provenance": provenance(),
    }


def _explain(result: Dict[str, Any]) -> str:
    """Human-readable summary: the verdict head followed by each fired indicator.

    ``join`` rather than string concatenation, so a URL that fires no indicator
    gets "URL appears benign." with no trailing separator whitespace.
    """
    reasons = [item["explanation"] for item in result["indicators"]]
    if result["is_phishing"]:
        head = "Suspicious URL identified."
    else:
        head = "URL appears benign."
    return " ".join([head] + reasons)


def evaluate_phishing_url(url: str) -> Tuple[bool, float, Dict[str, Any], str, List[Dict[str, Any]]]:
    """Historical entry point: ``(is_phishing, confidence, features, explanation, rules)``.

    Kept signature-compatible for ``app.services.rule_engine`` and
    ``POST /api/detect/phishing``. ``url`` is echoed inside the feature dict, so
    callers that print features still see the analysed value.
    """
    result = score_url(url)
    features = dict(result["features"])
    # ``host``/``url`` are new keys; the original feature dict had no host field,
    # so the legacy view keeps every pre-existing key and adds the new ones.
    return (
        result["is_phishing"],
        result["confidence"],
        features,
        _explain(result),
        result["indicators"],
    )


def evaluate_url_phishing(url: str) -> Dict[str, Any]:
    """Tiered classification with the extended redirection/TLD indicators."""
    result = score_url(url, include_extended=True)
    features = result["features"]
    confidence = result["confidence"]
    classification = result["verdict"]
    rules = result["indicators"]

    explanation = (
        f"Classified as {classification.upper()} (score: {int(confidence * 100)}/100). "
        + _explain(result)
    )

    return {
        "url": result["url"],
        "classification": classification,
        "is_phishing": result["is_phishing"],
        "confidence": confidence,
        "risk_score": int(round(confidence * 100)),
        "explanation": explanation.strip(),
        "features": features,
        "triggered_rules": rules,
        "scorer": {"name": SCORER_NAME, "version": SCORER_VERSION},
        "provenance": result["provenance"],
    }


def summarise_indicators() -> Dict[str, Any]:
    """Registry view used by ``GET /api/detect/phishing/indicators``."""
    summary = registry_summary()
    summary["indicators"] = [
        {
            **indicator_spec(indicator_id),
            "core": indicator_id in LEXICAL_INDICATORS,
            "extended": indicator_id in EXTENDED_INDICATORS,
        }
        for indicator_id in ALL_INDICATORS
    ]
    summary["provenance"] = provenance()
    return summary
