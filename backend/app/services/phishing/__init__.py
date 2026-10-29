"""Offline lexical phishing scoring package.

Stage E split the 958-line ``app.services.phishing_detector`` monolith into
declared layers:

* :mod:`app.services.phishing.contract` - the machine-checked indicator registry,
  weights, thresholds, cap and provenance statement.
* :mod:`app.services.phishing.url_features` - safe, network-free lexical feature
  extraction with a documented malformed-input rejection contract.
* :mod:`app.services.phishing.scorer` - indicator fusion for a single URL, plus
  the historical five-tuple and tiered entry points.
* :mod:`app.services.phishing.email_scorer` - message-level indicators.
* :mod:`app.services.phishing.spear_scorer` - targeted/BEC message indicators.

``app.services.phishing_detector`` re-exports this package unchanged, so every
existing import path and response shape keeps working.
"""

from __future__ import annotations

from app.services.phishing.url_features import (
    FEATURE_PRODUCER_KEYS,
    MalformedURLError,
    VALID_REASONS,
    extract_features,
)
from app.services.phishing.contract import (
    ALL_INDICATORS,
    CONFIDENCE_CAP,
    CORE_INDICATOR_COUNT,
    EXTENDED_INDICATORS,
    LEXICAL_INDICATORS,
    MAX_SINGLE_INDICATOR_CONTRIBUTION,
    PHISHING_THRESHOLD,
    SCORER_NAME,
    SCORER_VERSION,
    SUSPICIOUS_THRESHOLD,
    classify,
    indicator_spec,
    list_indicators,
    provenance,
    registry_summary,
    saturate,
    validate_against_extractor,
)
from app.services.phishing.scorer import (
    evaluate_phishing_url,
    evaluate_url_phishing,
    score_url,
    summarise_indicators,
)
from app.services.phishing.email_scorer import evaluate_email_phishing, extract_email_address
from app.services.phishing.spear_scorer import evaluate_spear_phishing

# The registry's own consistency is checked while ``contract`` is imported; this
# second pass compares it with the extractor now that both modules are loaded, so
# an indicator reading a feature nothing produces fails at import time.
validate_against_extractor(FEATURE_PRODUCER_KEYS)

__all__ = [
    "ALL_INDICATORS",
    "CONFIDENCE_CAP",
    "CORE_INDICATOR_COUNT",
    "EXTENDED_INDICATORS",
    "FEATURE_PRODUCER_KEYS",
    "LEXICAL_INDICATORS",
    "MAX_SINGLE_INDICATOR_CONTRIBUTION",
    "MalformedURLError",
    "PHISHING_THRESHOLD",
    "SCORER_NAME",
    "SCORER_VERSION",
    "SUSPICIOUS_THRESHOLD",
    "VALID_REASONS",
    "classify",
    "evaluate_email_phishing",
    "evaluate_phishing_url",
    "evaluate_spear_phishing",
    "evaluate_url_phishing",
    "extract_email_address",
    "extract_features",
    "indicator_spec",
    "list_indicators",
    "provenance",
    "registry_summary",
    "saturate",
    "score_url",
    "summarise_indicators",
    "validate_against_extractor",
]
