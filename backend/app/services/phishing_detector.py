"""Backward-compatible façade over :mod:`app.services.phishing`.

Until stage E this module was a 958-line monolith that mixed the indicator
registry, the URL lexicon, the email and spear-phishing scorers, dead imports
(``httpx``, ``os``, ``base64``, ``time``, ``unquote``) and an unreferenced
"URL reputation" cache. It now re-exports the split package so that every
historical import path keeps working:

* ``extract_phishing_features`` - lexical feature vector (superset of the old
  twelve keys; see ``app.services.phishing.url_features``).
* ``evaluate_phishing_url`` - the historical
  ``(is_phishing, confidence, features, explanation, triggered_rules)`` tuple.
* ``evaluate_url_phishing`` - tiered classification (legitimate / suspicious /
  phishing) including the two extended redirection and TLD indicators.
* ``evaluate_email_phishing`` / ``evaluate_spear_phishing`` - message scorers.

Behavioural changes introduced here are recorded, with measurements, in
``REQUIREMENTS_TRACEABILITY.md`` and pinned by
``backend/tests/test_phishing_lexical.py`` and the golden replay in
``backend/tests/test_phishing_golden_replay.py``.

Nothing in this package performs network I/O: no URL is fetched, no DNS lookup
is resolved, and no reputation provider is contacted - there is no reputation
integration in this project at all, only a fixed "unavailable" statement.
"""

from __future__ import annotations

from app.services.phishing import (
    ALL_INDICATORS,
    CONFIDENCE_CAP,
    CORE_INDICATOR_COUNT,
    EXTENDED_INDICATORS,
    LEXICAL_INDICATORS,
    MAX_SINGLE_INDICATOR_CONTRIBUTION,
    MalformedURLError,
    PHISHING_THRESHOLD,
    SCORER_NAME,
    SCORER_VERSION,
    SUSPICIOUS_THRESHOLD,
    evaluate_email_phishing,
    evaluate_phishing_url,
    evaluate_spear_phishing,
    evaluate_url_phishing,
    extract_email_address,
    extract_features,
    indicator_spec,
    list_indicators,
    provenance,
    registry_summary,
    saturate,
    score_url,
    summarise_indicators,
)

#: Historical spelling of :func:`app.services.phishing.extract_features`.
extract_phishing_features = extract_features

__all__ = [
    "ALL_INDICATORS",
    "CONFIDENCE_CAP",
    "CORE_INDICATOR_COUNT",
    "EXTENDED_INDICATORS",
    "LEXICAL_INDICATORS",
    "MAX_SINGLE_INDICATOR_CONTRIBUTION",
    "MalformedURLError",
    "PHISHING_THRESHOLD",
    "SCORER_NAME",
    "SCORER_VERSION",
    "SUSPICIOUS_THRESHOLD",
    "evaluate_email_phishing",
    "evaluate_phishing_url",
    "evaluate_spear_phishing",
    "evaluate_url_phishing",
    "extract_email_address",
    "extract_features",
    "extract_phishing_features",
    "indicator_spec",
    "list_indicators",
    "provenance",
    "registry_summary",
    "saturate",
    "score_url",
    "summarise_indicators",
]
