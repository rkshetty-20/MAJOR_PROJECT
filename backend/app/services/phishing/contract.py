"""Contract for the phishing lexical scorer.

Everything the scorer can claim about itself lives here: the indicator
registry, the weights, the thresholds, the cap and the provenance statement.
The registry is validated at import time, so "10 weighted lexical indicators"
is a machine-checked fact rather than a number printed in a document.

The scorer is a deterministic lexical/structural scorer. It is **not** a
trained classifier, nothing here is fitted to a labelled dataset, and no
accuracy, precision or recall figure is published for it - see
``SCORER_PROVENANCE``.
"""

from __future__ import annotations

import string
from typing import Any, Callable, Dict, List, Optional

SCORER_NAME = "phishing-lexical-scorer"

#: 1.0.0 shipped the inline ``if`` chain. This implementation keeps the same
#: published weights but declares them as data, tightens the matching logic
#: (word-boundary keyword matching, IDN-aware homographs, obfuscated IP host
#: forms) and makes malformed input a documented rejection instead of a crash.
SCORER_VERSION = "1.1.0"

# ---------------------------------------------------------------------------
# Scoring policy
# ---------------------------------------------------------------------------
CONFIDENCE_CAP = 0.99
PHISHING_THRESHOLD = 0.65
SUSPICIOUS_THRESHOLD = 0.35
SEVERITY_ORDER = ("low", "medium", "high", "critical")

#: Credibility of a single indicator. ``rule_suspicious_keywords`` is the only
#: weighted-by-count indicator; without this guard ten keyword tokens alone
#: (2.0) saturate the whole score, which is how a legitimate login URL gets a
#: 99 % verdict. The cap keeps every verdict corroborated by at least two
#: independent signals before the score reaches the ceiling.
MAX_SINGLE_INDICATOR_CONTRIBUTION = 0.60

# ---------------------------------------------------------------------------
# Indicator vocabulary
# ---------------------------------------------------------------------------
INDICATOR_FIELDS = (
    "id",
    "name",
    "category",
    "version",
    "weight",
    "weight_kind",
    "inputs",
    "matching",
    "severity",
    "predicate",
    "explanation",
    "mitre",
)

INDICATOR_CATEGORIES = ("protocol", "host-shape", "lexical", "identity", "redirection")

#: Credential-oriented vocabulary. Each entry is a canonical keyword plus the
#: inflected forms that count as the same signal. Matching is on URL tokens
#: split at non-alphanumeric boundaries, never on raw substrings, so ``auth``
#: does not fire inside ``authorised`` and ``secure`` does not fire inside
#: ``insecure``.
SUSPICIOUS_KEYWORDS: Dict[str, tuple] = {
    "verify": ("verify", "verifies", "verified", "verifying", "verification"),
    "account": ("account", "accounts"),
    "login": ("login", "log-in", "signin", "sign-in", "logon"),
    "secure": ("secure",),
    "update": ("update", "updates", "updated"),
    "banking": ("banking",),
    "support": ("support",),
    "password": ("password", "passwords", "passwd"),
    "auth": ("auth", "authenticate", "authentication", "authorization"),
    "confirm": ("confirm", "confirmation", "confirming"),
}

#: Brands whose name inside a subdomain label is a deception signal.
TARGETED_BRANDS: tuple = (
    "paypal",
    "google",
    "apple",
    "microsoft",
    "amazon",
    "netflix",
    "facebook",
)

#: TLDs with a documented history of bulk registration in phishing campaigns.
#: Used only by the extended indicator, and deliberately a list rather than a
#: "suspiciousness" judgement about the TLD itself.
HIGH_ABUSE_TLDS: tuple = (
    ".xyz",
    ".top",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".buzz",
    ".club",
    ".work",
    ".fit",
    ".surf",
    ".monster",
    ".icu",
)

#: Query-parameter names that indicate a redirect target, i.e. a link whose
#: visible host is not the destination the user reaches.
REDIRECT_PARAMETERS: tuple = (
    "url",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "next",
    "return",
    "return_to",
    "dest",
    "destination",
    "target",
    "r",
    "goto",
    "link",
)

# ---------------------------------------------------------------------------
# Thresholds (declared here so tests can assert boundary semantics exactly)
# ---------------------------------------------------------------------------
LONG_URL_MIN_LENGTH = 75  # indicator fires when url_length > this
SPECIAL_CHARS_MIN_COUNT = 5  # indicator fires when special_chars > this
MANY_SUBDOMAINS_MIN_COUNT = 3  # indicator fires when num_subdomains >= this
STANDARD_PORTS: tuple = (80, 443)
SPECIAL_CHARS_ALPHABET = "-_@?=&%"


def _indicator(
    *,
    id: str,
    name: str,
    category: str,
    weight: float,
    inputs: tuple,
    matching: str,
    severity: str,
    predicate: Callable[[Dict[str, Any]], bool],
    explanation: str,
    mitre: str,
    weight_kind: str = "flat",
    version: str = SCORER_VERSION,
) -> Dict[str, Any]:
    return {
        "id": id,
        "name": name,
        "category": category,
        "version": version,
        "weight": weight,
        "weight_kind": weight_kind,
        "inputs": inputs,
        "matching": matching,
        "severity": severity,
        "predicate": predicate,
        "explanation": explanation,
        "mitre": mitre,
    }


# ---------------------------------------------------------------------------
# The 10 core lexical indicators
# ---------------------------------------------------------------------------
#: Weights and behaviour are unchanged from the pre-stage-E implementation;
#: only the *matching logic* of three indicators was corrected (see
#: ``REQUIREMENTS_TRACEABILITY.md`` for the recorded deltas).
LEXICAL_INDICATORS: Dict[str, Dict[str, Any]] = {
    spec["id"]: spec
    for spec in [
        _indicator(
            id="rule_ip_host",
            name="IP Address Hostname",
            category="host-shape",
            weight=0.40,
            inputs=("is_ip",),
            matching="host is an IPv4/IPv6 literal, including decimal, hexadecimal "
            "and invalid-octet dotted forms that browsers still resolve",
            severity="high",
            predicate=lambda f: bool(f["is_ip"]),
            explanation="Uses an IP address instead of a hostname.",
            mitre="T1566.002",
        ),
        _indicator(
            id="rule_no_https",
            name="Insecure Protocol",
            category="protocol",
            weight=0.20,
            inputs=("is_https",),
            matching="scheme is not https://",
            severity="medium",
            predicate=lambda f: not f["is_https"],
            explanation="Does not use secure HTTPS.",
            mitre="T1566.002",
        ),
        _indicator(
            id="rule_suspicious_keywords",
            name="Suspicious Keywords",
            category="lexical",
            weight=0.20,
            weight_kind="per_match",
            inputs=("keyword_count", "matched_keywords"),
            matching="count of distinct credential-harvesting keywords matched on "
            "URL token boundaries, contributing 0.20 each up to "
            f"{MAX_SINGLE_INDICATOR_CONTRIBUTION:.2f}",
            severity="medium",
            predicate=lambda f: f["keyword_count"] > 0,
            explanation="Contains {keyword_count} suspicious or credential-harvesting "
            "keywords ({matched_keywords}).",
            mitre="T1566.002",
        ),
        _indicator(
            id="rule_many_subdomains",
            name="Excessive Subdomains",
            category="host-shape",
            weight=0.15,
            inputs=("num_subdomains",),
            matching=f"num_subdomains >= {MANY_SUBDOMAINS_MIN_COUNT}",
            severity="medium",
            predicate=lambda f: f["num_subdomains"] >= MANY_SUBDOMAINS_MIN_COUNT,
            explanation="Has an unusually high number of subdomains ({num_subdomains}).",
            mitre="T1566.002",
        ),
        _indicator(
            id="rule_long_url",
            name="Long URL",
            category="lexical",
            weight=0.10,
            inputs=("url_length",),
            matching=f"url_length > {LONG_URL_MIN_LENGTH}",
            severity="low",
            predicate=lambda f: f["url_length"] > LONG_URL_MIN_LENGTH,
            explanation="URL length is unusually long ({url_length} characters).",
            mitre="T1566.002",
        ),
        _indicator(
            id="rule_special_chars",
            name="Many Special Characters",
            category="lexical",
            weight=0.10,
            inputs=("special_chars",),
            matching=f"special_chars > {SPECIAL_CHARS_MIN_COUNT} "
            f"over alphabet {''.join(sorted(SPECIAL_CHARS_ALPHABET))}",
            severity="low",
            predicate=lambda f: f["special_chars"] > SPECIAL_CHARS_MIN_COUNT,
            explanation="Contains many special characters, often used for obfuscation.",
            mitre="T1566.002",
        ),
        _indicator(
            id="rule_punycode",
            name="IDN / Punycode Homograph",
            category="host-shape",
            weight=0.30,
            inputs=("is_punycode", "non_ascii_host", "homograph_suspect"),
            matching="host contains a Punycode (xn--) label or a non-ASCII label that "
            "would be IDNA-encoded before resolution, i.e. a homograph vector",
            severity="high",
            predicate=lambda f: bool(f["is_punycode"]),
            explanation="Uses an internationalized hostname (Punycode xn-- or non-ASCII "
            "characters), which is common in homograph spoofing.",
            mitre="T1027.002",
        ),
        _indicator(
            id="rule_misleading_subdomain",
            name="Misleading Subdomain",
            category="identity",
            weight=0.35,
            inputs=("has_misleading_subdomain", "subdomain_labels"),
            matching="a targeted brand or a credential keyword appears in the subdomain "
            "labels while the registered domain is not that brand's own",
            severity="high",
            predicate=lambda f: bool(f["has_misleading_subdomain"]),
            explanation="Contains misleading brand names or keywords in subdomains.",
            mitre="T1656",
        ),
        _indicator(
            id="rule_credentials",
            name="Credentials in URL",
            category="identity",
            weight=0.30,
            inputs=("has_credentials",),
            matching="the authority component carries a userinfo part (user: or user:pass@)",
            severity="high",
            predicate=lambda f: bool(f["has_credentials"]),
            explanation="Contains credentials (username/password) embedded in the URL.",
            mitre="T1557",
        ),
        _indicator(
            id="rule_unusual_port",
            name="Unusual Port",
            category="protocol",
            weight=0.10,
            inputs=("unusual_port", "port"),
            matching=f"an explicit port outside {STANDARD_PORTS} is present",
            severity="low",
            predicate=lambda f: bool(f["unusual_port"]),
            explanation="Connects to a non-standard HTTP/HTTPS port ({port}).",
            mitre="T1571",
        ),
    ]
}

# ---------------------------------------------------------------------------
# Extended indicators (added by the tiered URL module, not part of the 10)
# ---------------------------------------------------------------------------
EXTENDED_INDICATORS: Dict[str, Dict[str, Any]] = {
    spec["id"]: spec
    for spec in [
        _indicator(
            id="rule_open_redirect",
            name="Potential Open Redirect",
            category="redirection",
            weight=0.25,
            inputs=("open_redirect_detected", "redirect_targets"),
            matching="a known redirect parameter (or a /redirect|/out|/forward|/goto path) "
            "carries an absolute URL or protocol-relative target",
            severity="high",
            predicate=lambda f: bool(f.get("open_redirect_detected")),
            explanation="Contains URL redirection parameter.",
            mitre="T1566.002",
        ),
        _indicator(
            id="rule_suspicious_tld",
            name="Suspicious TLD",
            category="host-shape",
            weight=0.15,
            inputs=("suspicious_tld", "domain"),
            matching=f"registered domain ends in one of the {len(HIGH_ABUSE_TLDS)} "
            "bulk-registration TLDs with documented campaign abuse",
            severity="low",
            predicate=lambda f: bool(f.get("suspicious_tld")),
            explanation="Domain utilizes a TLD frequently leveraged in malicious campaigns.",
            mitre="T1583.001",
        ),
    ]
}

CORE_INDICATOR_COUNT = len(LEXICAL_INDICATORS)
EXTENDED_INDICATOR_COUNT = len(EXTENDED_INDICATORS)

# --------------------------------------------------------------------------
# Feature contract every core indicator must be able to read
# --------------------------------------------------------------------------
REQUIRED_FEATURE_KEYS = (
    "url_length",
    "num_subdomains",
    "special_chars",
    "is_ip",
    "is_https",
    "keyword_count",
    "is_punycode",
    "has_misleading_subdomain",
    "has_credentials",
    "unusual_port",
    "domain",
)

#: Produced for evidence and API compatibility but consumed by no indicator.
#: ``hostname_length`` is the deliberate example: the pre-stage-E scorer published
#: it as a "feature" although no weight depended on it, so the registry check in
#: :func:`_validate_registry` keeps that class of dead vocabulary visible instead
#: of letting it hide inside the required set.
EXTRA_FEATURE_KEYS = (
    "hostname_length",
    "non_ascii_host",
    "homograph_suspect",
    "ip_form",
    "matched_keywords",
    "subdomain_labels",
    "misleading_token",
    "port",
    "scheme",
    "path_depth",
    # Only consumed by the extended (tiered) indicators.
    "open_redirect_detected",
    "redirect_targets",
    "suspicious_tld",
)

ALL_INDICATORS: Dict[str, Dict[str, Any]] = {**LEXICAL_INDICATORS, **EXTENDED_INDICATORS}


class IndicatorContractError(RuntimeError):
    """Raised at import time when the registry is incomplete or inconsistent."""


def _template_placeholders(template: str) -> List[str]:
    """Field names an explanation template interpolates."""
    found: List[str] = []
    for _literal, field, _spec, _conv in string.Formatter().parse(template):
        if field:
            found.append(field.split(".")[0])
    return found


def _validate_indicator(spec: Dict[str, Any]) -> None:
    missing = [field for field in INDICATOR_FIELDS if field not in spec]
    if missing:
        raise IndicatorContractError(f"indicator {spec.get('id')!r} is missing fields {missing}")

    for field in ("id", "name", "category", "version", "matching", "severity", "explanation", "mitre"):
        value = spec[field]
        if not isinstance(value, str) or not value.strip():
            raise IndicatorContractError(f"indicator {spec['id']!r} field {field!r} must be a non-empty string")

    if not isinstance(spec["weight"], (int, float)) or not 0 < spec["weight"] <= 1:
        raise IndicatorContractError(f"indicator {spec['id']!r} weight must be in (0, 1]")
    if spec["weight_kind"] not in ("flat", "per_match"):
        raise IndicatorContractError(f"indicator {spec['id']!r} has an unknown weight_kind")
    if spec["category"] not in INDICATOR_CATEGORIES:
        raise IndicatorContractError(f"indicator {spec['id']!r} category {spec['category']!r} is not declared")
    if spec["severity"] not in SEVERITY_ORDER:
        raise IndicatorContractError(f"indicator {spec['id']!r} severity {spec['severity']!r} is not declared")
    if not callable(spec["predicate"]):
        raise IndicatorContractError(f"indicator {spec['id']!r} has no callable predicate")
    if not spec["inputs"]:
        raise IndicatorContractError(f"indicator {spec['id']!r} declares no inputs")

    declared = set(REQUIRED_FEATURE_KEYS) | set(EXTRA_FEATURE_KEYS)
    unknown = [key for key in spec["inputs"] if key not in declared]
    if unknown:
        raise IndicatorContractError(f"indicator {spec['id']!r} reads undeclared features {unknown}")

    # An explanation must only interpolate declared inputs, otherwise rendering it
    # silently falls back to the raw template and the analyst sees braces.
    templated = [field for field in _template_placeholders(spec["explanation"]) if field not in spec["inputs"]]
    if templated:
        raise IndicatorContractError(f"indicator {spec['id']!r} explanation interpolates undeclared inputs {templated}")


def _validate_registry() -> None:
    for registry, label in ((LEXICAL_INDICATORS, "core"), (EXTENDED_INDICATORS, "extended")):
        for spec in registry.values():
            try:
                _validate_indicator(spec)
            except IndicatorContractError as exc:
                raise IndicatorContractError(f"{label} registry: {exc}") from exc

    core_ids = list(LEXICAL_INDICATORS)
    if len(core_ids) != 10:
        raise IndicatorContractError(f"expected 10 core lexical indicators, found {len(core_ids)}")
    overlap = set(core_ids) & set(EXTENDED_INDICATORS)
    if overlap:
        raise IndicatorContractError(f"indicator ids appear in both registries: {sorted(overlap)}")


def validate_against_extractor(producer_keys) -> None:
    """Cross-check the registry against the feature extractor's output keys.

    This cannot run while ``contract`` is being imported (``url_features`` imports
    ``contract`` at module level, so the extractor module is still partially
    initialised), therefore the package ``__init__`` calls it immediately after
    both modules are loaded - i.e. still at import time for every real consumer,
    but without the cycle.
    """
    produced = set(producer_keys)

    # Every feature an indicator reads must actually be produced, otherwise the
    # indicator silently reads None and can never fire.
    consumed = {key for spec in ALL_INDICATORS.values() for key in spec["inputs"]}
    unproducible = sorted(consumed - produced)
    if unproducible:
        raise IndicatorContractError(f"indicators read features the extractor never produces: {unproducible}")

    unclaimed = sorted(set(REQUIRED_FEATURE_KEYS) - consumed)
    if unclaimed:
        raise IndicatorContractError(f"required features no indicator consumes (dead vocabulary): {unclaimed}")

    undeclared = sorted(consumed - set(REQUIRED_FEATURE_KEYS) - set(EXTRA_FEATURE_KEYS))
    if undeclared:
        raise IndicatorContractError(f"indicators read features missing from the declared vocabulary: {undeclared}")


def _producer_keys() -> tuple:
    """Extractor output keys, resolved lazily to avoid an import cycle."""
    from app.services.phishing.url_features import FEATURE_PRODUCER_KEYS  # local import: cycle

    return FEATURE_PRODUCER_KEYS


def indicator_spec(indicator_id: str) -> Dict[str, Any]:
    """Public getter returning a copy of one indicator's contract."""
    if indicator_id not in ALL_INDICATORS:
        raise KeyError(f"unknown indicator {indicator_id!r}")
    return _serialisable(ALL_INDICATORS[indicator_id])


def _serialisable(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Copy of a spec with the non-serialisable predicate removed."""
    out = dict(spec)
    out.pop("predicate", None)
    return out


def list_indicators(include_extended: bool = True) -> List[Dict[str, Any]]:
    specs = list(LEXICAL_INDICATORS.values())
    if include_extended:
        specs += list(EXTENDED_INDICATORS.values())
    return [_serialisable(spec) for spec in specs]


def registry_summary() -> Dict[str, Any]:
    categories: Dict[str, int] = {}
    for spec in ALL_INDICATORS.values():
        categories[spec["category"]] = categories.get(spec["category"], 0) + 1
    return {
        "scorer": SCORER_NAME,
        "version": SCORER_VERSION,
        "core_indicators": len(LEXICAL_INDICATORS),
        "extended_indicators": len(EXTENDED_INDICATORS),
        "declared_features": len(REQUIRED_FEATURE_KEYS) + len(EXTRA_FEATURE_KEYS),
        "required_features": len(REQUIRED_FEATURE_KEYS),
        "evidence_only_features": len(EXTRA_FEATURE_KEYS),
        "features_produced_by_extractor": len(_producer_keys()),
        "confidence_cap": CONFIDENCE_CAP,
        "max_single_indicator_contribution": MAX_SINGLE_INDICATOR_CONTRIBUTION,
        "thresholds": {"phishing": PHISHING_THRESHOLD, "suspicious": SUSPICIOUS_THRESHOLD},
        "keyword_vocabulary_size": len(SUSPICIOUS_KEYWORDS),
        "categories": categories,
    }


def fuse_contribution(spec: Dict[str, Any], features: Dict[str, Any]) -> float:
    """Weight for one fired indicator, applying the per-indicator cap."""
    if spec["weight_kind"] == "per_match":
        raw = spec["weight"] * int(features.get("keyword_count") or 0)
        return min(round(raw, 4), MAX_SINGLE_INDICATOR_CONTRIBUTION)
    return float(spec["weight"])


def saturate(score: float) -> float:
    """Total score cap: the scorer never reports certainty."""
    return min(CONFIDENCE_CAP, round(score, 4))


def classify(confidence: float) -> str:
    if confidence >= PHISHING_THRESHOLD:
        return "phishing"
    if confidence >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "legitimate"


# ---------------------------------------------------------------------------
# Provenance - what the scorer is, and what it is not
# ---------------------------------------------------------------------------
UNCALIBRATED_NOTE = (
    "Weights are hand-set heuristics, not fitted parameters. No labelled evaluation "
    "corpus was used, so no precision, recall or accuracy figure is published for this "
    "scorer. Measured false positives on real legitimate HTTPS URLs: "
    "'https://support.google.com/accounts/verify-account-login' scores 0.95 (phishing "
    "tier) and "
    "'https://www.microsoft.com/en-us/security/account-verification/login' scores 0.60 "
    "(suspicious tier), because credential vocabulary and brand names appear in "
    "legitimate pages too. The verdict is therefore a triage signal that lists which "
    "lexical features to inspect, not an identification of a phishing site."
)

SCORER_PROVENANCE: Dict[str, Any] = {
    "scorer": SCORER_NAME,
    "version": SCORER_VERSION,
    "model_family": "deterministic lexical and structural scorer",
    "trained_model": False,
    "fitted_on_data": False,
    "calibration": "uncalibrated",
    "calibration_note": UNCALIBRATED_NOTE,
    "network_access": False,
    "submits_url": False,
    "resolves_dns": False,
    "domain_suffix_list": "bundled offline snapshot only (no publicsuffix.org fetch)",
    "external_reputation": {
        "implemented": False,
        "providers": [],
        "note": (
            "No VirusTotal, Google Safe Browsing or other reputation integration exists "
            "in this project. The response field is a fixed 'unavailable' statement, not a "
            "degraded lookup."
        ),
    },
    "core_indicators": CORE_INDICATOR_COUNT,
    "extended_indicators": EXTENDED_INDICATOR_COUNT,
    "confidence_cap": CONFIDENCE_CAP,
    "max_single_indicator_contribution": MAX_SINGLE_INDICATOR_CONTRIBUTION,
    "thresholds": {
        "phishing": PHISHING_THRESHOLD,
        "suspicious": SUSPICIOUS_THRESHOLD,
        "legitimate_below": SUSPICIOUS_THRESHOLD,
    },
    "deterministic": True,
}


def provenance() -> Dict[str, Any]:
    out = dict(SCORER_PROVENANCE)
    out["categories"] = registry_summary()["categories"]
    return out


_validate_registry()
