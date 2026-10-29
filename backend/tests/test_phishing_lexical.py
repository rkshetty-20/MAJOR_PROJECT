"""Stage E verification of the offline lexical phishing scorer.

These tests pin down what the scorer is *claimed* to be, and they are written so
that a false claim fails:

* the registry really declares 10 weighted core indicators (+2 extended) and is
  machine-checked at import time;
* confidence is capped, per-indicator contribution is capped, tiers are exact;
* no network I/O of any kind is possible (enforced structurally and at runtime);
* malformed input is a documented rejection with a stable reason code, never a
  crash and never an interpreter message;
* IDN/homograph and obfuscated IP hosts are recognised (they were missed before
  stage E - see ``tests/test_phishing_golden_replay.py`` for the measured delta);
* the uncalibrated limitation, including measured false positives on legitimate
  URLs, is published rather than hidden.
"""

from __future__ import annotations

import ast
import socket
from pathlib import Path
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import phishing as phishing_package
from app.services import phishing_detector as facade
from app.services.phishing import (
    CONFIDENCE_CAP,
    CORE_INDICATOR_COUNT,
    EXTENDED_INDICATORS,
    FEATURE_PRODUCER_KEYS,
    LEXICAL_INDICATORS,
    MAX_SINGLE_INDICATOR_CONTRIBUTION,
    PHISHING_THRESHOLD,
    SCORER_NAME,
    SCORER_VERSION,
    SUSPICIOUS_THRESHOLD,
    MalformedURLError,
    VALID_REASONS,
    classify,
    evaluate_email_phishing,
    evaluate_phishing_url,
    evaluate_spear_phishing,
    evaluate_url_phishing,
    extract_features,
    provenance,
    registry_summary,
    saturate,
    score_url,
    validate_against_extractor,
)
from app.services.phishing.contract import (
    EXTRA_FEATURE_KEYS,
    HIGH_ABUSE_TLDS,
    INDICATOR_FIELDS,
    LONG_URL_MIN_LENGTH,
    MANY_SUBDOMAINS_MIN_COUNT,
    REQUIRED_FEATURE_KEYS,
    SPECIAL_CHARS_ALPHABET,
    SPECIAL_CHARS_MIN_COUNT,
    STANDARD_PORTS,
    SUSPICIOUS_KEYWORDS,
    TARGETED_BRANDS,
    UNCALIBRATED_NOTE,
    IndicatorContractError,
    _validate_indicator,
    list_indicators,
)
from app.services.phishing.url_features import ip_form, keyword_hits

client = TestClient(app)

PACKAGE_DIR = Path(phishing_package.__file__).parent

EXPECTED_CORE_IDS = {
    "rule_ip_host",
    "rule_no_https",
    "rule_suspicious_keywords",
    "rule_many_subdomains",
    "rule_long_url",
    "rule_special_chars",
    "rule_punycode",
    "rule_misleading_subdomain",
    "rule_credentials",
    "rule_unusual_port",
}


# ---------------------------------------------------------------------------
# 1. The registry: 10 weighted indicators, machine-checked
# ---------------------------------------------------------------------------
def test_exactly_ten_core_weighted_indicators_are_declared():
    assert CORE_INDICATOR_COUNT == 10
    assert set(LEXICAL_INDICATORS) == EXPECTED_CORE_IDS
    assert set(EXTENDED_INDICATORS) == {"rule_open_redirect", "rule_suspicious_tld"}


def test_every_indicator_is_fully_declared():
    for spec in list_indicators(include_extended=True):
        for field in INDICATOR_FIELDS:
            if field == "predicate":
                continue
            assert field in spec, f"{spec['id']} missing {field}"
        assert spec["version"] == SCORER_VERSION
        assert spec["mitre"], f"{spec['id']} has no MITRE ATT&CK mapping"
        assert 0 < spec["weight"] <= 1
        assert spec["inputs"], f"{spec['id']} declares no inputs"
        live = LEXICAL_INDICATORS.get(spec["id"]) or EXTENDED_INDICATORS[spec["id"]]
        assert callable(live["predicate"])
        # A published spec must be JSON-serialisable: no callables leak out.
        assert "predicate" not in spec


def test_registry_counts_published_by_the_summary_match_the_live_registries():
    summary = registry_summary()
    assert summary["core_indicators"] == len(LEXICAL_INDICATORS) == 10
    assert summary["extended_indicators"] == len(EXTENDED_INDICATORS) == 2
    assert summary["declared_features"] == len(REQUIRED_FEATURE_KEYS) + len(EXTRA_FEATURE_KEYS)
    assert summary["features_produced_by_extractor"] == len(FEATURE_PRODUCER_KEYS)
    assert summary["scorer"] == SCORER_NAME
    assert summary["confidence_cap"] == CONFIDENCE_CAP
    assert summary["thresholds"] == {"phishing": PHISHING_THRESHOLD, "suspicious": SUSPICIOUS_THRESHOLD}
    assert sum(summary["categories"].values()) == 12


def test_broken_indicator_specs_are_rejected():
    """The import-time validator must actually reject the classic failure modes."""
    base = dict(LEXICAL_INDICATORS["rule_ip_host"])

    def mutate(**changes):
        spec = dict(base)
        spec.update(changes)
        return spec

    with pytest.raises(IndicatorContractError, match="missing fields"):
        _validate_indicator({k: v for k, v in base.items() if k != "mitre"})
    with pytest.raises(IndicatorContractError, match="weight must be in"):
        _validate_indicator(mutate(weight=0))
    with pytest.raises(IndicatorContractError, match="weight must be in"):
        _validate_indicator(mutate(weight=1.5))
    with pytest.raises(IndicatorContractError, match="unknown weight_kind"):
        _validate_indicator(mutate(weight_kind="vibes"))
    with pytest.raises(IndicatorContractError, match="category"):
        _validate_indicator(mutate(category="astrology"))
    with pytest.raises(IndicatorContractError, match="severity"):
        _validate_indicator(mutate(severity="scary"))
    with pytest.raises(IndicatorContractError, match="no callable predicate"):
        _validate_indicator(mutate(predicate="is_ip"))
    with pytest.raises(IndicatorContractError, match="declares no inputs"):
        _validate_indicator(mutate(inputs=()))
    with pytest.raises(IndicatorContractError, match="reads undeclared features"):
        _validate_indicator(mutate(inputs=("is_ip", "user_agent")))
    # An explanation that interpolates a field the indicator never declares would
    # render as literal braces in front of a user.
    with pytest.raises(IndicatorContractError, match="explanation interpolates undeclared"):
        _validate_indicator(mutate(explanation="Flagged because {mystery}."))
    with pytest.raises(IndicatorContractError, match="non-empty string"):
        _validate_indicator(mutate(matching="   "))


def test_registry_is_cross_checked_against_the_extractor():
    # Live check passes ...
    validate_against_extractor(FEATURE_PRODUCER_KEYS)
    # ... and it fails when an indicator reads a feature nothing produces.
    with pytest.raises(IndicatorContractError, match="never produces"):
        validate_against_extractor([key for key in FEATURE_PRODUCER_KEYS if key != "is_ip"])
    # ... and when the extractor produces a key no indicator consumes it is only
    # tolerated when it is explicitly declared as evidence-only vocabulary.
    assert "hostname_length" in EXTRA_FEATURE_KEYS
    assert "hostname_length" not in REQUIRED_FEATURE_KEYS
    assert not any("hostname_length" in spec["inputs"] for spec in list_indicators())


# ---------------------------------------------------------------------------
# 2. Caps, thresholds and fusion arithmetic
# ---------------------------------------------------------------------------
def test_confidence_is_capped_and_never_certainty():
    assert CONFIDENCE_CAP == 0.99
    assert saturate(1.0) == 0.99
    assert saturate(5.0) == 0.99
    assert saturate(0.64991) == 0.6499  # rounded to 4 dp, not clamped
    result = score_url("http://192.168.1.50/update-banking-account-login-verify")
    assert result["raw_indicator_sum"] > CONFIDENCE_CAP
    assert result["confidence"] == CONFIDENCE_CAP


def test_tier_boundaries_are_exact():
    assert classify(PHISHING_THRESHOLD) == "phishing"
    assert classify(PHISHING_THRESHOLD - 0.0001) == "suspicious"
    assert classify(SUSPICIOUS_THRESHOLD) == "suspicious"
    assert classify(SUSPICIOUS_THRESHOLD - 0.0001) == "legitimate"
    assert (PHISHING_THRESHOLD, SUSPICIOUS_THRESHOLD) == (0.65, 0.35)


def test_single_indicator_contribution_cap():
    # Paper IV-D gives each suspicious token 0.20 and Fig. 7 states that four
    # tokens are enough to flag a short HTTPS URL, so the guard is exactly 0.80.
    assert MAX_SINGLE_INDICATOR_CONTRIBUTION == 0.80
    spec = LEXICAL_INDICATORS["rule_suspicious_keywords"]
    assert spec["weight_kind"] == "per_match"
    assert saturate(fuse(spec, 2)) == 0.4
    assert saturate(fuse(spec, 3)) == 0.6
    # Before stage E the keyword weight multiplied out unbounded: 10 keywords
    # contributed 2.0 and single-handedly maxed the score. The guard stops that
    # without preventing the paper's four-token sensitivity from working.
    assert fuse(spec, 4) == 0.8
    assert fuse(spec, 10) == 0.8
    assert fuse(spec, 0) == 0.0


def test_paper_fig7_four_suspicious_tokens_are_flagged():
    """Paper Fig. 7: "a short HTTPS URL needs four suspicious tokens to be flagged".

    The published arithmetic is 4 x 0.20 = 0.80 >= the 0.65 threshold, while three
    tokens (0.60) stay below it. Asserted on the real scorer, not on the weights.
    """
    three = score_url("https://abc.example/verify/account/login")
    four = score_url("https://abc.example/verify/account/login/secure")

    assert three["confidence"] == 0.60
    assert three["verdict"] == "suspicious"
    assert four["confidence"] == 0.80
    assert four["verdict"] == "phishing"

    keyword_rule = next(r for r in four["indicators"] if r["id"] == "rule_suspicious_keywords")
    assert keyword_rule["contribution"] == 0.80
    # A keyword-only URL can reach the flag tier but never the 0.99 ceiling, which
    # is what keeps one count-based indicator from deciding the verdict alone.
    assert keyword_rule["contribution"] < CONFIDENCE_CAP


def fuse(spec: Dict[str, Any], keyword_count: int) -> float:
    from app.services.phishing.contract import fuse_contribution

    return fuse_contribution(spec, {"keyword_count": keyword_count})


def test_no_recorded_firing_exceeds_the_per_indicator_cap():
    corpus = [
        "http://192.168.1.50/update-banking-account-login-verify",
        "https://www.example.com/account/login?verify=1&update=1&secure=1&password=1&auth=1&confirm=1",
        "http://admin:admin@192.0.2.57:8080/session/login?confirm=1",
        "https://login.paypal.com.scammer-website.net/secure",
    ]
    for url in corpus:
        result = score_url(url, include_extended=True)
        for indicator in result["indicators"]:
            assert indicator["contribution"] <= MAX_SINGLE_INDICATOR_CONTRIBUTION, (url, indicator)
        assert result["confidence"] <= CONFIDENCE_CAP


def test_indicator_weight_sum_is_visible_in_the_result():
    result = score_url("http://192.168.1.1/login")
    assert {item["id"] for item in result["indicators"]} == {"rule_ip_host", "rule_no_https", "rule_suspicious_keywords"}
    assert result["raw_indicator_sum"] == round(0.4 + 0.2 + 0.2, 4)
    assert result["confidence"] == 0.8
    assert result["evaluated_indicators"] == 10  # core registry only
    assert score_url("http://192.168.1.1/login", include_extended=True)["evaluated_indicators"] == 12
    # Adding the extended specs must not move a score: the predicates gate on the
    # measured features.
    assert score_url("http://192.168.1.1/login", include_extended=True)["confidence"] == 0.8


# ---------------------------------------------------------------------------
# 3. Structural and runtime "never touches the network" guarantees
# ---------------------------------------------------------------------------
def test_package_source_imports_no_http_client_or_dns_library():
    """No httpx/requests/socket/DNS use anywhere in the phishing package."""
    forbidden = {"httpx", "requests", "aiohttp", "urllib3", "dns", "socket", "urllib.request"}
    for path in sorted(PACKAGE_DIR.glob("*.py")) + [Path(facade.__file__)]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = {node.module}
            else:
                continue
            overlap = {name for name in names if name in forbidden or name.split(".")[0] in forbidden}
            assert not overlap, f"{path.name} imports {sorted(overlap)}"


def test_scoring_a_corpus_with_networking_disabled_succeeds(monkeypatch):
    def blocked(*_args, **_kwargs):
        raise AssertionError("the lexical scorer must never open a network socket")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, blocked)

    for url in [
        "https://www.google.com/",
        "http://192.168.1.1/login",
        "https://login.paypal.com.scammer-website.net/secure",
        "http://xn--p1as.com/verify",
    ]:
        assert score_url(url)["url"] == url
    assert evaluate_email_phishing(
        sender="PayPal <paypal-alerts247@gmail.com>",
        subject="verify your account",
        body="click http://192.0.2.10/paypal/verify now",
    )["classification"] == "phishing"


def test_domain_suffix_list_is_the_bundled_offline_snapshot():
    """tldextract's default constructor downloads publicsuffix.org - ours must not."""
    source = (PACKAGE_DIR / "url_features.py").read_text(encoding="utf-8")
    assert "suffix_list_urls=()" in source, "extractor must be pinned to the bundled snapshot"
    assert provenance()["domain_suffix_list"].startswith("bundled offline snapshot")


# ---------------------------------------------------------------------------
# 4. Malformed-input rejection contract
# ---------------------------------------------------------------------------
REJECTIONS: List[List[Any]] = [
    [12345, "not-a-string"],
    ["", "empty"],
    ["   ", "empty"],
    ["http://", "no-hostname"],
    ["ftp://example.com/file", "unsupported-scheme"],
    ["example.com/login", "unsupported-scheme"],
    ["//example.com/x", "unsupported-scheme"],
    ["http://example.com:99999/login", "invalid-port"],
    ["http://example.com:notaport/login", "invalid-port"],
    ["http://exa mple.com/login", "forbidden-character"],
    ["http://exam\x08ple.com", "forbidden-character"],
    ["http://example.com/\x00evil", "forbidden-character"],
    ["http://apple\u202e.com/verify", "forbidden-character"],  # bidi override
    ["http://paypal\xa0.com/verify", "forbidden-character"],  # non-breaking space
    ["http://bad+.com/", "invalid-host-label"],
    ["http://-bad-start.com/", "invalid-host-label"],
    ["http://.leading-dot.com/", "invalid-host-label"],
    ["http://a..b.example.com/", "invalid-host-label"],
    ["http://[2001:db8::1/login", "invalid-host-label"],  # unbalanced IPv6 literal
]


@pytest.mark.parametrize("value,reason", REJECTIONS)
def test_malformed_input_is_rejected_with_a_stable_reason(value, reason):
    with pytest.raises(MalformedURLError) as excinfo:
        extract_features(value)
    message = str(excinfo.value)
    assert excinfo.value.reason == reason
    assert reason in VALID_REASONS
    assert message.strip()
    # MalformedURLError must stay a ValueError so pre-stage-E callers (the rule
    # engine, the routers) keep working unchanged.
    assert isinstance(excinfo.value, ValueError)


@pytest.mark.parametrize("value,reason", REJECTIONS)
def test_rejections_never_leak_interpreter_messages(value, reason):
    with pytest.raises(MalformedURLError) as excinfo:
        extract_features(value)
    message = str(excinfo.value)
    for fragment in ("Port out of range", "could not be cast to integer", "Invalid IPv", "Traceback"):
        assert fragment not in message


def test_empty_port_and_trailing_dot_are_tolerated_as_browsers_treat_them():
    features = extract_features("http://example.com:/")
    assert features["port"] is None
    assert features["unusual_port"] is False
    assert extract_features("http://192.0.2.10./verify")["is_ip"] is True
    assert extract_features("https://example.com:0/")["port"] == 0
    assert extract_features("https://example.com:8443/checkout")["unusual_port"] is True
    assert extract_features("https://example.com:443/status")["unusual_port"] is False
    assert STANDARD_PORTS == (80, 443)


# ---------------------------------------------------------------------------
# 5. Evasion shapes stage E made visible
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "host,form",
    [
        ("192.0.2.10", "ipv4"),
        ("192.0.2.10.", "ipv4"),
        ("2001:db8::1", "ipv6"),
        ("::1", "ipv6"),
        ("1357796046", "decimal"),
        ("0x1.0x2.0x3.0x4", "dotted-hex"),
        ("256.256.256.256", "invalid-dotted-quad"),
        ("127.1", "partial"),
        ("10.1.5", "partial"),
        ("example.com", "none"),
        ("be.ef", "none"),
        ("", "none"),
    ],
)
def test_ip_host_forms(host, form):
    assert ip_form(host) == (form != "none", form), host


@pytest.mark.parametrize(
    "url",
    [
        "http://1357796046/login",
        "http://0x1.0x2.0x3.0x4/login",
        "http://256.256.256.256/login",
        "http://[2001:db8::1]/login",
        "http://192.0.2.10./verify",
    ],
)
def test_obfuscated_ip_hosts_are_scored_as_ip_hosts(url):
    """Before stage E only dotted-quad literals counted, so every one of these
    bypassed the 0.40 IP-host indicator."""
    result = score_url(url)
    assert result["features"]["is_ip"] is True
    assert "rule_ip_host" in {item["id"] for item in result["indicators"]}
    assert result["confidence"] >= 0.6


@pytest.mark.parametrize(
    "url,expect_punycode",
    [
        ("https://xn--bcher-kva.example.com/login", True),
        ("http://xn--p1as.com/verify", True),
        ("http://\u00fcber-mensch.example.com/login", True),  # non-ASCII label
        ("http://\u0430\u0440\u0430\u0435.com/paypal", True),  # Cyrillic homoglyphs
        ("https://example.com/login", False),
    ],
)
def test_idn_and_punycode_hosts(url, expect_punycode):
    features = extract_features(url)
    assert features["is_punycode"] is expect_punycode
    if expect_punycode:
        assert "rule_punycode" in {item["id"] for item in score_url(url)["indicators"]}
        # The host is normalised to its IDNA form before the registered domain is
        # resolved, so the analyst can see what a resolver would actually fetch.
        assert features["non_ascii_host"] or features["domain"].startswith("xn--") or "xn--" in features["host"]


def test_mixed_script_homograph_is_flagged_as_evidence():
    features = extract_features("http://paypal-\u0430.com/verify")
    assert features["non_ascii_host"] is True
    assert features["is_punycode"] is True
    assert features["homograph_suspect"] is True


def test_punycode_plus_brand_token_boundary_hits_the_threshold_exactly():
    # 0.30 (punycode) + 0.35 (misleading subdomain) == 0.65 == PHISHING_THRESHOLD
    result = score_url("https://xn--bcher-kva.paypal.scammer.com")
    assert result["confidence"] == pytest.approx(PHISHING_THRESHOLD)
    assert result["is_phishing"] is True
    assert {item["id"] for item in result["indicators"]} == {"rule_punycode", "rule_misleading_subdomain"}


# ---------------------------------------------------------------------------
# 6. Vocabulary matching semantics
# ---------------------------------------------------------------------------
def test_keyword_matching_is_token_bounded_not_substring():
    assert keyword_hits("https://example.com/authorised") == []
    assert keyword_hits("https://example.com/insecure") == []
    assert keyword_hits("https://example.com/verify") == ["verify"]
    assert keyword_hits("https://example.com/account-verification") == ["account", "verify"]
    assert keyword_hits("https://example.com/signin") == ["login"]
    assert keyword_hits("https://example.com/passwd") == ["password"]
    assert len(SUSPICIOUS_KEYWORDS) == 10
    assert len(TARGETED_BRANDS) == 7
    assert HIGH_ABUSE_TLDS and all(tld.startswith(".") for tld in HIGH_ABUSE_TLDS)


def test_declared_thresholds_are_the_ones_the_predicates_use():
    assert LONG_URL_MIN_LENGTH == 75
    assert SPECIAL_CHARS_MIN_COUNT == 5
    assert MANY_SUBDOMAINS_MIN_COUNT == 3
    # "https://example.com/" is 20 characters, so 55/56 filler sit exactly on the
    # url_length boundary declared by the indicator.
    assert extract_features("https://example.com/" + "a" * 55)["url_length"] == LONG_URL_MIN_LENGTH
    assert "rule_long_url" not in {i["id"] for i in score_url("https://example.com/" + "a" * 55)["indicators"]}
    assert "rule_long_url" in {i["id"] for i in score_url("https://example.com/" + "a" * 56)["indicators"]}
    assert extract_features("https://example.com/?a=1&b=2")["special_chars"] == 4
    assert "rule_special_chars" not in {i["id"] for i in score_url("https://example.com/?a=1&b=2")["indicators"]}
    assert extract_features("https://example.com/?a=1&b=2&c=3&d=4")["special_chars"] == 8
    assert "rule_special_chars" in {i["id"] for i in score_url("https://example.com/?a=1&b=2&c=3&d=4")["indicators"]}
    assert extract_features("https://a.b.c.example.com/")["num_subdomains"] == MANY_SUBDOMAINS_MIN_COUNT
    assert extract_features("https://a.b.example.com/")["num_subdomains"] == 2
    assert set(SPECIAL_CHARS_ALPHABET) == {"-", "_", "@", "?", "=", "&", "%"}


def test_open_redirect_and_suspicious_tld_only_apply_in_the_tiered_view():
    redirect = "https://example.com/redirect?url=http://attacker-controlled-site.xyz/login"
    assert "rule_open_redirect" not in {i["id"] for i in score_url(redirect)["indicators"]}
    extended = score_url(redirect, include_extended=True)
    assert "rule_open_redirect" in {i["id"] for i in extended["indicators"]}
    assert extended["features"]["redirect_targets"][0]["param"] == "url"
    assert extended["confidence"] == 0.45  # 0.20 keyword + 0.25 redirect
    assert extended["features"]["suspicious_tld"] is False  # visible host is example.com
    top = score_url("http://secure-account-verification.top/login", include_extended=True)
    assert top["features"]["suspicious_tld"] is True
    assert "rule_suspicious_tld" in {i["id"] for i in top["indicators"]}
    # 4 tokens (0.80) + no-HTTPS (0.20) + suspicious TLD (0.15) saturates at 0.99.
    assert top["confidence"] == CONFIDENCE_CAP


# ---------------------------------------------------------------------------
# 7. Determinism and the historical public surface
# ---------------------------------------------------------------------------
def test_scoring_is_deterministic_and_does_not_mutate_input_features():
    url = "http://user:password@192.0.2.10:8080/verify-account?redirect=http://evil.xyz/login"
    first = score_url(url, include_extended=True)
    second = score_url(url, include_extended=True)
    assert first == second
    again = score_url(url, include_extended=True)
    again["features"]["is_ip"] = "tampered"
    assert score_url(url, include_extended=True)["features"]["is_ip"] is True


def test_legacy_five_tuple_and_phrases_are_preserved():
    is_phishing, confidence, features, explanation, rules = evaluate_phishing_url("http://192.168.1.1/login")
    assert is_phishing is True and confidence == 0.8
    for legacy_key in (
        "url_length",
        "hostname_length",
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
    ):
        assert legacy_key in features
    assert explanation.startswith("Suspicious URL identified.")
    assert "credential-harvesting keywords" in explanation
    assert rules and {"id", "name", "explanation", "contribution", "feature_values"} <= set(rules[0])
    punycode = score_url("https://xn--bcher-kva.example.com/login")["indicators"]
    assert any("Punycode" in item["explanation"] for item in punycode)
    assert "misleading brand names" in evaluate_phishing_url("https://login.paypal.com.scammer-website.net/secure")[3]
    benign = evaluate_phishing_url("https://www.google.com/")
    assert benign[0] is False and benign[3] == "URL appears benign."


def test_facade_reexports_the_package_and_claims_no_network_feature():
    assert facade.evaluate_phishing_url is phishing_package.evaluate_phishing_url
    assert facade.extract_phishing_features is phishing_package.extract_features
    source = Path(facade.__file__).read_text(encoding="utf-8")
    # The module docstring must not advertise a capability the code does not have.
    assert "no reputation" in source
    assert "no URL is fetched" in source
    assert "httpx" in source  # the killed dead import is recorded, not hidden


# ---------------------------------------------------------------------------
# 8. Honesty of the published provenance
# ---------------------------------------------------------------------------
def test_provenance_states_limits_that_are_true():
    block = provenance()
    assert block["trained_model"] is False
    assert block["fitted_on_data"] is False
    assert block["calibration"] == "uncalibrated"
    assert block["network_access"] is False
    assert block["submits_url"] is False
    assert block["resolves_dns"] is False
    assert block["deterministic"] is True
    assert block["external_reputation"]["implemented"] is False
    assert block["external_reputation"]["providers"] == []
    assert block["core_indicators"] == 10 and block["extended_indicators"] == 2
    note = UNCALIBRATED_NOTE
    assert "no precision, recall or accuracy figure is published" in note
    # The limitation must carry measured evidence, not an adjective.
    assert "0.99" in note and "https://support.google.com/accounts/verify-account-login" in note
    assert block["calibration_note"] == note


# ---------------------------------------------------------------------------
# 9. HTTP surface
# ---------------------------------------------------------------------------
def test_indicator_registry_is_queryable():
    response = client.get("/api/detect/phishing/indicators")
    assert response.status_code == 200
    body = response.json()
    assert body["core_indicators"] == 10
    assert body["extended_indicators"] == 2
    assert len(body["indicators"]) == 12
    assert body["thresholds"]["phishing"] == 0.65
    assert body["confidence_cap"] == CONFIDENCE_CAP
    assert body["provenance"]["external_reputation"]["implemented"] is False
    assert all("predicate" not in indicator for indicator in body["indicators"])
    paypal = next(i for i in body["indicators"] if i["id"] == "rule_misleading_subdomain")
    assert paypal["weight"] == 0.35 and paypal["category"] == "identity" and paypal["mitre"] == "T1656"


def test_legacy_endpoint_publishes_the_reputation_truth():
    body = client.post("/api/detect/phishing", json={"url": "http://192.168.1.1/login"}).json()
    assert body["is_phishing"] is True
    assert body["reputation"]["implemented"] is False
    assert body["reputation"]["provider"] is None
    assert body["reputation"]["status"] == "unavailable"
    assert "VirusTotal" in body["reputation"]["details"]
    assert body["scorer"] == {"name": SCORER_NAME, "version": SCORER_VERSION}
    assert body["confidence_cap"] == CONFIDENCE_CAP
    assert body["max_single_indicator_contribution"] == MAX_SINGLE_INDICATOR_CONTRIBUTION
    assert body["provenance"]["calibration"] == "uncalibrated"


@pytest.mark.parametrize(
    "url,fragment",
    [
        ("http://example.com:99999/login", "between 0 and 65535"),
        ("http://example.com:notaport/login", "between 0 and 65535"),
        ("http://exa mple.com/login", "forbidden control"),
        ("http://.leading-dot.com/", "empty label"),
    ],
)
def test_malformed_urls_are_controlled_400s_with_a_detail_string(url, fragment):
    """``detail`` stays a string: the UI reads ``err.response.data.detail``."""
    for endpoint in ("/api/detect/phishing", "/api/detect/url"):
        response = client.post(endpoint, json={"url": url})
        assert response.status_code == 400, endpoint
        detail = response.json()["detail"]
        assert isinstance(detail, str) and fragment in detail


def test_email_endpoint_survives_unparsable_embedded_link():
    """This used to be an unhandled ValueError -> HTTP 500."""
    response = client.post(
        "/api/detect/email",
        json={
            "sender": "Alert <a@corp.example>",
            "subject": "verify your account",
            "body": "click http://example.com:99999/login now and http://192.0.2.10/verify-account",
        },
    )
    assert response.status_code == 200, response.text
    links = response.json()["links_analysis"]
    assert links["total_links"] == 2
    assert links["analyzed_links_count"] == 1
    assert [{"url": s["url"], "reason": s["reason"]} for s in links["skipped_links"]] == [
        {"url": "http://example.com:99999/login", "reason": "invalid-port"}
    ]
    assert response.json()["provenance"]["network_access"] is False


def test_spear_endpoint_survives_unparsable_embedded_link():
    response = client.post(
        "/api/detect/spear-phishing",
        json={
            "sender": "CEO David Miller <david.miller.ceo@gmail.com>",
            "recipient_name": "Robert Langdon",
            "recipient_role": "Chief Financial Officer",
            "subject": "Confidential: Urgent Wire Transfer Required Today",
            "body": "Execute an urgent wire transfer. Bypass approval. See http://example.com:99999/login",
            "organization_name": "Acme Corp",
            "claimed_identity": "CEO",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["classification"] == "phishing"
    assert body["link_analysis"]["evaluated"] is None
    assert body["link_analysis"]["skipped"][0]["reason"] == "invalid-port"


def test_rule_engine_tolerates_malformed_url_stored_in_telemetry():
    """A stored target the lexicon rejects must skip, not abort the evaluation."""
    from datetime import datetime, timezone

    from app.database import SessionLocal
    from app.models import Detection, Scenario, SecurityEvent
    from app.models import Session as SessionModel
    from app.models import SessionStatus
    from app.routers.scenarios import seed_scenarios
    from app.services.rule_engine import evaluate_rules

    db = SessionLocal()
    session_id = None
    try:
        seed_scenarios(db)
        scenario = db.query(Scenario).first()
        session = SessionModel(
            student_id="test_malformed_url_target",
            scenario_id=scenario.id,
            status=SessionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        session_id = session.id
        db.add(
            SecurityEvent(
                session_id=session_id,
                scenario="phishing_url",
                event_type="phishing_url",
                timestamp=datetime(2026, 5, 4, 12, 0, tzinfo=timezone.utc),
                source="198.51.100.20",
                target="http://example.com:99999/login",
                payload_json="{}",
            )
        )
        db.commit()
        assert evaluate_rules(session_id=session_id, db=db) == []

        # A parsable target still produces the behavioural detection.
        db.add(
            SecurityEvent(
                session_id=session_id,
                scenario="phishing_url",
                event_type="phishing_url",
                timestamp=datetime(2026, 5, 4, 12, 0, tzinfo=timezone.utc),
                source="198.51.100.20",
                target="http://192.0.2.10/verify-account",
                payload_json="{}",
            )
        )
        db.commit()
        detections = evaluate_rules(session_id=session_id, db=db)
        assert [d.label for d in detections] == ["phishing_url_detected"]
    finally:
        if session_id is not None:
            db.query(Detection).filter(Detection.session_id == session_id).delete()
            db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).delete()
            db.query(SessionModel).filter(SessionModel.id == session_id).delete()
            db.commit()
        db.close()
