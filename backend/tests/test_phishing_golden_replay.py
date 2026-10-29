"""Locked behavioural replay for the lexical phishing scorer, plus the stage-E
delta audit against the pre-change baseline.

Two recorded files are involved and they must not be confused:

* ``tests/data/phishing_lexical_baseline_pre_stage_e.json`` - captured from the
  original 958-line monolith *before* stage E touched it. It is an audit record
  and is never regenerated: the crashes it contains are the evidence for the
  changes stage E made.
* ``tests/data/phishing_lexical_golden.json`` - the locked current behaviour,
  regenerated deliberately with ``python tests/regenerate_phishing_golden.py``.

Any drift in the lock fails here, so a future "improvement" to a weight, a
vocabulary entry or the matching logic has to be made consciously.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
from app.services.phishing import CONFIDENCE_CAP, MAX_SINGLE_INDICATOR_CONTRIBUTION, PHISHING_THRESHOLD

DATA = Path(__file__).parent / "data"
GOLDEN_PATH = DATA / "phishing_lexical_golden.json"
BASELINE_PATH = DATA / "phishing_lexical_baseline_pre_stage_e.json"

_TOOL_PATH = Path(__file__).with_name("regenerate_phishing_golden.py")
_spec = importlib.util.spec_from_file_location("regenerate_phishing_golden", _TOOL_PATH)
recorder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(recorder)

golden: Dict[str, Any] = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
baseline: Dict[str, Any] = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))

INTERPRETER_MESSAGES = (
    "Port out of range 0-65535",
    "Port could not be cast to integer value",
    "Invalid IPv6 URL",
)


def _email_keys() -> List[str]:
    return [
        f"{index:02d}|{item['sender']}|{item['subject']}" for index, item in enumerate(recorder.EMAIL_CORPUS)
    ]


def _spear_keys() -> List[str]:
    return [f"{index:02d}|{item['subject']}" for index, item in enumerate(recorder.SPEAR_CORPUS)]


# ---------------------------------------------------------------------------
# 1. The lock is complete and replays exactly
# ---------------------------------------------------------------------------
def test_lock_covers_the_declared_corpus_exactly():
    assert set(golden["urls"]) == set(recorder.URL_CORPUS)
    assert list(golden["emails"]) == _email_keys()
    assert list(golden["spears"]) == _spear_keys()
    assert len(golden["urls"]) == len(recorder.URL_CORPUS) == 66
    # Every recorded URL case covers both public entry points.
    for case in golden["urls"].values():
        assert set(case) == {"legacy", "tiered"}


def test_replay_of_urls_matches_the_locked_behaviour():
    drift = []
    for url in recorder.URL_CORPUS:
        fresh = recorder.capture_url_case(url)
        if fresh != golden["urls"][url]:
            drift.append((url, golden["urls"][url], fresh))
    assert not drift, "lexical behaviour drifted from the lock:\n" + "\n".join(repr(item) for item in drift)


def test_replay_of_messages_matches_the_locked_behaviour():
    drift = []
    for key, item in zip(_email_keys(), recorder.EMAIL_CORPUS):
        fresh = recorder.capture_email_case(item)
        if fresh != golden["emails"][key]:
            drift.append((key, golden["emails"][key], fresh))
    for key, item in zip(_spear_keys(), recorder.SPEAR_CORPUS):
        fresh = recorder.capture_spear_case(item)
        if fresh != golden["spears"][key]:
            drift.append((key, golden["spears"][key], fresh))
    assert not drift, "message-level behaviour drifted from the lock:\n" + "\n".join(repr(i) for i in drift)


def test_every_declared_indicator_fires_somewhere_in_the_lock():
    """A declared-but-dead indicator would be invisible to every other test."""
    core_fired = set()
    extended_fired = set()
    for case in golden["urls"].values():
        core_fired.update(rule[0] for rule in case["legacy"].get("rules", []))
        extended_fired.update(rule[0] for rule in case["tiered"].get("rules", []))
    assert core_fired == {
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
    assert {"rule_open_redirect", "rule_suspicious_tld"} <= extended_fired


def test_lock_respects_caps_and_thresholds():
    for case in golden["urls"].values():
        for view in ("legacy", "tiered"):
            recorded = case[view]
            if "error" in recorded:
                continue
            assert recorded["confidence"] <= CONFIDENCE_CAP
            for rule in recorded["rules"]:
                assert rule[1] <= MAX_SINGLE_INDICATOR_CONTRIBUTION, rule
                assert rule[1] > 0, rule
            if view == "legacy":
                assert recorded["is_phishing"] is (recorded["confidence"] >= PHISHING_THRESHOLD)
            else:
                tier = "phishing" if recorded["confidence"] >= PHISHING_THRESHOLD else (
                    "suspicious" if recorded["confidence"] >= 0.35 else "legitimate"
                )
                assert recorded["classification"] == tier


# ---------------------------------------------------------------------------
# 2. Honest limitations stay recorded in the lock
# ---------------------------------------------------------------------------
#: Real, legitimate HTTPS URLs. Their scores are the counter-evidence against any
#: precision claim, so they are pinned here as well as in UNCALIBRATED_NOTE.
MEASURED_FALSE_POSITIVES = {
    "https://support.google.com/accounts/verify-account-login": (0.95, "phishing"),
    "https://accounts.google.com/ServiceLogin/signin": (0.75, "phishing"),
    "https://www.microsoft.com/en-us/security/account-verification/login": (0.60, "suspicious"),
    "https://help.github.com/en/articles/updating-your-password-support": (0.40, "suspicious"),
}


@pytest.mark.parametrize("url,expected", sorted(MEASURED_FALSE_POSITIVES.items()))
def test_measured_false_positives_on_legitimate_urls_are_recorded(url, expected):
    confidence, tier = expected
    recorded = golden["urls"][url]["tiered"]
    assert recorded["confidence"] == confidence
    assert recorded["classification"] == tier


def test_the_lock_records_that_the_phishing_tier_is_reachable_without_any_hard_signal():
    """Two legitimate brand URLs reach the phishing tier with HTTPS, no IP host,
    no credentials and no Punycode - only vocabulary and a brand-ish subdomain.
    Anyone tightening this scorer must update these recorded values on purpose."""
    phishing_without_host_signals = [
        url
        for url, (confidence, tier) in MEASURED_FALSE_POSITIVES.items()
        if tier == "phishing"
        and golden["urls"][url]["tiered"]["scheme"] == "https"
        and not any(rule[0] in {"rule_ip_host", "rule_credentials", "rule_punycode"} for rule in golden["urls"][url]["tiered"]["rules"])
    ]
    assert len(phishing_without_host_signals) >= 2, phishing_without_host_signals


# ---------------------------------------------------------------------------
# 3. Delta audit against the pre-stage-E baseline
# ---------------------------------------------------------------------------
def test_pre_change_baseline_still_records_the_crashes_it_had():
    """Guard against the audit record being quietly regenerated."""
    errors = [
        case["legacy"]["error"]
        for case in baseline["urls"].values()
        if "error" in case.get("legacy", {})
    ] + [case["error"] for case in baseline["emails"].values() if "error" in case]
    assert any("Port out of range 0-65535" in text for text in errors)
    assert any("could not be cast to integer" in text for text in errors)
    assert any("URL must include a valid hostname" in text for text in errors)


def test_interpreter_error_messages_are_no_longer_surfaced():
    for view in ("urls", "emails", "spears"):
        for key, case in golden[view].items():
            texts: List[str] = []
            if view == "urls":
                texts = [case["legacy"].get("error", ""), case["tiered"].get("error", "")]
            else:
                texts = [case.get("error", "")]
            for text in texts:
                for fragment in INTERPRETER_MESSAGES:
                    assert fragment not in text, (key, text)


def test_malformed_links_no_longer_abort_message_analysis():
    """Email cases 02 and 03 used to raise ValueError straight out of the endpoint."""
    for index, body in enumerate(recorder.EMAIL_CORPUS):
        key = _email_keys()[index]
        text = body["body"]
        if "example.com:99999" not in text and "example.com:notaport" not in text:
            continue
        assert ":99999" in text or "notaport" in text
        assert "error" in baseline["emails"][key], key
        assert "error" not in golden["emails"][key], key
        assert golden["emails"][key]["total_links"] == 1
        assert golden["emails"][key]["analyzed_links"] == 0


NEWLY_REJECTED = {
    "//example.com/x",
    "ftp://example.com/file",
    "http://-bad-start.com/",
    "http://.leading-dot.com/",
    "http://a..b.example.com/",
    "http://bad+.com/",
    "http://exa mple.com/login",
    "http://exam\x08ple.com",
    "http://example.com/\x00evil",
    "http://paypal\xa0.com/verify",
    "http://apple\u202e.com/verify",
}


def test_inputs_that_were_silently_scored_are_now_rejected_with_a_reason():
    """Each of these was parsed into a meaningless host (or scored at all) before
    stage E; they are now controlled rejections, and that is a recorded behaviour
    change, not a silent one."""
    became_rejections = set()
    for url, case in golden["urls"].items():
        if url not in baseline["urls"]:
            continue
        was_scored = "error" not in baseline["urls"][url]["legacy"]
        now_rejected = "error" in case["legacy"]
        if was_scored and now_rejected:
            became_rejections.add(url)
    assert became_rejections == NEWLY_REJECTED
    # And the recorded rejection text is the declared contract error, never a
    # traceback fragment or an interpreter message.
    for url in NEWLY_REJECTED:
        assert golden["urls"][url]["legacy"]["error"].startswith("MalformedURLError: "), url


def test_obfuscated_ip_hosts_flipped_to_detection():
    """Hosts a browser resolves but the old lexicon did not treat as an IP.

    The delta is measured over the corpus the pre-change baseline also
    contained: URLs added to the corpus after stage E have no "before" value,
    so they cannot appear in a before/after flip set. Those additions are
    audited separately by ``test_measured_false_positives_on_legitimate_urls_are_recorded``.
    """
    expected_flips = {
        "http://0x1.0x2.0x3.0x4/login",
        "http://1357796046/login",
        "http://192.0.2.10./verify",
        "http://256.256.256.256/login",
        "http://\u00fcber-mensch.example.com/login",
    }
    flips = set()
    for url, case in golden["urls"].items():
        if url not in baseline["urls"]:
            continue
        pre, post = baseline["urls"][url]["legacy"], case["legacy"]
        if "error" in pre or "error" in post:
            continue
        if not pre.get("is_phishing") and post.get("is_phishing"):
            flips.add(url)
    assert flips == expected_flips


def test_no_pre_existing_detection_was_lost():
    """Every URL the monolith called phishing is still called phishing.

    Weights were capped and matching tightened; detection coverage was not
    reduced. This is the regression direction that matters for a triage tool.
    """
    lost = []
    for url, case in golden["urls"].items():
        pre = baseline["urls"].get(url, {}).get("legacy", {})
        if pre.get("is_phishing") and "error" not in case["legacy"]:
            if not case["legacy"]["is_phishing"]:
                lost.append(url)
    assert lost == [], lost
    # Set form of the same guarantee, so a case that became a documented
    # rejection cannot hide a lost detection.
    pre_phishing = {url for url, case in baseline["urls"].items() if case["legacy"].get("is_phishing")}
    post_phishing = {url for url, case in golden["urls"].items() if case["legacy"].get("is_phishing")}
    assert pre_phishing <= post_phishing, sorted(pre_phishing - post_phishing)


def test_uncapped_keyword_weight_is_gone():
    def contributions(case: Dict[str, Any]) -> List[float]:
        values: List[float] = []
        for view in ("legacy", "tiered"):
            values.extend(rule[1] for rule in case.get(view, {}).get("rules", []))
        return values

    pre_max = max(v for case in baseline["urls"].values() for v in contributions(case))
    post_max = max(v for case in golden["urls"].values() for v in contributions(case))
    assert pre_max == 2.0, pre_max  # rule_suspicious_keywords x 10 matches
    assert post_max == pytest.approx(MAX_SINGLE_INDICATOR_CONTRIBUTION)
    # The saturation float noise (0.6000000000000001, 0.30000000000000004) is gone.
    for case in golden["urls"].values():
        for value in contributions(case):
            assert value == round(value, 4)


def test_spear_evaluation_is_unchanged_apart_from_the_guarded_link_path():
    assert golden["spears"] == baseline["spears"]


def test_lock_contains_the_punycode_boundary_case():
    """The tier boundary is recorded on both sides, with the arithmetic visible.

    Measured in the lock: 0.30 (punycode) + 0.35 (misleading brand subdomain)
    lands exactly on the declared 0.65 threshold and therefore classifies as
    phishing, while the neighbouring IDN URL at 0.20 + 0.30 = 0.50 does not.
    """
    boundary = golden["urls"]["https://xn--bcher-kva.paypal.scammer.com"]
    assert boundary["legacy"]["confidence"] == PHISHING_THRESHOLD
    assert boundary["legacy"]["is_phishing"] is True
    assert boundary["legacy"]["rules"] == [["rule_punycode", 0.3], ["rule_misleading_subdomain", 0.35]]
    assert boundary["tiered"]["classification"] == "phishing"

    below = golden["urls"]["https://xn--bcher-kva.example.com/login"]
    assert below["legacy"]["confidence"] == 0.5
    assert below["legacy"]["is_phishing"] is False
    assert below["tiered"]["classification"] == "suspicious"
