"""Regenerate the phishing lexical baselines.

Two baselines are kept on purpose:

* ``tests/data/phishing_lexical_baseline_pre_stage_e.json`` - the behaviour of
  the scorer *before* stage E touched it. It is never regenerated again; it is
  the audit record of what the original implementation did, including the
  crashes and the scores that stage E later corrected.
* ``tests/data/phishing_lexical_golden.json`` - the locked current behaviour.
  ``tests/test_phishing_golden_replay.py`` replays the corpus against it and
  fails on any drift.

Named without the ``test_`` prefix on purpose: pytest must never rewrite a lock
file as a side effect of running the suite.

Usage (from ``backend/``)::

    python tests/regenerate_phishing_golden.py --out tests/data/phishing_lexical_golden.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.phishing_detector import (  # noqa: E402
    evaluate_phishing_url,
    evaluate_url_phishing,
)

# --------------------------------------------------------------------------
# Corpus
# --------------------------------------------------------------------------
# One entry per lexical indicator (positive / negative / boundary), the tier
# boundaries, and every malformed or evasion shape recorded while auditing
# stage E. IPs are reserved documentation addresses (RFC 5737) except where a
# literal is itself the subject of the case.
URL_CORPUS: List[str] = [
    # Benign shapes
    "https://www.google.com/",
    "https://www.google.com/search?q=cybersecurity",
    "https://example.com/",
    "http://example.com/",
    "https://my.very.long.subdomain.legitimate.com",
    "https://www.github.com",
    "https://example.com:443/status",
    "http://example.com:80/status",
    "https://docs.example.co.uk/manual/page",
    "https://example.com/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q",
    # Indicator positives
    "http://192.168.1.1/login",
    "https://192.0.2.10/verify-account",
    "http://verify-account.update.banking-secure.com/login?token=12345",
    "https://login.paypal.com.scammer-website.net/secure",
    "https://login.paypal.com.scammer-verification.net/auth",
    "http://user:password@example.com",
    "https://example.com:8443/checkout",
    "https://xn--bcher-kva.example.com/login",
    # Punycode hostname that also carries a brand token in a misleading
    # subdomain: the contributions add up to exactly the declared 0.65
    # threshold, so it is the boundary case of the tier decision.
    "https://xn--bcher-kva.paypal.scammer.com",
    "http://secure-account-verification.top/login",
    "https://example.com/redirect?url=http://attacker-controlled-site.xyz/login",
    "https://example.com/out/https://evil.example",
    # Boundary probes (the "https://example.com/" prefix is 20 characters, so the
    # filler length below yields exactly the declared thresholds)
    "https://example.com/" + "a" * 55,  # url_length == 75 (not > 75)
    "https://example.com/" + "a" * 56,  # url_length == 76 (> 75)
    "https://example.com/?a=1&b=2",  # special_chars == 4 (not > 5)
    "https://example.com/?a=1&b=2&c=3&d=4",  # special_chars == 8 (> 5)
    "https://a.b.c.example.com/",  # num_subdomains == 3
    "https://a.b.example.com/",  # num_subdomains == 2
    # Homograph / IDN / obfuscation shapes
    "http://xn--p1as.com/verify",
    "http://\u00fcber-mensch.example.com/login",
    "http://\u0430\u0440\u0430\u0435.com/paypal",
    "http://apple\u202e.com/verify",
    "http://paypal\xa0.com/verify",
    "http://exa mple.com/login",
    "http://exam\x08ple.com",
    "http://example.com/\x00evil",
    "http://256.256.256.256/login",
    "http://1357796046/login",
    "http://0x1.0x2.0x3.0x4/login",
    "http://[::1]/login",
    "http://[fe80::1%25eth0]/x",
    "http://192.0.2.10./verify",
    "http://bad+.com/",
    "http://.leading-dot.com/",
    "http://-bad-start.com/",
    "http://a..b.example.com/",
    # Malformed ports / structure
    "http://example.com:99999/login",
    "http://example.com:notaport/login",
    "http://example.com:0/",
    "http://example.com:/",
    "http://",
    "ftp://example.com/file",
    "example.com/login",
    "//example.com/x",
    "http://user@example.com:23/x",
    # Long / heavy inputs
    "http://" + "a" * 300 + ".com/",
    "https://example.com" + "/path-segment" * 40,
    "http://1.2.3.4/" + "verify-account-login-secure-" * 12,
    "https://www.example.com/account/login?verify=1&update=1&secure=1&password=1&auth=1&confirm=1&support=1&banking=1",
    # Credential-harvesting phish archetypes
    "http://192.168.1.50/update-banking-account-login-verify",
    "https://apple.support.verify.account-login.top/secure/idcard?id=8f2",
    "http://admin:admin@192.0.2.57:8080/session/login?confirm=1",
    # Real-world legitimate HTTPS URLs that this scorer gets wrong. They are in
    # the corpus on purpose: the golden file must record the false positives so
    # nobody can claim precision the scorer does not have. See UNCALIBRATED_NOTE.
    "https://support.google.com/accounts/verify-account-login",
    "https://www.microsoft.com/en-us/security/account-verification/login",
    "https://accounts.google.com/ServiceLogin/signin",
    "https://help.github.com/en/articles/updating-your-password-support",
]

EMAIL_CORPUS: List[Dict[str, str]] = [
    {"sender": "Alice Smith <alice@example.com>", "subject": "Meeting minutes", "body": "Attached are the notes.", "reply_to": ""},
    {
        "sender": "PayPal Security Team <paypal-alerts247@gmail.com>",
        "subject": "URGENT: Your account has been suspended - Verify immediately!",
        "body": "Dear Customer,\nYour account will be suspended within 24 hours due to unauthorized access. Click here to login and update billing: http://192.0.2.10/paypal/verify",
        "reply_to": "stealer@hacker-mailbox.net",
    },
    # A body whose link cannot be parsed - must not crash the whole analysis.
    {"sender": "Alert <a@corp.example>", "subject": "verify", "body": "click http://example.com:99999/login now"},
    {"sender": "Alert <a@corp.example>", "subject": "verify", "body": "click http://example.com:notaport/login now"},
    {"sender": "Alert <a@corp.example>", "subject": "verify", "body": "click http://exa mple.com/login now"},
    {"sender": "PayPal <paypal@paypal.com>", "subject": "Receipt", "body": "Thanks for your order https://www.paypal.com/receipt/1234", "reply_to": ""},
]

SPEAR_CORPUS: List[Dict[str, Any]] = [
    {
        "sender": "John Smith <john.smith@acmecorp.example>",
        "recipient_name": "Sarah Connor",
        "recipient_role": "Operations Manager",
        "subject": "Weekly Department Review",
        "body": "Hi Sarah,\nCould you send over the revised schedule today?\nBest,\nJohn",
        "organization_name": "Acme Corp",
    },
    {
        "sender": "CEO David Miller <david.miller.ceo@gmail.com>",
        "recipient_name": "Robert Langdon",
        "recipient_role": "Chief Financial Officer",
        "subject": "Confidential: Urgent Wire Transfer Required Today",
        "body": "Robert,\nI am in an all-day confidential board meeting and cannot take calls. Execute an urgent wire transfer. Bypass standard PO approval. Keep this strictly confidential.",
        "organization_name": "Acme Corp",
        "claimed_identity": "CEO",
    },
]

FEATURE_KEYS = [
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
]


def _describe_error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def capture_url_case(url: str) -> Dict[str, Any]:
    """Record both public URL entry points for one input."""
    case: Dict[str, Any] = {}
    try:
        is_phishing, confidence, features, explanation, rules = evaluate_phishing_url(url)
        case["legacy"] = {
            "is_phishing": is_phishing,
            "confidence": confidence,
            "features": {k: features.get(k) for k in FEATURE_KEYS},
            "rules": [[r["id"], r["contribution"]] for r in rules],
            "explanation": explanation,
        }
    except Exception as exc:  # noqa: BLE001
        case["legacy"] = {"error": _describe_error(exc)}

    try:
        result = evaluate_url_phishing(url)
        case["tiered"] = {
            "classification": result["classification"],
            "is_phishing": result["is_phishing"],
            "confidence": result["confidence"],
            "risk_score": result["risk_score"],
            "open_redirect_detected": result["features"]["open_redirect_detected"],
            "suspicious_tld": result["features"]["suspicious_tld"],
            "scheme": result["features"]["scheme"],
            "path_depth": result["features"]["path_depth"],
            "rules": [[r["id"], r["contribution"]] for r in result["triggered_rules"]],
        }
    except Exception as exc:  # noqa: BLE001
        case["tiered"] = {"error": _describe_error(exc)}
    return case


def capture_email_case(item: Dict[str, str]) -> Dict[str, Any]:
    from app.services.phishing_detector import evaluate_email_phishing

    try:
        result = evaluate_email_phishing(
            sender=item["sender"],
            subject=item["subject"],
            body=item["body"],
            reply_to=item.get("reply_to") or None,
        )
        return {
            "classification": result["classification"],
            "confidence": result["confidence"],
            "risk_score": result["risk_score"],
            "rules": [[r["id"], r["contribution"]] for r in result["triggered_rules"]],
            "total_links": result["links_analysis"]["total_links"],
            "analyzed_links": len(result["links_analysis"]["all_links"]),
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": _describe_error(exc)}


def capture_spear_case(item: Dict[str, Any]) -> Dict[str, Any]:
    from app.services.phishing_detector import evaluate_spear_phishing

    try:
        result = evaluate_spear_phishing(**item)
        return {
            "classification": result["classification"],
            "confidence": result["confidence"],
            "attack_vector": result["attack_vector"],
            "rules": [[r["id"], r["contribution"]] for r in result["triggered_rules"]],
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": _describe_error(exc)}


def capture() -> Dict[str, Any]:
    # Keys carry the corpus index so that two cases with the same sender/subject
    # (deliberately present for the malformed-link cases) cannot overwrite each
    # other in the recorded file.
    return {
        "comment": (
            "Recorded lexical-scoring behaviour for a fixed corpus. Regenerate with "
            "python tests/regenerate_phishing_golden.py --out "
            "tests/data/phishing_lexical_golden.json"
        ),
        "urls": {url: capture_url_case(url) for url in URL_CORPUS},
        "emails": {
            f"{index:02d}|{item['sender']}|{item['subject']}": capture_email_case(item)
            for index, item in enumerate(EMAIL_CORPUS)
        },
        "spears": {
            f"{index:02d}|{item['subject']}": capture_spear_case(item)
            for index, item in enumerate(SPEAR_CORPUS)
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="destination JSON file")
    args = parser.parse_args()

    destination = Path(args.out)
    payload = capture()

    previous = None
    if destination.exists():
        previous = json.loads(destination.read_text(encoding="utf-8"))

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    changed = 0
    if previous is not None:
        for section in ("urls", "emails", "spears"):
            for key, value in payload[section].items():
                if previous.get(section, {}).get(key) != value:
                    changed += 1
    print(f"wrote {destination}  corpus={len(payload['urls']) + len(payload['emails']) + len(payload['spears'])}  changed cases: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
