"""Email-borne phishing indicator scorer.

Moved verbatim (weights, vocabulary, tiers) from the original
``phishing_detector.py`` monolith during stage E, with one robustness change:
embedded links are analysed through the safe lexical scorer, and a link that
cannot be parsed is recorded and skipped instead of aborting the whole
analysis. Before this change a message body containing
``http://host:99999/login`` made ``POST /api/detect/email`` return HTTP 500.

Like the URL scorer this is a deterministic indicator scorer: hand-set weights,
no trained model, no measured precision/recall.
"""

from __future__ import annotations

import email.utils
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from app.services.phishing.contract import (
    CONFIDENCE_CAP,
    PHISHING_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    saturate,
)
from app.services.phishing.scorer import evaluate_url_phishing
from app.services.phishing.url_features import MalformedURLError, authority_parts

#: Brands frequently impersonated in mass phishing, with the domains that are
#: genuinely theirs. An empty ``official_domains`` marks a claimed *internal*
#: role, which cannot be validated against a registry and is therefore judged
#: against free-webmail usage instead.
SPOOFED_BRANDS = [
    {"name": "PayPal", "keywords": ["paypal"], "official_domains": ["paypal.com", "paypal-communication.com"]},
    {
        "name": "Microsoft",
        "keywords": ["microsoft", "office365", "office 365", "outlook", "onedrive", "sharepoint", "azure"],
        "official_domains": ["microsoft.com", "office.com", "live.com", "outlook.com"],
    },
    {"name": "Google", "keywords": ["google", "gmail", "google drive", "google docs"], "official_domains": ["google.com", "gmail.com"]},
    {"name": "Apple", "keywords": ["apple", "icloud", "apple id", "itunes"], "official_domains": ["apple.com", "icloud.com"]},
    {"name": "Amazon", "keywords": ["amazon", "prime", "aws"], "official_domains": ["amazon.com", "amazonaws.com"]},
    {"name": "Netflix", "keywords": ["netflix"], "official_domains": ["netflix.com"]},
    {
        "name": "Banking / Financial",
        "keywords": ["bank of america", "chase", "wells fargo", "citibank", "capital one", "barclays", "hsbc"],
        "official_domains": ["bankofamerica.com", "chase.com", "wellsfargo.com", "citi.com", "capitalone.com"],
    },
    {
        "name": "Internal IT / HR",
        "keywords": ["it support", "it helpdesk", "help desk", "system administrator", "hr department", "human resources", "payroll department"],
        "official_domains": [],
    },
    {"name": "DocuSign", "keywords": ["docusign"], "official_domains": ["docusign.com", "docusign.net"]},
]

FREE_WEBMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "aol.com",
    "mail.com",
    "protonmail.com",
    "zoho.com",
    "yandex.com",
    "gmx.com",
}

URGENCY_TERMS = [
    "urgent",
    "immediately",
    "immediate action required",
    "account suspended",
    "suspension notice",
    "24 hours",
    "48 hours",
    "unauthorized access",
    "compromised",
    "deactivation warning",
    "final notice",
    "security breach",
    "law enforcement",
    "warrant",
    "action required",
]

CREDENTIAL_HARVEST_PHRASES = [
    "verify your account",
    "confirm your identity",
    "reset your password",
    "update billing",
    "update payment",
    "click here to login",
    "validate credentials",
    "sign in to verify",
    "security checkpoint",
    "unlock account",
    "reactivate account",
    "confirm your pin",
]

GENERIC_SALUTATIONS = [
    "dear customer",
    "dear user",
    "valued client",
    "dear account holder",
    "dear member",
    "dear sir/madam",
    "undisclosed recipients",
]

FINANCIAL_LURE_TERMS = [
    "wire transfer",
    "invoice attached",
    "unclaimed funds",
    "payment overdue",
    "bitcoin payment",
    "cryptocurrency reward",
    "lottery winner",
    "inheritance",
    "western union",
    "past due balance",
]

DANGEROUS_ATTACHMENT_PATTERNS = [
    r"\.exe\b",
    r"\.scr\b",
    r"\.vbs\b",
    r"\.iso\b",
    r"\.bat\b",
    r"\.zip\.exe\b",
    r"\.pdf\.exe\b",
    r"\.hta\b",
]

OFFICIAL_COMMUNICATION_CUES = [
    "support",
    "security",
    "notification",
    "billing",
    "service",
    "verify",
    "account",
    "admin",
    "banking",
]

SENDER_LOOKALIKE_PATTERNS = [
    r"paypa[l1]",
    r"micros[o0]ft",
    r"app[l1]e",
    r"arnazon",
    r"g[o0]{2}g[l1]e",
    r"supp[o0]rt",
    r"sec[u0]rity",
]

#: Domains that legitimately use the lookalike patterns above, so the pattern
#: must not fire against them.
LOOKALIKE_EXEMPT_DOMAINS = ["paypal.com", "microsoft.com", "apple.com", "amazon.com", "google.com"]

_EMBEDDED_URL = re.compile(r'https?://[^\s<>"\')]+')
_ANCHOR_HREF = re.compile(r'<a\s+(?:[^>]*?\s+)?href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE)


def extract_email_address(raw_str: str) -> Tuple[str, str, str]:
    """Return ``(display_name, address, domain)`` from a sender string.

    Never raises: unparseable values yield empty parts, which simply cannot
    trigger the identity indicators.
    """
    if not isinstance(raw_str, str):
        return "", "", ""
    name, addr = email.utils.parseaddr(raw_str.strip())
    if not addr and "@" in raw_str:
        match = re.search(r"[\w.\-]+@[\w.\-]+", raw_str)
        if match:
            addr = match.group(0)
    addr = (addr or "").strip().lower()
    domain = addr.split("@")[-1] if "@" in addr else ""
    return (name or "").strip(), addr, domain.lower() if addr else ""


def _risk_level(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def evaluate_email_phishing(
    sender: str,
    subject: str,
    body: str,
    recipient: Optional[str] = None,
    reply_to: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Analyze email telemetry for deceptive phishing indicators.

    Covers sender identity (display-name spoofing, brand impersonation,
    free-webmail mismatch, Reply-To discrepancy, typosquatting), coercive
    content (urgency, credential-harvesting calls to action, generic
    salutations, financial lures, dangerous attachments) and embedded links
    (destination reputation via the lexical scorer, anchor-text mismatch).
    """
    sender = sender or ""
    subject = subject or ""
    body = body or ""

    sender_name, sender_addr, sender_domain = extract_email_address(sender)
    _reply_name, reply_addr, reply_domain = extract_email_address(reply_to or "")

    score = 0.0
    triggered_rules: Dict[str, Dict[str, Any]] = {}

    def add_rule(id_: str, name: str, explanation: str, contribution: float, feature_vals: Dict[str, Any]) -> None:
        nonlocal score
        score += contribution
        triggered_rules[id_] = {
            "id": id_,
            "name": name,
            "explanation": explanation,
            "contribution": round(contribution, 4),
            "feature_values": feature_vals,
        }

    # 1. SENDER IDENTITY -----------------------------------------------------
    full_sender_text = f"{sender_name} {sender_addr}".lower()
    impersonated_brand = None
    for brand in SPOOFED_BRANDS:
        if not any(keyword in full_sender_text for keyword in brand["keywords"]):
            continue
        if brand["official_domains"] and not any(sender_domain.endswith(domain) for domain in brand["official_domains"]):
            impersonated_brand = brand["name"]
            add_rule(
                "rule_sender_display_spoof",
                "Sender Display Name Spoofing",
                f"Sender claims to represent {brand['name']} but message originates from unauthorized domain '{sender_domain}'.",
                0.40,
                {"claimed_brand": brand["name"], "actual_domain": sender_domain},
            )
            break
        if not brand["official_domains"] and sender_domain in FREE_WEBMAIL_DOMAINS:
            impersonated_brand = brand["name"]
            add_rule(
                "rule_internal_role_webmail",
                "Internal Role from Free Webmail",
                f"Sender claims to represent {brand['name']} using a public webmail domain '{sender_domain}'.",
                0.35,
                {"claimed_role": brand["name"], "domain": sender_domain},
            )
            break

    if not impersonated_brand and sender_domain in FREE_WEBMAIL_DOMAINS:
        if any(cue in full_sender_text for cue in OFFICIAL_COMMUNICATION_CUES):
            add_rule(
                "rule_webmail_for_official_comm",
                "Public Webmail for Official Communication",
                f"Official service notification sent from free public webmail provider ({sender_domain}).",
                0.25,
                {"domain": sender_domain, "sender": sender_addr},
            )

    if reply_domain and sender_domain and reply_domain != sender_domain:
        add_rule(
            "rule_reply_to_mismatch",
            "Reply-To Mismatch",
            f"Reply-To address domain '{reply_domain}' differs from sender domain '{sender_domain}'.",
            0.25,
            {"from_domain": sender_domain, "reply_to_domain": reply_domain},
        )

    for pattern in SENDER_LOOKALIKE_PATTERNS:
        if re.search(pattern, sender_domain, re.IGNORECASE) and not any(
            sender_domain.endswith(domain) for domain in LOOKALIKE_EXEMPT_DOMAINS
        ):
            add_rule(
                "rule_typosquat_sender",
                "Lookalike / Typosquatted Domain",
                f"Sender domain '{sender_domain}' matches known typosquatting pattern.",
                0.35,
                {"sender_domain": sender_domain},
            )
            break

    # 2. CONTENT AND PSYCHOLOGICAL TRIGGERS ---------------------------------
    content_text = f"{subject}\n{body}".lower()

    matched_urgency = [term for term in URGENCY_TERMS if term in content_text]
    if matched_urgency:
        add_rule(
            "rule_urgency_pressure",
            "Urgency & Coercive Pressure",
            f"Message creates artificial urgency or fear using terms: {', '.join(matched_urgency[:3])}.",
            min(0.30, 0.15 + 0.05 * len(matched_urgency)),
            {"matched_terms": matched_urgency},
        )

    matched_cred = [phrase for phrase in CREDENTIAL_HARVEST_PHRASES if phrase in content_text]
    if matched_cred:
        add_rule(
            "rule_credential_harvesting_cta",
            "Credential Harvesting Call-To-Action",
            f"Contains explicit requests to input credentials or verify security details: '{matched_cred[0]}'.",
            min(0.35, 0.20 + 0.05 * len(matched_cred)),
            {"matched_phrases": matched_cred},
        )

    matched_salutation = [salutation for salutation in GENERIC_SALUTATIONS if salutation in content_text]
    if matched_salutation:
        add_rule(
            "rule_generic_salutation",
            "Generic Salutation",
            f"Uses depersonalized generic greeting ('{matched_salutation[0]}') typical of mass phishing campaigns.",
            0.15,
            {"salutation": matched_salutation[0]},
        )

    matched_financial = [term for term in FINANCIAL_LURE_TERMS if term in content_text]
    if matched_financial:
        add_rule(
            "rule_financial_lure",
            "Financial Lure / Fraud Indicators",
            f"Contains financial extortion or fake invoice keywords: {', '.join(matched_financial[:2])}.",
            0.20,
            {"matched_terms": matched_financial},
        )

    for attachment_pattern in DANGEROUS_ATTACHMENT_PATTERNS:
        if re.search(attachment_pattern, content_text, re.IGNORECASE):
            add_rule(
                "rule_dangerous_attachment_reference",
                "Dangerous Attachment Indicator",
                "References high-risk executable or script attachment types.",
                0.35,
                {"matched_pattern": attachment_pattern},
            )
            break

    # 3. EMBEDDED LINKS ------------------------------------------------------
    raw_urls = _EMBEDDED_URL.findall(body)
    analyzed_links: Dict[str, Dict[str, Any]] = {}
    skipped_links: Dict[str, str] = {}
    has_phishing_link = False
    has_insecure_link = False

    # Sorted, de-duplicated traversal keeps the result independent of set
    # ordering (and therefore of PYTHONHASHSEED).
    for url_item in sorted(set(raw_urls)):
        try:
            url_eval = evaluate_url_phishing(url_item)
        except MalformedURLError as exc:
            skipped_links[url_item] = exc.reason
            continue
        except ValueError as exc:  # pragma: no cover - defensive
            skipped_links[url_item] = str(exc)
            continue
        analyzed_links[url_item] = url_eval
        if url_eval["is_phishing"] or url_eval["classification"] in ("phishing", "suspicious"):
            has_phishing_link = True
        if not url_eval["features"]["is_https"]:
            has_insecure_link = True

    if has_phishing_link:
        flagged_count = len([item for item in analyzed_links.values() if item["is_phishing"]])
        add_rule(
            "rule_malicious_embedded_url",
            "Malicious Embedded URL",
            "Contains embedded link(s) exhibiting strong phishing or deceptive characteristics.",
            0.45,
            {"flagged_links_count": flagged_count, "skipped_links": sorted(skipped_links)},
        )
    elif analyzed_links and has_insecure_link:
        add_rule(
            "rule_insecure_links_in_email",
            "Insecure Embedded HTTP Links",
            "Contains unencrypted HTTP links in message content.",
            0.15,
            {"total_links": len(analyzed_links)},
        )

    anchor_mismatches = []
    for href, display in _ANCHOR_HREF.findall(body):
        clean_display = re.sub(r"<[^>]+>", "", display).strip()
        if clean_display.startswith(("http://", "https://")):
            try:
                href_host = extract_host(href)
                display_host = extract_host(clean_display)
            except ValueError:
                continue
            if href_host.lower() != display_host.lower():
                anchor_mismatches.append({"displayed": clean_display, "actual_destination": href})

    if anchor_mismatches:
        add_rule(
            "rule_anchor_destination_mismatch",
            "Hyperlink Text Deception",
            f"Hyperlink display text claims '{anchor_mismatches[0]['displayed']}' but actually redirects to "
            f"'{anchor_mismatches[0]['actual_destination']}'.",
            0.40,
            {"mismatches": anchor_mismatches},
        )

    confidence = saturate(score)
    if confidence >= PHISHING_THRESHOLD:
        classification = "phishing"
    elif confidence >= SUSPICIOUS_THRESHOLD:
        classification = "suspicious"
    else:
        classification = "legitimate"

    risk_score = int(round(confidence * 100))
    explanation = (
        f"Email classified as {classification.upper()} ({_risk_level(risk_score)} risk, "
        f"confidence {int(confidence * 100)}%). " + " ".join(rule["explanation"] for rule in triggered_rules.values())
    ).strip()

    return {
        "classification": classification,
        "is_phishing": confidence >= PHISHING_THRESHOLD,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "confidence_cap": CONFIDENCE_CAP,
        "explanation": explanation,
        "sender_analysis": {
            "display_name": sender_name,
            "address": sender_addr,
            "domain": sender_domain,
            "is_free_webmail": sender_domain in FREE_WEBMAIL_DOMAINS,
            "impersonated_brand": impersonated_brand,
            "reply_to": reply_addr,
            "reply_to_domain": reply_domain,
        },
        "links_analysis": {
            "total_links": len(raw_urls),
            "analyzed_links_count": len(analyzed_links),
            "flagged_links": [item for item in analyzed_links.values() if item["is_phishing"] or item["classification"] != "legitimate"],
            "all_links": list(analyzed_links.values()),
            "skipped_links": [{"url": url, "reason": reason} for url, reason in sorted(skipped_links.items())],
            "anchor_mismatches": anchor_mismatches,
        },
        "triggered_rules": list(triggered_rules.values()),
        "provenance": {
            "model_family": "deterministic indicator scorer",
            "trained_model": False,
            "calibration": "uncalibrated",
            "network_access": False,
            "note": (
                "Email indicators are hand-set weights over declared vocabularies; no message corpus was "
                "used to fit them and no accuracy figure is published. Embedded links are analysed lexically "
                "only - the scorer never fetches a URL, so link reputation reflects structure, not live content."
            ),
        },
    }


def extract_host(url: str) -> str:
    """Host of a URL without the raising ``.port`` property (never resolves)."""
    host = authority_parts(urlparse(url))[1]
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host
