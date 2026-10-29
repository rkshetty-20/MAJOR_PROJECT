"""Targeted (spear) phishing / BEC indicator scorer.

Moved from the original ``phishing_detector.py`` monolith in stage E with two
changes: the embedded-link check uses the safe lexical scorer and skips links it
cannot parse (previously an unparsable first link crashed the endpoint), and the
declared vocabularies live at module scope so tests can assert them.

Deterministic indicator scoring only - hand-set weights, no trained model, no
measured precision/recall, no network access.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from app.services.phishing.contract import PHISHING_THRESHOLD, SUSPICIOUS_THRESHOLD, saturate
from app.services.phishing.email_scorer import FREE_WEBMAIL_DOMAINS, extract_email_address
from app.services.phishing.scorer import evaluate_url_phishing
from app.services.phishing.url_features import MalformedURLError

EXECUTIVE_TITLES = [
    "ceo",
    "chief executive officer",
    "cfo",
    "chief financial officer",
    "coo",
    "chief operating officer",
    "cto",
    "chief technology officer",
    "cio",
    "ciso",
    "president",
    "founder",
    "managing director",
    "vice president",
    "vp",
    "general counsel",
    "board member",
    "head of legal",
]

HIGH_RISK_FINANCIAL_ACTIONS = [
    "wire transfer",
    "wire funds",
    "bank transfer",
    "swift",
    "immediate transfer",
    "ach payment",
    "send payment",
    "overseas account",
    "confidential invoice",
    "settlement payment",
]

PAYROLL_DIVERSION_TERMS = [
    "direct deposit",
    "routing number",
    "bank account change",
    "update my payroll",
    "voided check",
    "payroll information",
]

PII_THEFT_TERMS = [
    "w2",
    "w-2",
    "social security numbers",
    "ssn",
    "employee tax records",
    "staff roster with pii",
    "payroll summary report",
]

GIFT_CARD_TERMS = [
    "gift card",
    "apple card",
    "itunes card",
    "google play card",
    "steam card",
    "amazon gift card",
    "scratch the back",
]

AUTHORITY_COERCION_PHRASES = [
    "as per my instructions",
    "board approved",
    "i am counting on you",
    "treat this as top priority",
    "confidential matter",
    "strictly confidential",
    "keep this between us",
    "private transaction",
]

CHANNEL_ISOLATION_PHRASES = [
    "in a meeting",
    "in an important meeting",
    "boarding a flight",
    "traveling currently",
    "do not call",
    "cannot take calls",
    "email only",
    "phone is off",
    "cannot talk on the phone",
]

APPROVAL_BYPASS_TERMS = [
    "bypass approval",
    "skip the po",
    "skip the purchase order",
    "paperwork later",
    "approve without delay",
]

ROLE_ALIASES = {
    "chief financial officer": ["cfo", "finance", "financial", "wire", "transfer", "treasury", "accounting", "supplier"],
    "chief technology officer": ["cto", "devops", "engineering", "infrastructure", "server", "admin"],
    "chief executive officer": ["ceo", "executive", "board", "leadership"],
    "human resources": ["hr", "payroll", "benefits", "employee"],
    "payroll": ["payroll", "direct deposit", "salary", "compensation"],
    "operations": ["operations", "operational", "schedule", "review"],
}

#: Indicators that represent an active pretext. Personalization indicators alone
#: never make a message malicious, so with none of these present the scorer
#: reports zero confidence instead of a personalization-driven false positive.
THREAT_INDICATORS = frozenset(
    {
        "rule_spear_exec_spoofing",
        "rule_spear_authority_coercion",
        "rule_spear_channel_isolation",
        "rule_spear_bec_wire_fraud",
        "rule_spear_payroll_diversion",
        "rule_spear_pii_theft",
        "rule_spear_gift_card_fraud",
        "rule_spear_approval_bypass",
        "rule_spear_credential_portal",
    }
)

_EMBEDDED_URL = re.compile(r'https?://[^\s<>"\')]+')


def _risk_level(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def evaluate_spear_phishing(
    sender: str,
    recipient_name: str,
    recipient_role: str,
    subject: str,
    body: str,
    organization_name: Optional[str] = None,
    claimed_identity: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluate a targeted message for spear-phishing and BEC indicators."""
    sender = sender or ""
    recipient_name = recipient_name or ""
    recipient_role = recipient_role or ""
    subject = subject or ""
    body = body or ""

    _sender_name, sender_addr, sender_domain = extract_email_address(sender)

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

    text_corpus = f"{subject}\n{body}".lower()

    # 1. PERSONALIZATION -----------------------------------------------------
    personalization_score = 0.0
    recip_clean = recipient_name.strip().lower()
    recip_tokens = [token for token in recip_clean.split() if len(token) > 2]

    target_name_found = bool(recip_clean) and (recip_clean in text_corpus or any(token in text_corpus for token in recip_tokens))
    if target_name_found:
        personalization_score += 0.25
        add_rule(
            "rule_spear_recipient_name",
            "Personalized Target Addressing",
            f"Message specifically addresses recipient by name ('{recipient_name}'), indicating targeted reconnaissance.",
            0.20,
            {"recipient_name": recipient_name},
        )

    role_clean = recipient_role.strip().lower()
    role_tokens = [token for token in role_clean.split() if len(token) > 3]
    for key, aliases in ROLE_ALIASES.items():
        if key in role_clean or any(part in role_clean for part in key.split()):
            role_tokens.extend(aliases)

    role_found = bool(role_clean) and (role_clean in text_corpus or any(token in text_corpus for token in role_tokens))
    if role_found:
        personalization_score += 0.25
        add_rule(
            "rule_spear_role_alignment",
            "Role & Department Tailoring",
            f"Message content specifically aligns with recipient's organizational role ('{recipient_role}').",
            0.20,
            {"recipient_role": recipient_role},
        )

    org_found = bool(organization_name and organization_name.strip().lower() in text_corpus)
    if org_found:
        personalization_score += 0.20
        add_rule(
            "rule_spear_org_context",
            "Internal Organization Context",
            f"Message explicitly references internal organization name '{organization_name}'.",
            0.15,
            {"organization_name": organization_name},
        )

    personalization_level = "high" if personalization_score >= 0.40 else ("moderate" if personalization_score > 0 else "none")

    # 2. IMPERSONATION AND AUTHORITY ---------------------------------------
    claimed_exec = None
    sender_corpus = f"{_sender_name} {claimed_identity or ''}".lower()
    for title in EXECUTIVE_TITLES:
        if title in sender_corpus or title in text_corpus:
            claimed_exec = title.upper()
            break

    is_external_or_webmail = sender_domain in FREE_WEBMAIL_DOMAINS or bool(
        organization_name and organization_name.lower().replace(" ", "") not in sender_domain
    )

    if claimed_exec:
        if is_external_or_webmail:
            add_rule(
                "rule_spear_exec_spoofing",
                "Executive / Leadership Spoofing",
                f"Sender purports to be leadership ({claimed_exec}) but communicates from external/unverified domain '{sender_domain}'.",
                0.40,
                {"claimed_title": claimed_exec, "sender_domain": sender_domain},
            )
        else:
            add_rule(
                "rule_spear_executive_presence",
                "Executive Directive Pattern",
                f"Message invokes executive authority ({claimed_exec}).",
                0.15,
                {"claimed_title": claimed_exec},
            )

    matched_authority = [phrase for phrase in AUTHORITY_COERCION_PHRASES if phrase in text_corpus]
    if matched_authority:
        add_rule(
            "rule_spear_authority_coercion",
            "Executive Pressure & Secrecy Demand",
            f"Demands strict confidentiality or asserts unverified executive authority ('{matched_authority[0]}').",
            0.25,
            {"matched_phrases": matched_authority},
        )

    matched_isolation = [phrase for phrase in CHANNEL_ISOLATION_PHRASES if phrase in text_corpus]
    if matched_isolation:
        add_rule(
            "rule_spear_channel_isolation",
            "Channel Isolation (Suppression of Out-of-Band Verification)",
            f"Adversary attempts to prevent voice or in-person verification ('{matched_isolation[0]}').",
            0.30,
            {"matched_phrases": matched_isolation},
        )

    # 3. REQUEST VECTOR ------------------------------------------------------
    attack_vector = "general_spear_phish"

    matched_wire = [term for term in HIGH_RISK_FINANCIAL_ACTIONS if term in text_corpus]
    if matched_wire:
        attack_vector = "bec_wire_fraud"
        add_rule(
            "rule_spear_bec_wire_fraud",
            "Business Email Compromise (Wire Transfer Fraud)",
            f"Directs urgent out-of-band wire transfer or sensitive fund transfer: '{matched_wire[0]}'.",
            0.45,
            {"matched_terms": matched_wire},
        )

    matched_payroll = [term for term in PAYROLL_DIVERSION_TERMS if term in text_corpus]
    if matched_payroll:
        attack_vector = "payroll_diversion"
        add_rule(
            "rule_spear_payroll_diversion",
            "Payroll / Direct Deposit Diversion",
            "Requests changes to direct deposit or employee banking details without standard workflow.",
            0.45,
            {"matched_terms": matched_payroll},
        )

    matched_pii = [term for term in PII_THEFT_TERMS if term in text_corpus]
    if matched_pii:
        attack_vector = "pii_w2_theft"
        add_rule(
            "rule_spear_pii_theft",
            "Employee PII / W-2 Form Exfiltration",
            "Requests bulk employee tax records, W-2 forms, or SSN datasets.",
            0.45,
            {"matched_terms": matched_pii},
        )

    matched_gift = [term for term in GIFT_CARD_TERMS if term in text_corpus]
    if matched_gift:
        attack_vector = "gift_card_scam"
        add_rule(
            "rule_spear_gift_card_fraud",
            "Executive Gift Card Purchase Scam",
            "Requests immediate purchase of retail gift cards on behalf of leadership.",
            0.40,
            {"matched_terms": matched_gift},
        )

    matched_bypass = [term for term in APPROVAL_BYPASS_TERMS if term in text_corpus]
    if matched_bypass:
        add_rule(
            "rule_spear_approval_bypass",
            "Security / Approval Process Circumvention",
            f"Explicitly instructs the recipient to bypass established verification protocols: '{matched_bypass[0]}'.",
            0.25,
            {"matched_terms": matched_bypass},
        )

    # 4. EMBEDDED LINK -------------------------------------------------------
    raw_urls = _EMBEDDED_URL.findall(body)
    skipped_links: Dict[str, str] = {}
    link_eval: Optional[Dict[str, Any]] = None
    for candidate in raw_urls:
        try:
            link_eval = evaluate_url_phishing(candidate)
        except MalformedURLError as exc:
            skipped_links[candidate] = exc.reason
            continue
        except ValueError as exc:  # pragma: no cover - defensive
            skipped_links[candidate] = str(exc)
            continue
        break

    if link_eval is not None and link_eval["is_phishing"]:
        add_rule(
            "rule_spear_credential_portal",
            "Targeted Credential Harvesting Link",
            "Includes a tailored login portal link identified as deceptive.",
            0.35,
            {"url": link_eval["url"], "skipped_links": sorted(skipped_links)},
        )

    has_active_threat = any(rule_id in THREAT_INDICATORS for rule_id in triggered_rules)
    if not has_active_threat:
        confidence = 0.0
        classification = "legitimate"
        attack_vector = "benign"
    else:
        confidence = saturate(score)
        if confidence >= PHISHING_THRESHOLD:
            classification = "phishing"
        elif confidence >= SUSPICIOUS_THRESHOLD:
            classification = "suspicious"
        else:
            classification = "legitimate"
            attack_vector = "benign"

    risk_score = int(round(confidence * 100))
    risk_level = _risk_level(risk_score)

    countermeasures: List[str] = []
    if attack_vector == "bec_wire_fraud":
        countermeasures.append("Perform dual-authorization telephone confirmation using internally registered company directory extension.")
        countermeasures.append("Never execute out-of-band wire changes without signed purchase order confirmation.")
    elif attack_vector == "payroll_diversion":
        countermeasures.append("Require employee to authenticate directly through internal HR portal; do not accept email direct deposit change requests.")
    elif attack_vector == "gift_card_scam":
        countermeasures.append("Recognize that corporate leadership will never request gift card purchases or scratch-off codes via email.")
    elif attack_vector == "pii_w2_theft":
        countermeasures.append("Do not transmit W-2 or tax information via unencrypted email; verify requests directly with General Counsel.")
    elif attack_vector != "benign":
        countermeasures.append("Verify the sender's identity using an alternative, authenticated communication channel.")

    explanation = (
        f"Message classified as {'SPEAR PHISHING' if classification != 'legitimate' else 'NOT TARGETED PHISHING'} "
        f"({risk_level} risk, attack vector: {attack_vector.upper()}). "
        + " ".join(rule["explanation"] for rule in triggered_rules.values())
    ).strip()

    return {
        "classification": classification,
        "is_phishing": confidence >= PHISHING_THRESHOLD,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "attack_vector": attack_vector,
        "personalization": {
            "level": personalization_level,
            "target_name_matched": target_name_found,
            "role_matched": role_found,
            "organization_matched": org_found,
            "score": round(personalization_score, 2),
        },
        "impersonation": {
            "claimed_leadership": claimed_exec,
            "sender_domain": sender_domain,
            "sender_address": sender_addr,
            "is_external": is_external_or_webmail,
        },
        "link_analysis": {
            "evaluated": link_eval["url"] if link_eval else None,
            "skipped": [{"url": url, "reason": reason} for url, reason in sorted(skipped_links.items())],
        },
        "explanation": explanation,
        "triggered_rules": list(triggered_rules.values()),
        "recommended_countermeasures": countermeasures,
        "provenance": {
            "model_family": "deterministic indicator scorer",
            "trained_model": False,
            "calibration": "uncalibrated",
            "network_access": False,
            "note": (
                "Spear-phishing indicators are hand-set weights over declared phrase vocabularies; they "
                "detect the *textual pretext* of a message, not the identity of its sender. Authentication "
                "results (SPF/DKIM/DMARC) are not available to this scorer and are not simulated."
            ),
        },
    }
