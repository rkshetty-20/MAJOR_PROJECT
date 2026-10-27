import re
from urllib.parse import urlparse, unquote, parse_qs
from typing import Dict, Any, Tuple, List, Optional
import os
import base64
import httpx
import logging
import ipaddress
import time

# tldextract is an optional dependency. When absent, a minimal offline
# fallback is used that understands common multi-part suffixes.
try:
    import tldextract as _tldextract  # type: ignore

    def _extract_domain(url: str):
        return _tldextract.extract(url)

except ImportError:  # pragma: no cover
    _tldextract = None  # type: ignore

    # Common two-part TLD suffixes for the fallback parser.
    _COMMON_SUFFIXES = {
        "co.uk", "co.in", "co.jp", "com.au", "com.br", "org.uk",
        "net.au", "co.za", "gov.uk", "ac.uk",
    }

    class _TLDResult:
        """Minimal struct mirroring tldextract.ExtractResult."""
        def __init__(self, subdomain: str, domain: str, suffix: str) -> None:
            self.subdomain = subdomain
            self.domain = domain
            self.suffix = suffix
            self.top_domain_under_public_suffix = f"{domain}.{suffix}" if domain else ""
            self.registered_domain = self.top_domain_under_public_suffix

    def _extract_domain(url: str) -> _TLDResult:  # type: ignore
        try:
            hostname = urlparse(url).hostname or ""
        except Exception:
            hostname = ""
        if not hostname:
            return _TLDResult("", "", "")
        parts = hostname.split(".")
        if len(parts) < 2:
            return _TLDResult("", hostname, "")
        # Check for known two-part suffix
        if len(parts) >= 3 and ".".join(parts[-2:]) in _COMMON_SUFFIXES:
            suffix = ".".join(parts[-2:])
            domain = parts[-3]
            subdomain = ".".join(parts[:-3])
        else:
            suffix = parts[-1]
            domain = parts[-2]
            subdomain = ".".join(parts[:-2])
        return _TLDResult(subdomain, domain, suffix)

logger = logging.getLogger(__name__)

# Cache for URL reputation. Structure: { url_id: {"data": dict, "timestamp": float} }
_reputation_cache = {}
CACHE_TTL_SECONDS = 3600 # 1 hour

def extract_phishing_features(url: str) -> Dict[str, Any]:
    """
    Extracts features from a URL for phishing detection.
    """
    if not isinstance(url, str):
        raise ValueError("URL must be a string")

    # Basic normalization
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty")

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
    except Exception:
        hostname = ""
        path = ""
        
    if not hostname:
        raise ValueError("URL must include a valid hostname")
        
    ext = _extract_domain(url)

    # 1. URL Length
    url_length = len(url)
    
    # 2. Hostname length
    hostname_length = len(hostname)
    
    # 3. Number of subdomains
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False
        
    num_subdomains = 0
    if not is_ip and ext.subdomain:
        # e.g., 'a.b' has 1 dot -> 2 subdomains
        num_subdomains = ext.subdomain.count('.') + 1

    # 4. Special characters count in URL
    special_chars = sum(1 for c in url if c in ['-', '_', '@', '?', '=', '&', '%'])
    
    # 5. HTTPS usage
    is_https = url.startswith("https://")
    
    # 6. Suspicious keywords in URL
    suspicious_tokens = ['verify', 'account', 'login', 'secure', 'update', 'banking', 'support', 'password', 'auth', 'confirm']
    keyword_count = sum(1 for token in suspicious_tokens if token in url.lower())

    # 7. Punycode detection
    is_punycode = "xn--" in hostname.lower()

    # 8. Misleading subdomains (e.g. login.paypal.com.scammer.com)
    brands = ['paypal', 'google', 'apple', 'microsoft', 'amazon', 'netflix', 'facebook']
    has_misleading_subdomain = False
    if not is_ip and ext.subdomain:
        # Check if brand is in subdomain
        if any(brand in ext.subdomain.lower() for brand in brands) or any(tok in ext.subdomain.lower() for tok in suspicious_tokens):
            has_misleading_subdomain = True
            
    # New feature: credentials in authority
    has_credentials = bool(parsed.username or parsed.password)
    
    # New feature: unusual port
    unusual_port = False
    if parsed.port and parsed.port not in [80, 443]:
        unusual_port = True

    return {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "num_subdomains": num_subdomains,
        "special_chars": special_chars,
        "is_ip": is_ip,
        "is_https": is_https,
        "keyword_count": keyword_count,
        "is_punycode": is_punycode,
        "has_misleading_subdomain": has_misleading_subdomain,
        "has_credentials": has_credentials,
        "unusual_port": unusual_port,
        "domain": f"{ext.domain}.{ext.suffix}" if getattr(ext, "suffix", "") else getattr(ext, "domain", "")
    }


def evaluate_phishing_url(url: str) -> Tuple[bool, float, Dict[str, Any], str, List[Dict[str, Any]]]:
    """
    Evaluates a URL based on extracted features and returns:
    (is_phishing, confidence, feature_dict, deterministic_explanation, triggered_rules)
    """
    features = extract_phishing_features(url)
    
    score = 0.0
    reasons = []
    triggered_rules = []
    
    def add_rule(id_, name, explanation, contribution, feat_vals):
        nonlocal score
        score += contribution
        reasons.append(explanation)
        triggered_rules.append({
            "id": id_,
            "name": name,
            "explanation": explanation,
            "contribution": contribution,
            "feature_values": feat_vals
        })
    
    if features["is_ip"]:
        add_rule("rule_ip_host", "IP Address Hostname", "Uses an IP address instead of a hostname.", 0.4, {"is_ip": True})
        
    if not features["is_https"]:
        add_rule("rule_no_https", "Insecure Protocol", "Does not use secure HTTPS.", 0.2, {"is_https": False})
        
    if features["keyword_count"] > 0:
        contr = 0.2 * features["keyword_count"]
        add_rule("rule_suspicious_keywords", "Suspicious Keywords", f"Contains {features['keyword_count']} suspicious or credential-harvesting keywords.", contr, {"keyword_count": features["keyword_count"]})
        
    if features["num_subdomains"] >= 3:
        add_rule("rule_many_subdomains", "Excessive Subdomains", f"Has an unusually high number of subdomains ({features['num_subdomains']}).", 0.15, {"num_subdomains": features["num_subdomains"]})
        
    if features["url_length"] > 75:
        add_rule("rule_long_url", "Long URL", "URL length is unusually long.", 0.1, {"url_length": features["url_length"]})
        
    if features["special_chars"] > 5:
        add_rule("rule_special_chars", "Many Special Characters", "Contains many special characters, often used for obfuscation.", 0.1, {"special_chars": features["special_chars"]})

    if features["is_punycode"]:
        add_rule("rule_punycode", "Punycode Detected", "Uses Punycode (often used in homograph attacks).", 0.3, {"is_punycode": True})

    if features["has_misleading_subdomain"]:
        add_rule("rule_misleading_subdomain", "Misleading Subdomain", "Contains misleading brand names or keywords in subdomains.", 0.35, {"has_misleading_subdomain": True})
        
    if features["has_credentials"]:
        add_rule("rule_credentials", "Credentials in URL", "Contains credentials (username/password) embedded in the URL.", 0.3, {"has_credentials": True})
        
    if features["unusual_port"]:
        add_rule("rule_unusual_port", "Unusual Port", "Connects to a non-standard HTTP/HTTPS port.", 0.1, {"unusual_port": True})
        
    # Cap score at 0.99
    confidence = min(0.99, round(score, 4))
    
    is_phishing = confidence >= 0.65

    if is_phishing:
        explanation = "Suspicious URL identified. " + " ".join(reasons)
    else:
        explanation = "URL appears benign. " + " ".join(reasons)
    
    return is_phishing, confidence, features, explanation.strip(), triggered_rules


# ===========================================================================
# 1. ENHANCED URL PHISHING DETECTION MODULE
# ===========================================================================

def evaluate_url_phishing(url: str) -> Dict[str, Any]:
    """
    Evaluates submitted URLs using comprehensive lexical and structural features:
    - HTTPS usage and protocol security
    - Domain characteristics (IP hosts, domain length, entropy, subdomains, punycode)
    - Suspicious TLD patterns
    - URL length and path complexity
    - Suspicious symbols and obfuscation (@, -, //, %)
    - Open redirect indicators in parameters and path
    - Classification: legitimate (< 0.35), suspicious (0.35 - 0.64), phishing (>= 0.65)
    """
    is_phishing_flag, confidence, features, base_explanation, triggered_rules = evaluate_phishing_url(url)
    
    parsed = urlparse(url.strip())
    query_params = parse_qs(parsed.query)
    
    # Check for open redirects
    redirect_keys = ["url", "redirect", "redirect_url", "redirect_uri", "next", "return", "return_to", "dest", "destination", "target", "r", "goto", "link"]
    found_redirects = []
    redirect_risk = False
    
    for key in redirect_keys:
        if key in query_params:
            for val in query_params[key]:
                if val.startswith("http://") or val.startswith("https://") or val.startswith("//"):
                    found_redirects.append({"param": key, "target": val})
                    redirect_risk = True

    # Check path for embedded URLs e.g. /redirect/http://evil.com
    path_redirect_match = re.search(r'/(?:redirect|out|forward|goto)/(https?://[^\s/]+)', parsed.path, re.IGNORECASE)
    if path_redirect_match:
        found_redirects.append({"param": "path", "target": path_redirect_match.group(1)})
        redirect_risk = True

    # Check for high-risk TLDs commonly abused in automated phishing
    suspicious_tlds = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".club", ".work", ".fit", ".surf", ".monster", ".icu"}
    domain_str = features.get("domain", "").lower()
    has_suspicious_tld = any(domain_str.endswith(tld) for tld in suspicious_tlds)
    
    extra_rules = list(triggered_rules)
    adjusted_score = confidence

    if redirect_risk:
        redirect_rule = {
            "id": "rule_open_redirect",
            "name": "Potential Open Redirect",
            "explanation": f"Contains URL redirection parameter ({found_redirects[0]['param']} -> {found_redirects[0]['target']}).",
            "contribution": 0.25,
            "feature_values": {"redirects": found_redirects}
        }
        extra_rules.append(redirect_rule)
        adjusted_score = min(0.99, adjusted_score + 0.25)

    if has_suspicious_tld:
        tld_rule = {
            "id": "rule_suspicious_tld",
            "name": "Suspicious TLD",
            "explanation": f"Domain utilizes a TLD frequently leveraged in malicious campaigns ({domain_str}).",
            "contribution": 0.15,
            "feature_values": {"domain": domain_str}
        }
        extra_rules.append(tld_rule)
        adjusted_score = min(0.99, adjusted_score + 0.15)

    adjusted_score = round(adjusted_score, 4)

    # Multi-tier classification: legitimate, suspicious, phishing
    if adjusted_score >= 0.65:
        classification = "phishing"
    elif adjusted_score >= 0.35:
        classification = "suspicious"
    else:
        classification = "legitimate"

    return {
        "url": url,
        "classification": classification,
        "is_phishing": adjusted_score >= 0.65,
        "confidence": adjusted_score,
        "risk_score": int(round(adjusted_score * 100)),
        "explanation": f"Classified as {classification.upper()} (score: {int(adjusted_score * 100)}/100). " + base_explanation,
        "features": {
            **features,
            "open_redirect_detected": redirect_risk,
            "redirect_targets": found_redirects,
            "suspicious_tld": has_suspicious_tld,
            "scheme": parsed.scheme,
            "path_depth": len([seg for seg in parsed.path.split("/") if seg]),
        },
        "triggered_rules": extra_rules,
    }


# ===========================================================================
# 2. EMAIL PHISHING DETECTION MODULE
# ===========================================================================

# Notable brands frequently impersonated in mass phishing
_SPOOFED_BRANDS = [
    {"name": "PayPal", "keywords": ["paypal"], "official_domains": ["paypal.com", "paypal-communication.com"]},
    {"name": "Microsoft", "keywords": ["microsoft", "office365", "office 365", "outlook", "onedrive", "sharepoint", "azure"], "official_domains": ["microsoft.com", "office.com", "live.com", "outlook.com"]},
    {"name": "Google", "keywords": ["google", "gmail", "google drive", "google docs"], "official_domains": ["google.com", "gmail.com"]},
    {"name": "Apple", "keywords": ["apple", "icloud", "apple id", "itunes"], "official_domains": ["apple.com", "icloud.com"]},
    {"name": "Amazon", "keywords": ["amazon", "prime", "aws"], "official_domains": ["amazon.com", "amazonaws.com"]},
    {"name": "Netflix", "keywords": ["netflix"], "official_domains": ["netflix.com"]},
    {"name": "Banking / Financial", "keywords": ["bank of america", "chase", "wells fargo", "citibank", "capital one", "barclays", "hsbc"], "official_domains": ["bankofamerica.com", "chase.com", "wellsfargo.com", "citi.com", "capitalone.com"]},
    {"name": "Internal IT / HR", "keywords": ["it support", "it helpdesk", "help desk", "system administrator", "hr department", "human resources", "payroll department"], "official_domains": []},
    {"name": "DocuSign", "keywords": ["docusign"], "official_domains": ["docusign.com", "docusign.net"]},
]

_FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "mail.com", "protonmail.com", "zoho.com", "yandex.com", "gmx.com"
}


def _extract_email_address(raw_str: str) -> Tuple[str, str, str]:
    """Extracts (display_name, email_address, domain) from a sender string."""
    import email.utils
    name, addr = email.utils.parseaddr(raw_str.strip())
    if not addr and "@" in raw_str:
        # Fallback regex extraction
        match = re.search(r'[\w\.-]+@[\w\.-]+', raw_str)
        if match:
            addr = match.group(0)
    domain = addr.split("@")[-1].lower() if "@" in addr else ""
    return name.strip(), addr.strip().lower(), domain


def evaluate_email_phishing(
    sender: str,
    subject: str,
    body: str,
    recipient: Optional[str] = None,
    reply_to: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Analyzes email telemetry for deceptive phishing indicators:
    - Sender details: display-name spoofing, brand impersonation, free webmail mismatch, reply-to discrepancies
    - Content analysis: psychological urgency/fear triggers, credential harvesting calls to action, generic greetings
    - Link analysis: extraction of all embedded URLs, evaluating destination threat level and anchor text mismatch
    - Malicious attachment indicators (double extensions, script payloads)
    - Returns structured classification, risk score, confidence, and rule contributions
    """
    sender_name, sender_addr, sender_domain = _extract_email_address(sender)
    reply_name, reply_addr, reply_domain = _extract_email_address(reply_to or "")
    
    score = 0.0
    triggered_rules = []
    
    def add_rule(id_: str, name: str, explanation: str, contribution: float, feature_vals: Dict[str, Any]):
        nonlocal score
        score += contribution
        triggered_rules.append({
            "id": id_,
            "name": name,
            "explanation": explanation,
            "contribution": contribution,
            "feature_values": feature_vals
        })

    # 1. SENDER ANALYSIS
    # A. Display name brand impersonation vs domain mismatch
    full_sender_text = f"{sender_name} {sender_addr}".lower()
    impersonated_brand = None
    for brand in _SPOOFED_BRANDS:
        if any(kw in full_sender_text for kw in brand["keywords"]):
            if brand["official_domains"] and not any(sender_domain.endswith(d) for d in brand["official_domains"]):
                impersonated_brand = brand["name"]
                add_rule(
                    "rule_sender_display_spoof",
                    "Sender Display Name Spoofing",
                    f"Sender claims to represent {brand['name']} but message originates from unauthorized domain '{sender_domain}'.",
                    0.40,
                    {"claimed_brand": brand["name"], "actual_domain": sender_domain}
                )
                break
            elif not brand["official_domains"] and sender_domain in _FREE_WEBMAIL_DOMAINS:
                impersonated_brand = brand["name"]
                add_rule(
                    "rule_internal_role_webmail",
                    "Internal Role from Free Webmail",
                    f"Sender claims to represent {brand['name']} using a public webmail domain '{sender_domain}'.",
                    0.35,
                    {"claimed_role": brand["name"], "domain": sender_domain}
                )
                break

    # B. Free webmail provider for official corporate notifications
    if not impersonated_brand and sender_domain in _FREE_WEBMAIL_DOMAINS:
        official_cues = ["support", "security", "notification", "billing", "service", "verify", "account", "admin", "banking"]
        if any(cue in full_sender_text for cue in official_cues):
            add_rule(
                "rule_webmail_for_official_comm",
                "Public Webmail for Official Communication",
                f"Official service notification sent from free public webmail provider ({sender_domain}).",
                0.25,
                {"domain": sender_domain, "sender": sender_addr}
            )

    # C. Reply-To domain mismatch
    if reply_domain and sender_domain and reply_domain != sender_domain:
        add_rule(
            "rule_reply_to_mismatch",
            "Reply-To Mismatch",
            f"Reply-To address domain '{reply_domain}' differs from sender domain '{sender_domain}'.",
            0.25,
            {"from_domain": sender_domain, "reply_to_domain": reply_domain}
        )

    # D. Lookalike / typosquatted sender domain characters
    lookalike_patterns = [r'paypa[l1]', r'micros[o0]ft', r'app[l1]e', r'arnazon', r'g[o0]{2}g[l1]e', r'supp[o0]rt', r'sec[u0]rity']
    for pat in lookalike_patterns:
        if re.search(pat, sender_domain, re.IGNORECASE) and not any(sender_domain.endswith(d) for d in ["paypal.com", "microsoft.com", "apple.com", "amazon.com", "google.com"]):
            add_rule(
                "rule_typosquat_sender",
                "Lookalike / Typosquatted Domain",
                f"Sender domain '{sender_domain}' matches known typosquatting pattern.",
                0.35,
                {"sender_domain": sender_domain}
            )
            break

    # 2. CONTENT & PSYCHOLOGICAL TRIGGERS
    content_text = f"{subject}\n{body}".lower()

    # A. Urgency / fear / coercion cues
    urgency_terms = [
        "urgent", "immediately", "immediate action required", "account suspended", "suspension notice",
        "24 hours", "48 hours", "unauthorized access", "compromised", "deactivation warning",
        "final notice", "security breach", "law enforcement", "warrant", "action required"
    ]
    matched_urgency = [term for term in urgency_terms if term in content_text]
    if matched_urgency:
        contr = min(0.30, 0.15 + 0.05 * len(matched_urgency))
        add_rule(
            "rule_urgency_pressure",
            "Urgency & Coercive Pressure",
            f"Message creates artificial urgency or fear using terms: {', '.join(matched_urgency[:3])}.",
            contr,
            {"matched_terms": matched_urgency}
        )

    # B. Credential harvesting call to action
    cred_harvest_phrases = [
        "verify your account", "confirm your identity", "reset your password", "update billing",
        "update payment", "click here to login", "validate credentials", "sign in to verify",
        "security checkpoint", "unlock account", "reactivate account", "confirm your pin"
    ]
    matched_cred = [phrase for phrase in cred_harvest_phrases if phrase in content_text]
    if matched_cred:
        contr = min(0.35, 0.20 + 0.05 * len(matched_cred))
        add_rule(
            "rule_credential_harvesting_cta",
            "Credential Harvesting Call-To-Action",
            f"Contains explicit requests to input credentials or verify security details: '{matched_cred[0]}'.",
            contr,
            {"matched_phrases": matched_cred}
        )

    # C. Generic / depersonalized salutation
    generic_salutations = ["dear customer", "dear user", "valued client", "dear account holder", "dear member", "dear sir/madam", "undisclosed recipients"]
    matched_salutation = [sal for sal in generic_salutations if sal in content_text]
    if matched_salutation:
        add_rule(
            "rule_generic_salutation",
            "Generic Salutation",
            f"Uses depersonalized generic greeting ('{matched_salutation[0]}') typical of mass phishing campaigns.",
            0.15,
            {"salutation": matched_salutation[0]}
        )

    # D. Financial lure / fake invoice
    financial_terms = [
        "wire transfer", "invoice attached", "unclaimed funds", "payment overdue", "bitcoin payment",
        "cryptocurrency reward", "lottery winner", "inheritance", "western union", "past due balance"
    ]
    matched_fin = [t for t in financial_terms if t in content_text]
    if matched_fin:
        add_rule(
            "rule_financial_lure",
            "Financial Lure / Fraud Indicators",
            f"Contains financial extortion or fake invoice keywords: {', '.join(matched_fin[:2])}.",
            0.20,
            {"matched_terms": matched_fin}
        )

    # E. Dangerous attachment references
    dangerous_exts = [r'\.exe\b', r'\.scr\b', r'\.vbs\b', r'\.iso\b', r'\.bat\b', r'\.zip\.exe\b', r'\.pdf\.exe\b', r'\.hta\b']
    for ext_pat in dangerous_exts:
        if re.search(ext_pat, content_text, re.IGNORECASE):
            add_rule(
                "rule_dangerous_attachment_reference",
                "Dangerous Attachment Indicator",
                "References high-risk executable or script attachment types.",
                0.35,
                {"matched_pattern": ext_pat}
            )
            break

    # 3. LINK EXTRACTION & ANALYSIS
    raw_urls = re.findall(r'https?://[^\s<>"\')]+', body)
    analyzed_links = []
    has_phishing_link = False
    has_insecure_link = False
    
    for url_item in set(raw_urls):
        url_eval = evaluate_url_phishing(url_item)
        analyzed_links.append(url_eval)
        if url_eval["is_phishing"] or url_eval["classification"] in ["phishing", "suspicious"]:
            has_phishing_link = True
        if not url_eval["features"]["is_https"]:
            has_insecure_link = True

    if has_phishing_link:
        add_rule(
            "rule_malicious_embedded_url",
            "Malicious Embedded URL",
            "Contains embedded link(s) exhibiting strong phishing or deceptive characteristics.",
            0.45,
            {"flagged_links_count": len([l for l in analyzed_links if l["is_phishing"]])}
        )
    elif analyzed_links and has_insecure_link:
        add_rule(
            "rule_insecure_links_in_email",
            "Insecure Embedded HTTP Links",
            "Contains unencrypted HTTP links in message content.",
            0.15,
            {"total_links": len(analyzed_links)}
        )

    # Check for anchor text mismatch if HTML is present
    anchor_mismatches = []
    for href, display in re.findall(r'<a\s+(?:[^>]*?\s+)?href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>', body, re.IGNORECASE):
        clean_display = re.sub(r'<[^>]+>', '', display).strip()
        if clean_display.startswith("http://") or clean_display.startswith("https://"):
            parsed_href = urlparse(href)
            parsed_disp = urlparse(clean_display)
            if parsed_href.netloc.lower() != parsed_disp.netloc.lower():
                anchor_mismatches.append({"displayed": clean_display, "actual_destination": href})

    if anchor_mismatches:
        add_rule(
            "rule_anchor_destination_mismatch",
            "Hyperlink Text Deception",
            f"Hyperlink display text claims '{anchor_mismatches[0]['displayed']}' but actually redirects to '{anchor_mismatches[0]['actual_destination']}'.",
            0.40,
            {"mismatches": anchor_mismatches}
        )

    # Compute final score & confidence
    confidence = min(0.99, round(score, 4))
    
    if confidence >= 0.65:
        classification = "phishing"
    elif confidence >= 0.35:
        classification = "suspicious"
    else:
        classification = "legitimate"

    risk_score = int(round(confidence * 100))
    if risk_score >= 85:
        risk_level = "CRITICAL"
    elif risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    explanation = (
        f"Email classified as {classification.upper()} ({risk_level} risk, confidence {int(confidence * 100)}%). "
        + " ".join(r["explanation"] for r in triggered_rules)
    ).strip()

    return {
        "classification": classification,
        "is_phishing": confidence >= 0.65,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "explanation": explanation,
        "sender_analysis": {
            "display_name": sender_name,
            "address": sender_addr,
            "domain": sender_domain,
            "is_free_webmail": sender_domain in _FREE_WEBMAIL_DOMAINS,
            "impersonated_brand": impersonated_brand,
        },
        "links_analysis": {
            "total_links": len(raw_urls),
            "flagged_links": [l for l in analyzed_links if l["is_phishing"] or l["classification"] != "legitimate"],
            "all_links": analyzed_links,
            "anchor_mismatches": anchor_mismatches,
        },
        "triggered_rules": triggered_rules,
    }


# ===========================================================================
# 3. SPEAR PHISHING DETECTION MODULE
# ===========================================================================

_EXECUTIVE_TITLES = [
    "ceo", "chief executive officer", "cfo", "chief financial officer", "coo", "chief operating officer",
    "cto", "chief technology officer", "cio", "ciso", "president", "founder", "managing director",
    "vice president", "vp", "general counsel", "board member", "head of legal"
]

_HIGH_RISK_FINANCIAL_ACTIONS = [
    "wire transfer", "wire funds", "bank transfer", "swift", "immediate transfer", "ach payment",
    "send payment", "overseas account", "confidential invoice", "settlement payment"
]

_PAYROLL_DIVERT_TERMS = [
    "direct deposit", "routing number", "bank account change", "update my payroll", "voided check", "payroll information"
]

_PII_THEFT_TERMS = [
    "w2", "w-2", "social security numbers", "ssn", "employee tax records", "staff roster with pii", "payroll summary report"
]

_GIFT_CARD_TERMS = [
    "gift card", "apple card", "itunes card", "google play card", "steam card", "amazon gift card", "scratch the back"
]


def evaluate_spear_phishing(
    sender: str,
    recipient_name: str,
    recipient_role: str,
    subject: str,
    body: str,
    organization_name: Optional[str] = None,
    claimed_identity: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Evaluates targeted spear phishing messages using:
    - Personalization depth (tailored targeting of recipient name, corporate role, departmental workflows)
    - Impersonation indicators (executive / VIP spoofing, external webmail for internal leadership)
    - High-risk request vectors (BEC wire transfer fraud, payroll redirection, employee W-2/PII theft, gift card fraud)
    - Coercive authority, pressure, and out-of-band communication suppression
    - Returns attack classification, likelihood, personalization metrics, and defensive countermeasures
    """
    sender_name, sender_addr, sender_domain = _extract_email_address(sender)
    
    score = 0.0
    triggered_rules = []
    
    def add_rule(id_: str, name: str, explanation: str, contribution: float, feature_vals: Dict[str, Any]):
        nonlocal score
        score += contribution
        triggered_rules.append({
            "id": id_,
            "name": name,
            "explanation": explanation,
            "contribution": contribution,
            "feature_values": feature_vals
        })

    text_corpus = f"{subject}\n{body}".lower()
    
    # 1. PERSONALIZATION ANALYSIS
    personalization_score = 0.0
    recip_clean = recipient_name.strip().lower()
    recip_tokens = [t for t in recip_clean.split() if len(t) > 2]
    
    target_name_found = False
    if recip_clean and (recip_clean in text_corpus or any(t in text_corpus for t in recip_tokens)):
        target_name_found = True
        personalization_score += 0.25
        add_rule(
            "rule_spear_recipient_name",
            "Personalized Target Addressing",
            f"Message specifically addresses recipient by name ('{recipient_name}'), indicating targeted reconnaissance.",
            0.20,
            {"recipient_name": recipient_name}
        )

    role_clean = recipient_role.strip().lower()
    role_aliases = {
        "chief financial officer": ["cfo", "finance", "financial", "wire", "transfer", "treasury", "accounting", "supplier"],
        "chief technology officer": ["cto", "devops", "engineering", "infrastructure", "server", "admin"],
        "chief executive officer": ["ceo", "executive", "board", "leadership"],
        "human resources": ["hr", "payroll", "benefits", "employee"],
        "payroll": ["payroll", "direct deposit", "salary", "compensation"],
        "operations": ["operations", "operational", "schedule", "review"],
    }
    role_tokens = [tok for tok in role_clean.split() if len(tok) > 3]
    for key, aliases in role_aliases.items():
        if key in role_clean or any(k in role_clean for k in key.split()):
            role_tokens.extend(aliases)

    role_found = False
    if role_clean and (role_clean in text_corpus or any(tok in text_corpus for tok in role_tokens)):
        role_found = True
        personalization_score += 0.25
        add_rule(
            "rule_spear_role_alignment",
            "Role & Department Tailoring",
            f"Message content specifically aligns with recipient's organizational role ('{recipient_role}').",
            0.20,
            {"recipient_role": recipient_role}
        )

    org_found = False
    if organization_name and organization_name.strip().lower() in text_corpus:
        org_found = True
        personalization_score += 0.20
        add_rule(
            "rule_spear_org_context",
            "Internal Organization Context",
            f"Message explicitly references internal organization name '{organization_name}'.",
            0.15,
            {"organization_name": organization_name}
        )

    personalization_level = "high" if personalization_score >= 0.40 else ("moderate" if personalization_score > 0 else "none")

    # 2. IMPERSONATION & EXECUTIVE AUTHORITY
    claimed_exec = None
    sender_corpus = f"{sender_name} {claimed_identity or ''}".lower()
    
    for title in _EXECUTIVE_TITLES:
        if title in sender_corpus or title in text_corpus:
            claimed_exec = title.upper()
            break

    is_external_or_webmail = sender_domain in _FREE_WEBMAIL_DOMAINS or (organization_name and organization_name.lower().replace(" ", "") not in sender_domain)

    if claimed_exec:
        if is_external_or_webmail:
            add_rule(
                "rule_spear_exec_spoofing",
                "Executive / Leadership Spoofing",
                f"Sender purports to be leadership ({claimed_exec}) but communicates from external/unverified domain '{sender_domain}'.",
                0.40,
                {"claimed_title": claimed_exec, "sender_domain": sender_domain}
            )
        else:
            add_rule(
                "rule_spear_executive_presence",
                "Executive Directive Pattern",
                f"Message invokes executive authority ({claimed_exec}).",
                0.15,
                {"claimed_title": claimed_exec}
            )

    # Authority coercion and pressure
    authority_phrases = [
        "as per my instructions", "board approved", "i am counting on you", "treat this as top priority",
        "confidential matter", "strictly confidential", "keep this between us", "private transaction"
    ]
    matched_auth = [p for p in authority_phrases if p in text_corpus]
    if matched_auth:
        add_rule(
            "rule_spear_authority_coercion",
            "Executive Pressure & Secrecy Demand",
            f"Demands strict confidentiality or asserts unverified executive authority ('{matched_auth[0]}').",
            0.25,
            {"matched_phrases": matched_auth}
        )

    # Channel isolation (don't call me, in a meeting, boarding plane)
    isolation_phrases = [
        "in a meeting", "in an important meeting", "boarding a flight", "traveling currently",
        "do not call", "cannot take calls", "email only", "phone is off", "cannot talk on the phone"
    ]
    matched_iso = [p for p in isolation_phrases if p in text_corpus]
    if matched_iso:
        add_rule(
            "rule_spear_channel_isolation",
            "Channel Isolation (Suppression of Out-of-Band Verification)",
            f"Adversary attempts to prevent voice or in-person verification ('{matched_iso[0]}').",
            0.30,
            {"matched_phrases": matched_iso}
        )

    # 3. HIGH-RISK TARGETED ATTACK VECTORS
    attack_vector = "general_spear_phish"
    
    # A. Business Email Compromise (BEC) Wire Transfer Fraud
    matched_wire = [w for w in _HIGH_RISK_FINANCIAL_ACTIONS if w in text_corpus]
    if matched_wire:
        attack_vector = "bec_wire_fraud"
        add_rule(
            "rule_spear_bec_wire_fraud",
            "Business Email Compromise (Wire Transfer Fraud)",
            f"Directs urgent out-of-band wire transfer or sensitive fund transfer: '{matched_wire[0]}'.",
            0.45,
            {"matched_terms": matched_wire}
        )

    # B. Payroll Diversion / Direct Deposit Fraud
    matched_payroll = [p for p in _PAYROLL_DIVERT_TERMS if p in text_corpus]
    if matched_payroll:
        attack_vector = "payroll_diversion"
        add_rule(
            "rule_spear_payroll_diversion",
            "Payroll / Direct Deposit Diversion",
            f"Requests changes to direct deposit or employee banking details without standard workflow.",
            0.45,
            {"matched_terms": matched_payroll}
        )

    # C. W-2 / Employee PII Exfiltration
    matched_pii = [pii for pii in _PII_THEFT_TERMS if pii in text_corpus]
    if matched_pii:
        attack_vector = "pii_w2_theft"
        add_rule(
            "rule_spear_pii_theft",
            "Employee PII / W-2 Form Exfiltration",
            "Requests bulk employee tax records, W-2 forms, or SSN datasets.",
            0.45,
            {"matched_terms": matched_pii}
        )

    # D. Executive Gift Card Scam
    matched_gift = [g for g in _GIFT_CARD_TERMS if g in text_corpus]
    if matched_gift:
        attack_vector = "gift_card_scam"
        add_rule(
            "rule_spear_gift_card_fraud",
            "Executive Gift Card Purchase Scam",
            "Requests immediate purchase of retail gift cards on behalf of leadership.",
            0.40,
            {"matched_terms": matched_gift}
        )

    # E. Process / Approval Bypass Request
    bypass_terms = ["bypass approval", "skip the po", "skip the purchase order", "paperwork later", "approve without delay"]
    matched_bypass = [b for b in bypass_terms if b in text_corpus]
    if matched_bypass:
        add_rule(
            "rule_spear_approval_bypass",
            "Security / Approval Process Circumvention",
            f"Explicitly instructs the recipient to bypass established verification protocols: '{matched_bypass[0]}'.",
            0.25,
            {"matched_terms": matched_bypass}
        )

    # Embedded link check
    raw_urls = re.findall(r'https?://[^\s<>"\')]+', body)
    if raw_urls:
        url_eval = evaluate_url_phishing(raw_urls[0])
        if url_eval["is_phishing"]:
            add_rule(
                "rule_spear_credential_portal",
                "Targeted Credential Harvesting Link",
                "Includes a tailored login portal link identified as deceptive.",
                0.35,
                {"url": raw_urls[0]}
            )

    threat_rules = {
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
    has_active_threat = any(r["id"] in threat_rules for r in triggered_rules)

    if not has_active_threat:
        confidence = 0.0
        classification = "legitimate"
        attack_vector = "benign"
    else:
        confidence = min(0.99, round(score, 4))
        if confidence >= 0.65:
            classification = "phishing"
        elif confidence >= 0.35:
            classification = "suspicious"
        else:
            classification = "legitimate"
            attack_vector = "benign"

    risk_score = int(round(confidence * 100))
    if risk_score >= 85:
        risk_level = "CRITICAL"
    elif risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Countermeasure recommendations
    countermeasures = []
    if attack_vector == "bec_wire_fraud":
        countermeasures.append("Perform dual-authorization telephone confirmation using internally registered company directory extension.")
        countermeasures.append("Never execute out-of-band wire changes without signed purchase order confirmation.")
    elif attack_vector == "payroll_diversion":
        countermeasures.append("Require employee to authenticate directly through internal HR portal; do not accept email direct deposit change requests.")
    elif attack_vector == "gift_card_scam":
        countermeasures.append("Recognize that corporate leadership will never request gift card purchases or scratch-off codes via email.")
    elif attack_vector == "pii_w2_theft":
        countermeasures.append("Do not transmit W-2 or tax information via unencrypted email; verify requests directly with General Counsel.")
    else:
        countermeasures.append("Verify the sender's identity using an alternative, authenticated communication channel.")

    explanation = (
        f"Message classified as SPEAR PHISHING ({risk_level} risk, attack vector: {attack_vector.upper()}). "
        + " ".join(r["explanation"] for r in triggered_rules)
    ).strip()

    return {
        "classification": classification,
        "is_phishing": confidence >= 0.65,
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
            "is_external": is_external_or_webmail,
        },
        "explanation": explanation,
        "triggered_rules": triggered_rules,
        "recommended_countermeasures": countermeasures,
    }


