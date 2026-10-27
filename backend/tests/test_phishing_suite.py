import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.phishing_detector import (
    evaluate_url_phishing,
    evaluate_email_phishing,
    evaluate_spear_phishing,
)

client = TestClient(app)

# ===========================================================================
# 1. URL Phishing Detection Tests
# ===========================================================================

def test_url_phishing_legitimate():
    url = "https://www.google.com/search?q=cybersecurity"
    result = evaluate_url_phishing(url)
    assert result["classification"] == "legitimate"
    assert result["is_phishing"] is False
    assert result["confidence"] < 0.35
    assert result["features"]["is_https"] is True


def test_url_phishing_malicious_indicators():
    url = "http://192.168.1.50/update-banking-account-login-verify"
    result = evaluate_url_phishing(url)
    assert result["classification"] == "phishing"
    assert result["is_phishing"] is True
    assert result["confidence"] >= 0.65
    assert result["features"]["is_ip"] is True
    assert result["features"]["keyword_count"] >= 3


def test_url_phishing_open_redirect():
    url = "https://example.com/redirect?url=http://attacker-controlled-site.xyz/login"
    result = evaluate_url_phishing(url)
    assert result["features"]["open_redirect_detected"] is True
    assert any(r["id"] == "rule_open_redirect" for r in result["triggered_rules"])


def test_url_phishing_suspicious_tld():
    url = "http://secure-account-verification.top/login"
    result = evaluate_url_phishing(url)
    assert result["features"]["suspicious_tld"] is True
    assert any(r["id"] == "rule_suspicious_tld" for r in result["triggered_rules"])
    assert result["classification"] in ["suspicious", "phishing"]


# ===========================================================================
# 2. Email Phishing Detection Tests
# ===========================================================================

def test_email_phishing_benign():
    result = evaluate_email_phishing(
        sender="Alice Smith <alice@example.com>",
        recipient="bob@example.com",
        subject="Project Status Update for Wednesday Meeting",
        body="Hi Bob,\nAttached are the meeting minutes from yesterday. Please review them before our team sync.\nThanks,\nAlice",
    )
    assert result["classification"] == "legitimate"
    assert result["is_phishing"] is False
    assert result["confidence"] < 0.35
    assert result["risk_level"] in ["LOW", "MEDIUM"]


def test_email_phishing_brand_spoofing_free_webmail():
    result = evaluate_email_phishing(
        sender="PayPal Security Team <paypal-alerts247@gmail.com>",
        recipient="victim@company.com",
        subject="URGENT: Your account has been suspended - Verify immediately!",
        body="Dear Customer,\nYour account will be suspended within 24 hours due to unauthorized access. Click here to login and update billing: http://192.168.1.1/paypal/verify\nFailure to do so will result in permanent closure.",
        reply_to="stealer@hacker-mailbox.net",
    )
    assert result["classification"] == "phishing"
    assert result["is_phishing"] is True
    assert result["confidence"] >= 0.65
    assert result["risk_score"] >= 65
    rule_ids = {r["id"] for r in result["triggered_rules"]}
    assert "rule_sender_display_spoof" in rule_ids
    assert "rule_urgency_pressure" in rule_ids
    assert "rule_credential_harvesting_cta" in rule_ids
    assert "rule_reply_to_mismatch" in rule_ids
    assert "rule_malicious_embedded_url" in rule_ids


def test_email_phishing_generic_salutation_and_attachment():
    result = evaluate_email_phishing(
        sender="Billing Department <billing@quick-invoice-service.xyz>",
        recipient="accounts@company.com",
        subject="Overdue Invoice Payment Required Immediately",
        body="Dear Customer,\nYour payment is past due. Please find invoice.pdf.exe attached and wire transfer funds immediately.",
    )
    assert result["is_phishing"] is True
    rule_ids = {r["id"] for r in result["triggered_rules"]}
    assert "rule_dangerous_attachment_reference" in rule_ids
    assert "rule_financial_lure" in rule_ids


# ===========================================================================
# 3. Spear Phishing Detection Tests
# ===========================================================================

def test_spear_phishing_benign_executive():
    result = evaluate_spear_phishing(
        sender="John Smith <john.smith@acmecorp.com>",
        recipient_name="Sarah Connor",
        recipient_role="Operations Manager",
        subject="Weekly Department Review",
        body="Hi Sarah,\nCould you send over the revised schedule for the operations team when you have a moment today?\nBest,\nJohn",
        organization_name="Acme Corp",
    )
    assert result["classification"] == "legitimate"
    assert result["is_phishing"] is False
    assert result["attack_vector"] == "benign"


def test_spear_phishing_ceo_wire_fraud_bec():
    result = evaluate_spear_phishing(
        sender="CEO David Miller <david.miller.ceo@gmail.com>",
        recipient_name="Robert Langdon",
        recipient_role="Chief Financial Officer",
        subject="Confidential: Urgent Wire Transfer Required Today",
        body="Robert,\nI am currently in an all-day confidential board meeting and cannot take calls. As per my instructions, we need to execute an urgent wire transfer of $78,500 to our overseas supplier before 3 PM. Bypass standard PO approval for now, I will sign the paperwork later. Keep this strictly confidential.",
        organization_name="Acme Corp",
        claimed_identity="CEO",
    )
    assert result["classification"] == "phishing"
    assert result["is_phishing"] is True
    assert result["attack_vector"] == "bec_wire_fraud"
    assert result["confidence"] >= 0.65
    assert result["personalization"]["target_name_matched"] is True
    assert result["personalization"]["role_matched"] is True
    rule_ids = {r["id"] for r in result["triggered_rules"]}
    assert "rule_spear_exec_spoofing" in rule_ids
    assert "rule_spear_authority_coercion" in rule_ids
    assert "rule_spear_channel_isolation" in rule_ids
    assert "rule_spear_bec_wire_fraud" in rule_ids
    assert "rule_spear_approval_bypass" in rule_ids
    assert len(result["recommended_countermeasures"]) > 0


def test_spear_phishing_payroll_diversion():
    result = evaluate_spear_phishing(
        sender="Employee Alex Mercer <alex.mercer.work@yahoo.com>",
        recipient_name="Mary Watson",
        recipient_role="Payroll Specialist",
        subject="URGENT: Change my direct deposit bank info before this cycle",
        body="Hello Mary,\nI need to immediately update my direct deposit bank account and routing number for the upcoming payroll cycle. Attached is my new voided check. Please process without delay.",
        organization_name="Acme Corp",
    )
    assert result["classification"] == "phishing"
    assert result["attack_vector"] == "payroll_diversion"
    rule_ids = {r["id"] for r in result["triggered_rules"]}
    assert "rule_spear_payroll_diversion" in rule_ids


def test_spear_phishing_gift_card_scam():
    result = evaluate_spear_phishing(
        sender="CEO Marcus Vance <executive.office@gmail.com>",
        recipient_name="Emily Davis",
        recipient_role="Executive Assistant",
        subject="Task for you",
        body="Emily, are you at your desk? I need you to quickly purchase 10 Apple gift cards for a client presentation. Scratch the back and send me the codes. I am in a meeting, do not call.",
        organization_name="Acme Corp",
        claimed_identity="CEO",
    )
    assert result["classification"] == "phishing"
    assert result["attack_vector"] == "gift_card_scam"


# ===========================================================================
# 4. HTTP API Endpoints Tests
# ===========================================================================

def test_api_detect_url_endpoint():
    res = client.post("/api/detect/url", json={"url": "https://www.github.com"})
    assert res.status_code == 200
    data = res.json()
    assert data["classification"] == "legitimate"
    assert "confidence" in data
    assert "risk_score" in data


def test_api_detect_email_endpoint():
    res = client.post(
        "/api/detect/email",
        json={
            "sender": "Netflix Billing <billing@netflix-account-notice.net>",
            "subject": "Action Required: Payment Declined",
            "body": "Dear customer, your payment was declined. Click here to login: http://192.168.1.1/netflix",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["is_phishing"] is True
    assert data["classification"] == "phishing"
    assert "sender_analysis" in data
    assert "links_analysis" in data


def test_api_detect_spear_phishing_endpoint():
    res = client.post(
        "/api/detect/spear-phishing",
        json={
            "sender": "CEO <ceo@mail-personal.com>",
            "recipient_name": "Thomas Anderson",
            "recipient_role": "Lead Architect",
            "subject": "Confidential Request",
            "body": "Thomas, please send me the source code repository credentials immediately. In a meeting, do not call.",
            "organization_name": "Metacortex",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["is_phishing"] is True
    assert "personalization" in data
    assert "impersonation" in data
    assert len(data["recommended_countermeasures"]) > 0


def test_api_detect_phishing_backward_compat():
    res = client.post("/api/detect/phishing", json={"url": "https://www.google.com"})
    assert res.status_code == 200
    data = res.json()
    assert data["is_phishing"] is False
    assert data["heuristic_confidence"] == 0.0
