import pytest
from app.services.phishing_detector import extract_phishing_features, evaluate_phishing_url

def test_extract_features_normal_https():
    url = "https://www.google.com/"
    features = extract_phishing_features(url)
    assert features["is_https"] is True
    assert features["url_length"] == 23
    assert features["num_subdomains"] == 1
    assert features["is_ip"] is False
    assert features["keyword_count"] == 0
    assert features["special_chars"] == 0

def test_evaluate_normal_https():
    url = "https://www.google.com/"
    is_phishing, confidence, features, explanation, triggered_rules = evaluate_phishing_url(url)
    assert is_phishing is False
    assert confidence == 0.0

def test_evaluate_multiple_suspicious_indicators():
    url = "http://verify-account.update.banking-secure.com/login?token=12345"
    is_phishing, confidence, features, explanation, triggered_rules = evaluate_phishing_url(url)
    
    assert features["is_https"] is False
    assert features["keyword_count"] >= 4  # verify, account, update, secure, login, banking
    assert features["special_chars"] > 0
    
    assert is_phishing is True
    assert confidence >= 0.65

def test_evaluate_http_without_https():
    url = "http://example.com"
    is_phishing, confidence, features, explanation, triggered_rules = evaluate_phishing_url(url)
    assert features["is_https"] is False
    assert confidence >= 0.2

def test_evaluate_ip_hostname():
    url = "http://192.168.1.1/login"
    is_phishing, confidence, features, explanation, triggered_rules = evaluate_phishing_url(url)
    assert features["is_ip"] is True
    assert features["keyword_count"] >= 1
    assert is_phishing is True

def test_malformed_unsupported_input():
    with pytest.raises(ValueError, match="URL must be a string"):
        extract_phishing_features(None)
    with pytest.raises(ValueError, match="URL must be a string"):
        extract_phishing_features(123)
    
    with pytest.raises(ValueError, match="URL cannot be empty"):
        extract_phishing_features("   ")

def test_scores_thresholds():
    # Below 0.65
    url_below = "http://example.com" # 0.2
    is_phishing, conf, _, explanation, triggered_rules = evaluate_phishing_url(url_below)
    assert not is_phishing

    # Exactly or above 0.65
    # is_ip (0.4) + no https (0.2) + 1 keyword (0.2) = 0.8
    url_above = "http://192.168.1.1/login"
    is_phishing, conf, _, explanation, triggered_rules = evaluate_phishing_url(url_above)
    assert is_phishing
    assert conf >= 0.65

def test_punycode_detection():
    url = "https://xn--bcher-kva.example.com/login"
    is_phishing, confidence, features, explanation, triggered_rules = evaluate_phishing_url(url)
    assert features["is_punycode"] is True
    assert "Punycode" in explanation

def test_misleading_subdomain():
    url = "https://login.paypal.com.scammer-website.net/secure"
    is_phishing, confidence, features, explanation, triggered_rules = evaluate_phishing_url(url)
    assert features["has_misleading_subdomain"] is True
    assert "misleading brand names" in explanation
    assert is_phishing is True

def test_legitimate_url_with_many_subdomains():
    url = "https://my.very.long.subdomain.legitimate.com"
    is_phishing, confidence, features, explanation, triggered_rules = evaluate_phishing_url(url)
    # Subdomains >= 3 -> +0.15
    assert features["num_subdomains"] >= 3
    assert is_phishing is False
    assert confidence >= 0.15

def test_threshold_boundary_exact():
    # Exactly 0.65 threshold test
    # IP (0.4) + no https (0.2) + url length > 75 (0.1) = 0.7 > 0.65
    # Let's hit exactly 0.65: IP (0.4) + no https (0.2) + wait, it's hard to get exactly 0.65 without 0.05 increments.
    # IP (0.4) + no https (0.2) = 0.6 (below)
    # Punycode (0.3) + misleading (0.35) = 0.65
    url = "https://xn--bcher-kva.paypal.scammer.com"
    is_phishing, confidence, features, explanation, triggered_rules = evaluate_phishing_url(url)
    assert features["is_punycode"] is True
    assert features["has_misleading_subdomain"] is True
    assert features["num_subdomains"] < 3
    # Punycode (0.3) + Misleading (0.35) = 0.65
    import math
    assert math.isclose(confidence, 0.65, abs_tol=0.01)
    assert is_phishing is True

def test_improved_input_validation():
    with pytest.raises(ValueError, match="URL must include a valid hostname"):
        evaluate_phishing_url("http://")
    
    with pytest.raises(ValueError, match="URL must be a string"):
        evaluate_phishing_url(["not", "a", "string"])

def test_credentials_in_url():
    url = "https://user:password@example.com"
    is_phishing, confidence, features, explanation, triggered_rules = evaluate_phishing_url(url)
    assert features["has_credentials"] is True
    assert any(rule["id"] == "rule_credentials" for rule in triggered_rules)

def test_unusual_port():
    url = "https://example.com:8443"
    is_phishing, confidence, features, explanation, triggered_rules = evaluate_phishing_url(url)
    assert features["unusual_port"] is True
    assert any(rule["id"] == "rule_unusual_port" for rule in triggered_rules)