from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_detect_phishing_valid_benign():
    response = client.post("/api/detect/phishing", json={"url": "https://www.google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["url"] == "https://www.google.com"
    assert data["is_phishing"] is False
    assert data["heuristic_confidence"] == 0.0
    assert "URL appears benign" in data["explanation"]
    assert "is_https" in data["features"]

def test_detect_phishing_suspicious():
    response = client.post("/api/detect/phishing", json={"url": "http://192.168.1.1/update-account-login"})
    assert response.status_code == 200
    data = response.json()
    assert data["is_phishing"] is True
    assert data["heuristic_confidence"] >= 0.65
    assert "Suspicious URL identified" in data["explanation"]
    assert "credential-harvesting keywords" in data["explanation"]

def test_detect_phishing_invalid_scheme():
    response = client.post("/api/detect/phishing", json={"url": "ftp://files.example.com"})
    assert response.status_code == 400
    assert "URL must start with http" in response.json()["detail"]

def test_detect_phishing_empty():
    response = client.post("/api/detect/phishing", json={"url": "   "})
    assert response.status_code == 400
    assert "cannot be empty" in response.json()["detail"]
