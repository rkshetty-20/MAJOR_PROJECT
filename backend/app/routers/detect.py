from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import logging
from app.services.phishing_detector import (
    evaluate_phishing_url,
    evaluate_url_phishing,
    evaluate_email_phishing,
    evaluate_spear_phishing,
)

router = APIRouter(tags=["Detection"])
logger = logging.getLogger(__name__)

# ==========================================
# Legacy & Base Models (Backward Compatibility)
# ==========================================

class PhishingRequest(BaseModel):
    url: str

class PhishingResponse(BaseModel):
    url: str
    is_phishing: bool
    heuristic_confidence: float
    explanation: str
    features: Dict[str, Any]
    triggered_rules: list = []
    reputation: Dict[str, Any] = None


@router.post(
    "/api/detect/phishing",
    response_model=PhishingResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate a URL for phishing characteristics using offline heuristic analysis",
)
def detect_phishing_endpoint(payload: PhishingRequest) -> Dict[str, Any]:
    """
    Analyzes a URL string offline using heuristics.
    Does not fetch, crawl, or resolve the URL.
    """
    url = payload.url.strip()
    
    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL cannot be empty."
        )

    if not url.startswith("http://") and not url.startswith("https://"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL must start with http:// or https://"
        )
        
    try:
        is_phishing, confidence, features, explanation, triggered_rules = evaluate_phishing_url(url)
        
        return {
            "url": url,
            "is_phishing": is_phishing,
            "heuristic_confidence": confidence,
            "explanation": explanation,
            "features": features,
            "triggered_rules": triggered_rules,
            "reputation": {
                "provider": "Offline Heuristics",
                "status": "unavailable",
                "details": "External network lookup disabled per paper design (safe lexical analysis only)."
            }
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.exception("Error analyzing URL: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze URL."
        )


# ==========================================
# 1. URL Phishing Detection Endpoint
# ==========================================

class UrlDetectionRequest(BaseModel):
    url: str = Field(..., description="Target URL to analyze (must begin with http:// or https://)")

class UrlDetectionResponse(BaseModel):
    url: str
    classification: str
    is_phishing: bool
    confidence: float
    risk_score: int
    explanation: str
    features: Dict[str, Any]
    triggered_rules: List[Dict[str, Any]] = []


@router.post(
    "/api/detect/url",
    response_model=UrlDetectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate a submitted URL with multi-tier classification and open-redirect analysis",
)
def detect_url_endpoint(payload: UrlDetectionRequest) -> Dict[str, Any]:
    """
    Analyzes submitted URLs for HTTPS, domain characteristics, length, symbols,
    open redirects, and classifies into legitimate, suspicious, or phishing.
    """
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URL cannot be empty.")
    if not url.startswith("http://") and not url.startswith("https://"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URL must start with http:// or https://")
        
    try:
        return evaluate_url_phishing(url)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.exception("Error in URL phishing evaluation: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to analyze URL.")


# ==========================================
# 2. Email Phishing Detection Endpoint
# ==========================================

class EmailDetectionRequest(BaseModel):
    sender: str = Field(..., description="Sender display name and email address, e.g. 'Support <support@paypal-security.net>'")
    subject: str = Field(..., description="Email subject line")
    body: str = Field(..., description="Email message body (plain text or HTML)")
    recipient: Optional[str] = Field(None, description="Optional recipient address")
    reply_to: Optional[str] = Field(None, description="Optional Reply-To header address")
    headers: Optional[Dict[str, str]] = Field(None, description="Optional raw email headers")

class EmailDetectionResponse(BaseModel):
    classification: str
    is_phishing: bool
    confidence: float
    risk_score: int
    risk_level: str
    explanation: str
    sender_analysis: Dict[str, Any]
    links_analysis: Dict[str, Any]
    triggered_rules: List[Dict[str, Any]] = []


@router.post(
    "/api/detect/email",
    response_model=EmailDetectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze email message content, sender spoofing, urgency cues, and embedded links",
)
def detect_email_endpoint(payload: EmailDetectionRequest) -> Dict[str, Any]:
    """
    Analyzes email telemetry:
    - Sender display-name spoofing and brand impersonation
    - Free webmail usage for corporate services
    - Reply-To domain discrepancies
    - Urgency, coercion, and credential harvesting keywords
    - Extraction and deep analysis of all embedded hyperlinks
    - Attachment risk indicators
    """
    if not payload.sender.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Sender cannot be empty.")
    if not payload.subject.strip() and not payload.body.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email must contain a subject or body.")

    try:
        return evaluate_email_phishing(
            sender=payload.sender,
            subject=payload.subject,
            body=payload.body,
            recipient=payload.recipient,
            reply_to=payload.reply_to,
            headers=payload.headers,
        )
    except Exception as e:
        logger.exception("Error evaluating email phishing: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to analyze email.")


# ==========================================
# 3. Spear Phishing Detection Endpoint
# ==========================================

class SpearPhishingRequest(BaseModel):
    sender: str = Field(..., description="Sender address / identity, e.g. 'CEO John Smith <ceo.work123@gmail.com>'")
    recipient_name: str = Field(..., description="Target employee name, e.g. 'Jane Doe'")
    recipient_role: str = Field(..., description="Target employee title or department, e.g. 'CFO', 'HR Director', 'DevOps'")
    subject: str = Field(..., description="Message subject line")
    body: str = Field(..., description="Message body content")
    organization_name: Optional[str] = Field(None, description="Target company or organization name, e.g. 'Acme Corp'")
    claimed_identity: Optional[str] = Field(None, description="Optional claimed executive identity, e.g. 'CEO'")

class SpearPhishingResponse(BaseModel):
    classification: str
    is_phishing: bool
    confidence: float
    risk_score: int
    risk_level: str
    attack_vector: str
    personalization: Dict[str, Any]
    impersonation: Dict[str, Any]
    explanation: str
    triggered_rules: List[Dict[str, Any]] = []
    recommended_countermeasures: List[str] = []


@router.post(
    "/api/detect/spear-phishing",
    response_model=SpearPhishingResponse,
    status_code=status.HTTP_200_OK,
    summary="Identify targeted spear phishing, executive impersonation, BEC wire fraud, and payroll diversion",
)
def detect_spear_phishing_endpoint(payload: SpearPhishingRequest) -> Dict[str, Any]:
    """
    Evaluates targeted spear phishing:
    - Personalization depth (recipient name, role, and organization alignment)
    - Executive / VIP impersonation from unverified or free webmail domains
    - High-risk request vectors: BEC wire transfers, payroll diversion, W-2 PII theft, gift card scams
    - Coercive pressure, secrecy demands, and out-of-band verification suppression
    - Actionable defensive countermeasures
    """
    if not payload.sender.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Sender cannot be empty.")
    if not payload.recipient_name.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Recipient name cannot be empty.")
    if not payload.body.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Message body cannot be empty.")

    try:
        return evaluate_spear_phishing(
            sender=payload.sender,
            recipient_name=payload.recipient_name,
            recipient_role=payload.recipient_role,
            subject=payload.subject,
            body=payload.body,
            organization_name=payload.organization_name,
            claimed_identity=payload.claimed_identity,
        )
    except Exception as e:
        logger.exception("Error evaluating spear phishing: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to analyze spear phishing.")

