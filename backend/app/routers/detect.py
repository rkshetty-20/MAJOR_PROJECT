from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import logging
from app.services.phishing_detector import (
    CONFIDENCE_CAP,
    MAX_SINGLE_INDICATOR_CONTRIBUTION,
    SCORER_NAME,
    SCORER_VERSION,
    MalformedURLError,
    evaluate_phishing_url,
    evaluate_url_phishing,
    evaluate_email_phishing,
    evaluate_spear_phishing,
    provenance,
    summarise_indicators,
)

router = APIRouter(tags=["Detection"])
logger = logging.getLogger(__name__)

#: Reputation lookups are not implemented anywhere in this project. The block is
#: a fixed statement of that fact, surfaced on every legacy response so a reader
#: cannot mistake the lexical verdict for a feed result.
NO_REPUTATION = {
    "implemented": False,
    "provider": None,
    "status": "unavailable",
    "details": (
        "No external reputation integration (VirusTotal, Google Safe Browsing or any "
        "other feed) exists in this project, and no URL is ever fetched or resolved. "
        "The verdict comes only from the offline lexical indicators listed above."
    ),
}

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
    scorer: Dict[str, Any] = None
    provenance: Dict[str, Any] = None
    confidence_cap: Optional[float] = None
    max_single_indicator_contribution: Optional[float] = None


class IndicatorRegistryResponse(BaseModel):
    """Self-description of the lexical scorer: indicators, weights, thresholds."""

    scorer: str
    version: str
    core_indicators: int
    extended_indicators: int
    declared_features: int
    required_features: int
    evidence_only_features: int
    features_produced_by_extractor: int
    confidence_cap: float
    max_single_indicator_contribution: float
    thresholds: Dict[str, float]
    keyword_vocabulary_size: int
    categories: Dict[str, int]
    indicators: List[Dict[str, Any]]
    provenance: Dict[str, Any]


@router.get(
    "/api/detect/phishing/indicators",
    response_model=IndicatorRegistryResponse,
    status_code=status.HTTP_200_OK,
    summary="List every lexical phishing indicator, its declared weight, inputs and provenance",
)
def detect_phishing_indicators() -> Dict[str, Any]:
    """Expose the validated indicator registry instead of a prose claim.

    The counts returned here are computed from the registry the scorer actually
    evaluates (validated at import time), so "10 weighted lexical indicators" can
    be checked by a client rather than taken on trust.
    """
    return summarise_indicators()


@router.post(
    "/api/detect/phishing",
    response_model=PhishingResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate a URL for phishing characteristics using offline heuristic analysis",
)
def detect_phishing_endpoint(payload: PhishingRequest) -> Dict[str, Any]:
    """
    Analyzes a URL string offline using the declared lexical indicators.
    The URL is never fetched, crawled, resolved or submitted to a third party.
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
            "reputation": dict(NO_REPUTATION),
            "scorer": {"name": SCORER_NAME, "version": SCORER_VERSION},
            "provenance": provenance(),
            "confidence_cap": CONFIDENCE_CAP,
            "max_single_indicator_contribution": MAX_SINGLE_INDICATOR_CONTRIBUTION,
        }
    except MalformedURLError as e:
        # Controlled rejection: the message comes from the validation contract in
        # app.services.phishing.url_features, never from interpreter internals.
        logger.warning("Rejected malformed URL (%s): %s", e.reason, url[:200])
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
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
    scorer: Optional[Dict[str, Any]] = None
    provenance: Optional[Dict[str, Any]] = None


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
    Analysis is lexical and offline; the URL is never fetched or resolved.
    """
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URL cannot be empty.")
    if not url.startswith("http://") and not url.startswith("https://"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URL must start with http:// or https://")
        
    try:
        return evaluate_url_phishing(url)
    except MalformedURLError as e:
        logger.warning("Rejected malformed URL (%s): %s", e.reason, url[:200])
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
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
    confidence_cap: Optional[float] = None
    explanation: str
    sender_analysis: Dict[str, Any]
    links_analysis: Dict[str, Any]
    triggered_rules: List[Dict[str, Any]] = []
    provenance: Optional[Dict[str, Any]] = None


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
    - Extraction and lexical analysis of all embedded hyperlinks (never fetched)
    - Attachment risk indicators

    Links that cannot be parsed are reported in ``links_analysis.skipped_links``
    rather than aborting the analysis.
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
    link_analysis: Optional[Dict[str, Any]] = None
    provenance: Optional[Dict[str, Any]] = None


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

