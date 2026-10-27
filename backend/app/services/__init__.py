"""Services package for AOD-IPS backend."""

from app.services.suricata_ingest import ingest_new_events
from app.services.rule_engine import evaluate_rules
from app.services.ml_engine import evaluate_ml
from app.services.risk_engine import compute_risk_score
from app.services.adaptive_engine import recommend_next_scenario
from app.services.simulation_service import (
    run_synthetic_simulation,
    get_available_scenarios,
    SCENARIO_METADATA,
)
from app.services.chatbot_service import (
    query_openrouter,
    extract_session_security_context,
    ChatbotServiceError,
    MissingAPIKeyError,
    OpenRouterAuthError,
    OpenRouterRateLimitError,
    OpenRouterUnavailableError,
)

__all__ = [
    "ingest_new_events",
    "evaluate_rules",
    "evaluate_ml",
    "compute_risk_score",
    "recommend_next_scenario",
    "run_synthetic_simulation",
    "get_available_scenarios",
    "SCENARIO_METADATA",
    "query_openrouter",
    "extract_session_security_context",
    "ChatbotServiceError",
    "MissingAPIKeyError",
    "OpenRouterAuthError",
    "OpenRouterRateLimitError",
    "OpenRouterUnavailableError",
]
