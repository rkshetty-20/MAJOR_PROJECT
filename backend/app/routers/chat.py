import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.services.chatbot_service import (
    query_openrouter,
    query_openrouter_stream,
    extract_session_security_context,
    ChatbotServiceError,
    MissingAPIKeyError,
    OpenRouterAuthError,
    OpenRouterRateLimitError,
    OpenRouterUnavailableError,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["AI Chatbot"])


# ==========================================
# Pydantic Schemas
# ==========================================

class ChatMessage(BaseModel):
    role: str = Field(..., description="Role of the sender ('user' or 'assistant')")
    content: str = Field(..., description="Message text content")

    model_config = ConfigDict(extra="ignore")


class ChatRequest(BaseModel):
    message: str = Field(..., description="Cybersecurity question or incident inquiry")
    conversation_history: Optional[List[ChatMessage]] = Field(
        default_factory=list,
        description="List of prior message turns for conversational memory",
    )
    security_context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Structured security telemetry (e.g. login fraud metrics, detection alerts)",
    )
    session_id: Optional[int] = Field(
        default=None,
        description="Optional session ID to automatically extract active database telemetry",
    )

    model_config = ConfigDict(extra="ignore")


class ChatResponse(BaseModel):
    response: str = Field(..., description="The assistant's cybersecurity guidance or explanation")
    model: str = Field(..., description="Model identifier used to fulfill the request")


class ChatErrorResponse(BaseModel):
    error: str = Field(..., description="User-friendly error message")


# ==========================================
# Endpoints
# ==========================================

@router.post(
    "/api/chat",
    response_model=ChatResponse,
    responses={
        400: {"model": ChatErrorResponse, "description": "Invalid input / empty message"},
        404: {"model": ChatErrorResponse, "description": "Session not found"},
        429: {"model": ChatErrorResponse, "description": "Rate limit exceeded"},
        503: {"model": ChatErrorResponse, "description": "AI provider service unavailable or unconfigured"},
    },
    summary="Chat with FraudGuard Security Assistant",
)
@router.post("/chat", response_model=ChatResponse, include_in_schema=False)
async def chat_with_assistant(
    payload: ChatRequest,
    db: DBSession = Depends(get_db),
) -> Any:
    """
    Submits a message to the FraudGuard Security Assistant.
    Supports two operating modes:
    1. General Cybersecurity Inquiry: Answers conceptual and defensive security questions.
    2. Security Event Analysis: Analyzes structured event telemetry (passed via security_context
       or automatically loaded via session_id) with strict factual grounding.
    """
    # 1. Validate user message
    trimmed_msg = payload.message.strip() if payload.message else ""
    if not trimmed_msg:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Message cannot be empty."},
        )

    # 2. Determine security context
    context = payload.security_context

    # If session_id is supplied and context is not already explicitly provided, create an intent hint
    if payload.session_id is not None and context is None:
        context = {"session_id": payload.session_id}

    # 3. Format conversation history
    history_dicts = [
        {"role": msg.role, "content": msg.content}
        for msg in (payload.conversation_history or [])
    ]

    # Pass it through the dynamic builder (now async and takes history)
    from app.services.chatbot_service import build_dynamic_security_context
    context = await build_dynamic_security_context(trimmed_msg, context, db, history_dicts)

    # 4. Invoke the AI service
    try:
        result = await query_openrouter(
            message=trimmed_msg,
            conversation_history=history_dicts,
            security_context=context,
        )
        return ChatResponse(
            response=result["response"],
            model=result["model"],
        )

    except MissingAPIKeyError as exc:
        logger.warning("Chatbot invocation failed: %s", exc.message)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": exc.message},
        )

    except OpenRouterAuthError as exc:
        logger.error("Chatbot authentication error: %s", exc.message)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": exc.message},
        )

    except OpenRouterRateLimitError as exc:
        logger.warning("Chatbot rate limit error: %s", exc.message)
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"error": exc.message},
        )

    except OpenRouterUnavailableError as exc:
        logger.error("Chatbot provider error: %s", exc.message)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": exc.message},
        )

    except ChatbotServiceError as exc:
        logger.error("Chatbot service failure: %s", exc.message)
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.message},
        )

    except Exception as exc:
        logger.exception("Unhandled error processing chat: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "An unexpected error occurred while processing your request."},
        )


@router.post(
    "/api/chat/stream",
    summary="Stream Chat with FraudGuard Security Assistant",
)
@router.post("/chat/stream", include_in_schema=False)
async def stream_chat_with_assistant(
    payload: ChatRequest,
    db: DBSession = Depends(get_db),
):
    """
    Submits a message to the FraudGuard Security Assistant and streams the response back via Server-Sent Events (SSE).
    """
    # 1. Validate user message
    trimmed_msg = payload.message.strip() if payload.message else ""
    if not trimmed_msg:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Message cannot be empty."},
        )

    # 2. Determine security context
    context = payload.security_context

    if payload.session_id is not None and context is None:
        context = {"session_id": payload.session_id}

    # 3. Format conversation history
    history_dicts = [
        {"role": msg.role, "content": msg.content}
        for msg in (payload.conversation_history or [])
    ]

    from app.services.chatbot_service import build_dynamic_security_context
    context = await build_dynamic_security_context(trimmed_msg, context, db, history_dicts)

    # 4. Invoke the AI service with streaming
    generator = query_openrouter_stream(
        message=trimmed_msg,
        conversation_history=history_dicts,
        security_context=context,
    )
    
    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )
