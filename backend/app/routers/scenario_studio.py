"""Attack Scenario Studio API (Milestone 2).

Endpoints for the LLM-powered scenario proposal + validation workflow:

    POST /api/scenario-studio/propose  -> LLM proposes a validated scenario spec (preview).
    POST /api/scenario-studio/validate -> Validate a caller-supplied scenario spec.

These produce and vet a *plan* only. Compiling the plan into a persisted,
replayable dataset is Milestone 3 (POST /api/scenario-studio/compile).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.services.scenario_simulator.compiler import (
    CompilationError,
    compile_scenario_to_dataset,
)
from app.services.scenario_simulator.evaluator import (
    ReplayError,
    get_dataset_lifecycle,
    replay_studio_dataset,
)
from app.services.scenario_simulator.generator import (
    ProviderUnavailableError,
    generate_scenario_proposal,
)
from app.services.scenario_simulator.learning_import import (
    LearningImportError,
    evaluate_learning_eligibility,
    import_dataset_learning_examples,
)
from app.services.scenario_simulator.spec import (
    AttackCategory,
    MAX_EVENT_COUNT,
    ScenarioSpec,
)
from app.services.scenario_simulator.validators import (
    run_full_validation,
    validate_analyst_request,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scenario-studio", tags=["Attack Scenario Studio"])

# Total wall-clock budget for the LLM proposal interaction (initial call + any
# bounded validation-repair passes). Kept strictly below the frontend axios
# request timeout (15s) so a slow/unreachable provider returns an honest 503
# with fallback_available=true before the browser aborts the request.
PROPOSE_DEADLINE_SECONDS = 12.0


class ScenarioControls(BaseModel):
    """Server-side, safe controls. No arbitrary commands/targets/payloads."""

    model_config = ConfigDict(extra="forbid")

    attack_category: Optional[AttackCategory] = None
    intensity: Optional[str] = Field(default=None, description="low | medium | high")
    event_count: Optional[int] = Field(default=None, ge=1, le=MAX_EVENT_COUNT)
    duration_seconds: Optional[int] = Field(default=None, ge=1, le=86400)
    benign_to_malicious_ratio: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    seed: Optional[int] = None
    evaluation_objective: Optional[str] = Field(default=None, max_length=500)
    dataset_role: Optional[str] = Field(default=None, description="training | validation | test")


class ProposeRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    request: str = Field(..., min_length=1, max_length=4000, description="Natural-language scenario description")
    controls: Optional[ScenarioControls] = None
    model: Optional[str] = Field(default=None, description="Optional model override (validated server-side)")


class ProposeResponse(BaseModel):
    status: str
    spec: Optional[Dict[str, Any]] = None
    validation: Optional[Dict[str, Any]] = None
    model: Optional[str] = None
    correlation_id: Optional[str] = None
    attempts: int = 0
    fallback_available: bool = True


class ValidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    spec: Dict[str, Any]


class ValidateResponse(BaseModel):
    valid: bool
    spec: Optional[Dict[str, Any]] = None
    validation: Dict[str, Any]


class CompileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    spec: Dict[str, Any]


class CompileResponse(BaseModel):
    dataset_id: str
    scenario_id: str
    scenario_category: str
    events_count: int
    dataset_role: str
    generator_version: Optional[str] = None
    llm_input_sha256: Optional[str] = None
    is_training_eligible: bool
    ground_truth_available: bool
    provenance: Dict[str, Any]


@router.get(
    "/categories",
    summary="Supported attack categories and detector routing",
)
def list_supported_categories() -> List[Dict[str, Any]]:
    from app.services.scenario_simulator.spec import CATEGORY_REGISTRY

    return [
        {
            "attack_category": cat.value,
            "detector_route": route.model_dump(),
        }
        for cat, route in CATEGORY_REGISTRY.items()
    ]


@router.post(
    "/propose",
    response_model=ProposeResponse,
    summary="Generate an LLM scenario proposal (preview only, not persisted)",
)
async def propose_scenario(payload: ProposeRequest) -> ProposeResponse:
    """Ask the configured LLM to propose a safe synthetic scenario specification.

    The proposal is screened, structurally validated, and safety/feasibility
    checked before being returned. It is NOT persisted and NOT executed. If the
    provider is unavailable, the caller receives an honest 503 with
    fallback_available=true so the deterministic simulator can be used instead.
    """
    request_report = validate_analyst_request(payload.request)
    if not request_report.ok:
        # Return the itemized unsafe-request feedback rather than calling the LLM.
        return ProposeResponse(
            status="unsafe_request",
            validation=request_report.to_serializable(),
            fallback_available=True,
        )

    controls = payload.controls.model_dump(exclude_none=True) if payload.controls else {}

    # Bound the total LLM interaction so an honest 503 reaches the client before
    # its own request timeout fires. This MUST stay below the frontend axios
    # timeout (15s); otherwise the browser aborts first and the fallback path the
    # UI depends on never renders (see frontend/src/api.ts).
    try:
        async with asyncio.timeout(PROPOSE_DEADLINE_SECONDS):
            result = await generate_scenario_proposal(
                request=payload.request,
                controls=controls,
                model=payload.model,
            )
    except ProviderUnavailableError as exc:
        logger.warning("Scenario provider unavailable: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": str(exc),
                "fallback_available": True,
                "hint": "The deterministic simulator remains available without the LLM.",
            },
        )
    except TimeoutError:
        logger.warning(
            "Scenario proposal exceeded the %.0fs deadline", PROPOSE_DEADLINE_SECONDS
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": f"AI provider did not respond within {PROPOSE_DEADLINE_SECONDS:.0f}s.",
                "fallback_available": True,
                "hint": "The deterministic simulator remains available without the LLM.",
            },
        )

    return ProposeResponse(**result)


@router.post(
    "/validate",
    response_model=ValidateResponse,
    summary="Validate a scenario specification (schema + safety + feasibility)",
)
def validate_scenario(payload: ValidateRequest) -> ValidateResponse:
    """Validate a caller-supplied (possibly analyst-edited) scenario spec.

    Used after the analyst edits safe parameters in the preview, before
    confirming generation in Milestone 3.
    """
    try:
        spec = ScenarioSpec(**payload.spec)
    except Exception as exc:  # pydantic ValidationError or TypeError
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"Scenario failed schema validation: {type(exc).__name__}"},
        )

    report = run_full_validation(spec)
    return ValidateResponse(
        valid=report.ok,
        spec=spec.model_dump(mode="json"),
        validation=report.to_serializable(),
    )


@router.post(
    "/compile",
    response_model=CompileResponse,
    summary="Compile a validated scenario spec into a persisted, replayable dataset",
)
def compile_scenario(payload: CompileRequest, db: DBSession = Depends(get_db)) -> CompileResponse:
    """Deterministically expand a validated spec into synthetic telemetry + a Dataset.

    The spec is re-checked (schema + safety + feasibility) here so a caller can
    never persist unvalidated telemetry. Compilation writes only a Dataset row of
    synthetic events; it does not execute anything or emit real traffic.
    """
    try:
        spec = ScenarioSpec(**payload.spec)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"Scenario failed schema validation: {type(exc).__name__}"},
        )

    report = run_full_validation(spec)
    if not report.ok:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "Scenario failed safety/feasibility validation", "validation": report.to_serializable()},
        )

    try:
        ds = compile_scenario_to_dataset(spec, db)
    except CompilationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"Scenario could not be compiled: {exc}"},
        )

    return CompileResponse(
        dataset_id=ds.id,
        scenario_id=ds.scenario_id,
        scenario_category=ds.scenario_category,
        events_count=ds.events_count,
        dataset_role=ds.dataset_role,
        generator_version=ds.generator_version,
        llm_input_sha256=ds.llm_input_sha256,
        is_training_eligible=ds.is_training_eligible,
        ground_truth_available=ds.ground_truth_available,
        provenance=spec.generation_provenance.model_dump(mode="json"),
    )


@router.post(
    "/datasets/{dataset_id}/replay",
    summary="Replay a compiled dataset through detection and evaluate expected vs actual",
)
def replay_dataset(
    dataset_id: str,
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    """Materialize compiled telemetry into the real event tables, run the existing
    rule + ML detectors, and score actual detections against the spec's trusted
    expected labels. Produces an EvaluationRun and returns the comparison."""
    try:
        return replay_studio_dataset(dataset_id, db)
    except ReplayError as exc:
        msg = str(exc)
        code = status.HTTP_404_NOT_FOUND if "not found" in msg.lower() else status.HTTP_400_BAD_REQUEST
        raise HTTPException(status_code=code, detail={"error": msg})


@router.get(
    "/datasets/{dataset_id}/lifecycle",
    summary="Retrieve the separated lifecycle layers + provenance for a compiled dataset",
)
def get_dataset_lifecycle_endpoint(
    dataset_id: str,
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    """Return plan / telemetry / ground-truth / detections / evaluation as distinct
    layers plus provenance, for the Scenario Lifecycle Explorer."""
    try:
        return get_dataset_lifecycle(dataset_id, db)
    except ReplayError as exc:
        msg = str(exc)
        code = status.HTTP_404_NOT_FOUND if "not found" in msg.lower() else status.HTTP_400_BAD_REQUEST
        raise HTTPException(status_code=code, detail={"error": msg})


@router.get(
    "/datasets/{dataset_id}/learning-eligibility",
    summary="Check whether an evaluated dataset is eligible to import into Adaptive Learning",
)
def learning_eligibility_endpoint(
    dataset_id: str,
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    """Report learning-import eligibility without mutating anything.

    Surfaces the ground-truth, feature-schema compatibility, dataset-role,
    evaluation, cross-partition and duplicate-protection checks an analyst must
    satisfy before examples may enter the training pool.
    """
    try:
        return evaluate_learning_eligibility(dataset_id, db)
    except LearningImportError as exc:
        msg = str(exc)
        code = status.HTTP_404_NOT_FOUND if "not found" in msg.lower() else status.HTTP_400_BAD_REQUEST
        raise HTTPException(status_code=code, detail={"error": msg})


@router.post(
    "/datasets/{dataset_id}/import-learning",
    summary="Import an eligible dataset's trusted examples into the Adaptive Learning pool",
)
def import_learning_endpoint(
    dataset_id: str,
    db: DBSession = Depends(get_db),
) -> Dict[str, Any]:
    """Append trusted, design-time-labeled LearningExample rows for an eligible
    ``training`` dataset so the existing (unchanged) model-acceptance gate can later
    consider them. This never trains or activates a model, and rejects validation /
    test / unverified / heuristic-only datasets."""
    try:
        return import_dataset_learning_examples(dataset_id, db)
    except LearningImportError as exc:
        msg = str(exc)
        code = status.HTTP_404_NOT_FOUND if "not found" in msg.lower() else status.HTTP_409_CONFLICT
        raise HTTPException(status_code=code, detail={"error": msg})
