"""LLM scenario proposal generator (Milestone 2).

Implements the "LLM proposes; deterministic services execute" contract:

    1. Screen the analyst request for unsafe intent (never spend tokens on a
       request to actually attack/execute).
    2. Build a *constrained* prompt embedding the versioned schema, the
       supported-category registry and hard bounds.
    3. Ask the configured OpenRouter model for a single JSON object.
    4. Parse, structurally validate (``spec.ScenarioSpec``) and safety/feasibility
       validate (``validators``).
    5. On failure, perform a bounded repair pass (never infinite retries).
    6. If the provider is unavailable, honestly signal it and offer a
       deterministic fallback proposal so the pipeline stays usable.

This module produces and validates a *plan* only. It never writes database rows,
executes code, runs scans, sends messages, or calls any arbitrary tool.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import ValidationError

from app.config import settings
from app.services.chatbot_service import query_openrouter_messages, ChatbotServiceError
from app.services.scenario_simulator.spec import (
    AttackCategory,
    EventCategory,
    GroundTruthSource,
    Intensity,
    MAX_EVENT_COUNT,
    MAX_LLM_OUTPUT_TOKENS,
    MAX_VALIDATION_REPAIR_ATTEMPTS,
    SCENARIO_SPEC_SCHEMA_VERSION,
    ScenarioSpec,
    is_supported_category,
)
from app.services.scenario_simulator.validators import (
    ValidationReport,
    run_full_validation,
    validate_analyst_request,
)

logger = logging.getLogger(__name__)

GENERATOR_VERSION = "scenario-studio-1.0"


class ProviderUnavailableError(RuntimeError):
    """Raised when the LLM provider cannot be used; caller may fall back."""


# ==========================================
# Prompt construction
# ==========================================

_SUPPORTED_CATEGORY_DOC = (
    "- port_scan: network reconnaissance across many distinct destination ports (Suricata events).\n"
    "- brute_force: repeated failed logins against ONE account, optionally succeeding after failures (auth events).\n"
    "- credential_stuffing: one source authenticating against MANY distinct accounts in a short window (auth events).\n"
    "- phishing_url: offline URL analysis of synthetic .invalid/.example/.test domains (heuristic only, no ML).\n"
)


def build_system_prompt() -> str:
    return f"""You are the FraudGuard Attack Scenario Simulator's proposal engine.
You produce a SYNTHETIC, OFFLINE attack-simulation scenario specification for a defensive SOC learning platform.
You DO NOT execute anything. You only emit a JSON plan.

HARD RULES:
- Output EXACTLY ONE JSON object. No prose, no markdown fences, no commentary.
- The JSON MUST conform to schema_version "{SCENARIO_SPEC_SCHEMA_VERSION}".
- Only these attack_category values are supported:
{_SUPPORTED_CATEGORY_DOC}
- ALL entities must be clearly synthetic:
  * IPs MUST be RFC5737 (192.0.2.x, 198.51.100.x, 203.0.113.x) or RFC1918 (10.x, 172.16-31.x, 192.168.x).
  * Domains/URLs MUST use .invalid, .example, .test, or localhost.
  * Accounts/devices are fictional. NEVER real credentials or real external targets.
- Never include executable code, shell commands, exploit payloads, firewall changes,
  malware, message-sending, or instructions to attack real systems.
- Keep ground truth SEPARATE from observable features. Ground truth source MUST be one of:
  ids_signature, scenario_design, heuristic_policy, unverified. Never derive labels from detector output.
- Bounds: event_count 1..{MAX_EVENT_COUNT}; duration_seconds 1..86400; at most 12 stages.
- event_category MUST match the attack_category routing (network for port_scan, auth for
  brute_force/credential_stuffing, phishing for phishing_url).

TOP-LEVEL JSON FIELDS:
schema_version, scenario_id, title, description, attack_category, intensity(low|medium|high),
duration_seconds, event_count, seed, stages[], entity_templates[], event_templates[],
expected_outcomes[], evaluation_objective, ground_truth_source, dataset_role(training|validation|test),
benign_to_malicious_ratio(optional 0..1), generation_provenance.

stage: stage_id, stage_type(benign_baseline|recon|initial_access|lateral_or_escalation|exfil_or_impact|benign_noise),
description, depends_on[](stage ids), planned_event_template_ids[], expected_observable_behavior.
entity_template: entity_id, kind(source_ip|dest_ip|target_account|device|host|url), value, attributes{{}}.
event_template: template_id, stage_id, event_category(network|auth|phishing), time_offset_seconds,
source_ref(optional entity_id), target_ref(optional entity_id), features{{observable only}},
ground_truth_label(0|1), ground_truth_source, repetition(1..{MAX_EVENT_COUNT}).
expected_outcome: expected_detection_labels[], is_malicious(bool), rationale.
generation_provenance: generator_version, source(llm), model(optional), request_correlation_id.
"""


def build_user_prompt(request: str, controls: Dict[str, Any]) -> str:
    lines = ["ANALYST REQUEST:", request.strip(), "", "APPLIED CONTROLS (authoritative constraints):"]
    for key in (
        "attack_category", "intensity", "event_count", "duration_seconds",
        "benign_to_malicious_ratio", "seed", "evaluation_objective",
    ):
        if controls.get(key) is not None:
            lines.append(f"- {key}: {controls[key]}")
    lines.append("")
    lines.append(
        "Return the single JSON scenario specification that faithfully simulates the request "
        "as safe synthetic telemetry, honoring the controls above. Use the provided seed verbatim."
    )
    return "\n".join(lines)


def _extract_json(text: str) -> Dict[str, Any]:
    """Parse a JSON object from assistant text, tolerating code fences."""
    if not text:
        raise ValueError("Empty provider response.")
    candidate = text.strip()
    # Strip ```json fences if present despite instructions.
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", candidate, re.DOTALL)
    if fence:
        candidate = fence.group(1)
    else:
        # Fallback: grab the outermost {...}.
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = candidate[start : end + 1]
    obj = json.loads(candidate)
    if not isinstance(obj, dict):
        raise ValueError("Provider output was not a JSON object.")
    return obj


def _normalize_provenance(spec_dict: Dict[str, Any], model: Optional[str], correlation_id: str, prompt: str) -> Dict[str, Any]:
    prov = spec_dict.get("generation_provenance") or {}
    prov["generator_version"] = GENERATOR_VERSION
    prov["source"] = "llm"
    prov["model"] = model
    prov["request_correlation_id"] = correlation_id
    prov["llm_input_sha256"] = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    prov.setdefault("created_at", datetime.now(timezone.utc).isoformat())
    spec_dict["generation_provenance"] = prov
    # schema_version is authoritative regardless of what the model returns.
    spec_dict["schema_version"] = SCENARIO_SPEC_SCHEMA_VERSION
    return spec_dict


def _apply_authoritative_controls(spec_dict: Dict[str, Any], controls: Dict[str, Any]) -> Dict[str, Any]:
    """Controls are trusted over the model's guesses for safe numeric params."""
    for key in ("event_count", "duration_seconds", "seed"):
        val = controls.get(key)
        if val is not None:
            try:
                spec_dict[key] = int(val)
            except (TypeError, ValueError):
                pass
    if controls.get("attack_category") and is_supported_category(str(controls["attack_category"])):
        spec_dict["attack_category"] = controls["attack_category"]
    if controls.get("intensity") in {i.value for i in Intensity}:
        spec_dict["intensity"] = controls["intensity"]
    if controls.get("dataset_role") in {"training", "validation", "test"}:
        spec_dict["dataset_role"] = controls["dataset_role"]
    spec_dict.setdefault("seed", controls.get("seed", 42))
    return spec_dict


def _schema_errors_to_report(exc: ValidationError) -> ValidationReport:
    from app.services.scenario_simulator.validators import ValidationViolation
    report = ValidationReport()
    for err in exc.errors():
        loc = ".".join(str(p) for p in err.get("loc", []))
        report.violations.append(
            ValidationViolation("schema", err.get("msg", "invalid value"), loc)
        )
    return report


def _report_to_messages(report: ValidationReport) -> List[str]:
    return [f"{v.location or v.code}: {v.message}" for v in report.violations]


# ==========================================
# Main entrypoint
# ==========================================

async def generate_scenario_proposal(
    request: str,
    controls: Optional[Dict[str, Any]] = None,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate and validate a scenario proposal from a natural-language request.

    Returns a dict:
        {
          "status": "ready" | "invalid" | "unsafe_request",
          "spec": <ScenarioSpec dict> | None,
          "validation": <serializable report>,
          "model": str | None,
          "correlation_id": str,
          "attempts": int,
          "fallback_available": bool,
        }
    Raises ProviderUnavailableError only when the provider fails AND no usable
    proposal could be produced, so the caller can fall back deterministically.
    """
    controls = controls or {}
    correlation_id = f"corr_{uuid.uuid4().hex[:12]}"

    # 1. Pre-token safety screen of the request.
    request_report = validate_analyst_request(request)
    if not request_report.ok:
        return {
            "status": "unsafe_request",
            "spec": None,
            "validation": request_report.to_serializable(),
            "model": None,
            "correlation_id": correlation_id,
            "attempts": 0,
            "fallback_available": True,
        }

    system_prompt = build_system_prompt()
    user_prompt = build_user_prompt(request, controls)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    last_report = ValidationReport()
    used_model = model or settings.OPENROUTER_MODEL

    for attempt in range(MAX_VALIDATION_REPAIR_ATTEMPTS + 1):
        try:
            result = await query_openrouter_messages(
                messages=messages,
                model=model,
                max_tokens=MAX_LLM_OUTPUT_TOKENS,
                temperature=0.2,
            )
        except ChatbotServiceError as exc:
            # Provider/key/rate issues -> let caller fall back.
            raise ProviderUnavailableError(exc.message) from exc

        used_model = result.get("model", used_model)
        raw = result.get("text", "")

        try:
            spec_dict = _extract_json(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            last_report = ValidationReport()
            from app.services.scenario_simulator.validators import ValidationViolation
            last_report.violations.append(
                ValidationViolation("malformed_json", f"Provider output was not valid JSON: {exc}", "provider")
            )
            messages.append({"role": "assistant", "content": raw[:2000]})
            messages.append({"role": "user", "content": "Output ONLY a single valid JSON object conforming to the schema. Fix the error: " + str(exc)})
            continue

        spec_dict = _apply_authoritative_controls(spec_dict, controls)
        spec_dict = _normalize_provenance(spec_dict, used_model, correlation_id, request)

        # 2. Structural schema validation.
        try:
            spec = ScenarioSpec(**spec_dict)
        except ValidationError as exc:
            last_report = _schema_errors_to_report(exc)
            msgs = "; ".join(_report_to_messages(last_report))
            messages.append({"role": "assistant", "content": json.dumps(spec_dict)[:2000]})
            messages.append({"role": "user", "content": f"The JSON failed schema validation. Errors: {msgs}. Return corrected JSON only."})
            continue

        # 3. Safety + feasibility validation.
        full_report = run_full_validation(spec)
        if not full_report.ok:
            last_report = full_report
            msgs = "; ".join(_report_to_messages(full_report))
            messages.append({"role": "assistant", "content": json.dumps(spec.model_dump(mode="json"))[:2000]})
            messages.append({"role": "user", "content": f"The scenario is unsafe/infeasible. Violations: {msgs}. Return corrected JSON only, keeping all entities synthetic."})
            continue

        return {
            "status": "ready",
            "spec": spec.model_dump(mode="json"),
            "validation": full_report.to_serializable(),
            "model": used_model,
            "correlation_id": correlation_id,
            "attempts": attempt + 1,
            "fallback_available": True,
        }

    # Exhausted bounded repairs.
    return {
        "status": "invalid",
        "spec": None,
        "validation": last_report.to_serializable(),
        "model": used_model,
        "correlation_id": correlation_id,
        "attempts": MAX_VALIDATION_REPAIR_ATTEMPTS + 1,
        "fallback_available": True,
    }
