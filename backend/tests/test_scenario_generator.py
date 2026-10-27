"""Tests for the M2 LLM scenario generator.

The provider is mocked so no network/key is required. These assert the
"LLM proposes; deterministic services validate" contract:

    * a valid JSON proposal is screened, schema-checked and safety-checked;
    * an unsafe analyst request never reaches the provider;
    * malformed / invalid output triggers a *bounded* repair loop, then "invalid";
    * provider failures raise ProviderUnavailableError so the caller can fall back;
    * trusted controls override the model's guesses for safe parameters.
"""

import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest

from app.services.chatbot_service import (
    ChatbotServiceError,
    MissingAPIKeyError,
    OpenRouterRateLimitError,
    OpenRouterUnavailableError,
)
from app.services.scenario_simulator import generator
from app.services.scenario_simulator.generator import (
    ProviderUnavailableError,
    generate_scenario_proposal,
)
from app.services.scenario_simulator.spec import (
    MAX_VALIDATION_REPAIR_ATTEMPTS,
    SCENARIO_SPEC_SCHEMA_VERSION,
)


def _valid_spec_json(**overrides):
    base = {
        "schema_version": SCENARIO_SPEC_SCHEMA_VERSION,
        "scenario_id": "scn_gen_001",
        "title": "Generated port scan",
        "description": "Synthetic port scan proposal.",
        "attack_category": "port_scan",
        "intensity": "medium",
        "duration_seconds": 60,
        "event_count": 20,
        "seed": 7,
        "stages": [
            {"stage_id": "s1", "stage_type": "recon", "description": "Scan",
             "expected_observable_behavior": "many distinct ports"},
        ],
        "entity_templates": [
            {"entity_id": "src1", "kind": "source_ip", "value": "10.0.0.50"},
            {"entity_id": "dst1", "kind": "dest_ip", "value": "203.0.113.9"},
        ],
        "event_templates": [
            {"template_id": "et_scan", "stage_id": "s1", "event_category": "network",
             "time_offset_seconds": 5, "source_ref": "src1", "target_ref": "dst1",
             "features": {"distinct_dest_ports": 20}, "ground_truth_label": 1,
             "ground_truth_source": "ids_signature", "repetition": 20},
        ],
        "expected_outcomes": [
            {"expected_detection_labels": ["port_scan_detected"], "is_malicious": True,
             "rationale": "High port diversity."},
        ],
        "evaluation_objective": "Confirm scan detection.",
        "generation_provenance": {"generator_version": "x", "source": "llm"},
    }
    base.update(overrides)
    return base


def _provider_text(payload: dict) -> dict:
    return {"text": json.dumps(payload), "model": "mock-model"}


def test_valid_proposal_returns_ready():
    spec = _valid_spec_json()
    with patch.object(generator, "query_openrouter_messages", new=AsyncMock(return_value=_provider_text(spec))):
        result = asyncio.run(generate_scenario_proposal("Simulate a synthetic port scan."))
    assert result["status"] == "ready"
    assert result["spec"]["attack_category"] == "port_scan"
    assert result["attempts"] == 1
    assert result["validation"]["ok"] is True


def test_unsafe_request_never_calls_provider():
    mock = AsyncMock()
    with patch.object(generator, "query_openrouter_messages", new=mock):
        result = asyncio.run(
            generate_scenario_proposal("Deliver malware and execute a reverse shell on the target.")
        )
    assert result["status"] == "unsafe_request"
    assert result["attempts"] == 0
    mock.assert_not_called()


def test_authoritative_controls_override_model():
    spec = _valid_spec_json(event_count=999, seed=1)  # model guesses we should override
    with patch.object(generator, "query_openrouter_messages", new=AsyncMock(return_value=_provider_text(spec))):
        result = asyncio.run(
            generate_scenario_proposal("Simulate a synthetic port scan.", controls={"event_count": 20, "seed": 123})
        )
    # event_count=999 would be out of bounds; control overrides to 20 -> valid
    assert result["status"] == "ready"
    assert result["spec"]["event_count"] == 20
    assert result["spec"]["seed"] == 123


def test_malformed_json_exhausts_bounded_repairs():
    always_bad = AsyncMock(return_value={"text": "this is not json", "model": "mock-model"})
    with patch.object(generator, "query_openrouter_messages", new=always_bad):
        result = asyncio.run(generate_scenario_proposal("Simulate a synthetic port scan."))
    assert result["status"] == "invalid"
    assert result["spec"] is None
    # exactly one initial attempt + MAX_VALIDATION_REPAIR_ATTEMPTS repairs
    assert always_bad.await_count == MAX_VALIDATION_REPAIR_ATTEMPTS + 1


def test_unknown_category_proposal_is_invalid():
    bad = _valid_spec_json(attack_category="ddos")
    with patch.object(generator, "query_openrouter_messages", new=AsyncMock(return_value=_provider_text(bad))):
        result = asyncio.run(generate_scenario_proposal("Simulate a synthetic port scan."))
    assert result["status"] == "invalid"


def test_unsafe_entities_in_proposal_are_rejected():
    spec = _valid_spec_json()
    spec["entity_templates"][1]["value"] = "8.8.8.8"  # real, non-synthetic IP
    with patch.object(generator, "query_openrouter_messages", new=AsyncMock(return_value=_provider_text(spec))):
        result = asyncio.run(generate_scenario_proposal("Simulate a synthetic port scan."))
    assert result["status"] == "invalid"
    codes = {v["code"] for v in result["validation"]["violations"]}
    assert "external_target" in codes


def test_repair_succeeds_on_second_attempt():
    calls = {"n": 0}

    async def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"text": "not json yet", "model": "mock-model"}
        return _provider_text(_valid_spec_json())

    with patch.object(generator, "query_openrouter_messages", new=flaky):
        result = asyncio.run(generate_scenario_proposal("Simulate a synthetic port scan."))
    assert result["status"] == "ready"
    assert result["attempts"] == 2


@pytest.mark.parametrize(
    "exc",
    [MissingAPIKeyError(), OpenRouterRateLimitError(), OpenRouterUnavailableError(), ChatbotServiceError("boom")],
)
def test_provider_failures_raise_provider_unavailable(exc):
    with patch.object(generator, "query_openrouter_messages", new=AsyncMock(side_effect=exc)):
        with pytest.raises(ProviderUnavailableError):
            asyncio.run(generate_scenario_proposal("Simulate a synthetic port scan."))
