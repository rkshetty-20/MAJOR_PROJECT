"""IDS analysis router: expanded Intrusion Detection payload-submission API.

Endpoints (all DB-free, deterministic given a seed):
  GET  /api/ids/catalog          - attack categories + attack types
  GET  /api/ids/presets          - one-click multi-stage simulation presets
  GET  /api/ids/rules            - rule registry for the management panel
  GET  /api/ids/rules/summary    - registry counts derived from the code
  POST /api/ids/analyze          - generate + run rules + ML + fuse a result
  POST /api/ids/preset/run       - run every stage of a preset in sequence

Input scope: the analysed packets are seeded synthetic/replayed telemetry.
No authorized live-capture ingestion path exists, so no endpoint here reports or
requires real-time traffic monitoring.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from app.services.ids import rules_engine
from app.services.ids.analysis import analyze_payload
from app.services.ids.attack_catalog import list_categories
from app.services.ids.presets import get_preset, list_presets

router = APIRouter(prefix="/api/ids", tags=["Intrusion Detection (IDS)"])


class AnalyzeRequest(BaseModel):
    attack_id: str = Field(..., description="Catalog attack type id")
    volume: str = Field(default="medium", description="low | medium | high")
    packet_count: int = Field(default=20, ge=1, le=200)
    seed: Optional[int] = Field(default=None, description="Deterministic seed for reproducibility")
    sensitivity: float = Field(default=0.5, ge=0.0, le=1.0, description="0 conservative -> 1 aggressive")
    rule_overrides: Optional[Dict[str, Any]] = Field(default=None, description="{rule_id: {enabled, threshold}}")
    rule_enabled: Optional[Dict[str, bool]] = Field(default=None, description="{rule_id: bool} quick toggles")

    model_config = ConfigDict(extra="ignore")


class PresetRunRequest(BaseModel):
    preset_id: str
    volume: str = Field(default="medium")
    packet_count: int = Field(default=15, ge=1, le=200)
    sensitivity: float = Field(default=0.5, ge=0.0, le=1.0)

    model_config = ConfigDict(extra="ignore")


@router.get("/catalog", summary="List attack categories and payload types")
def get_catalog() -> List[Dict[str, Any]]:
    return list_categories()


@router.get("/presets", summary="List one-click multi-stage attack presets")
def get_presets() -> List[Dict[str, Any]]:
    return list_presets()


@router.get("/rules", summary="Rule registry for the configuration panel")
def get_rules() -> List[Dict[str, Any]]:
    """Full per-rule contract (id, category, version, inputs, matching logic,
    severity, weight, tunable thresholds, explanation, MITRE mapping)."""
    out = []
    for r in rules_engine.RULE_REGISTRY:
        out.append({
            "rule_id": r["rule_id"],
            "name": r["name"],
            "layer": r["layer"],
            "category": r["category"],
            "version": r["version"],
            "severity": r["severity"],
            "weight": r["weight"],
            "mitre": r.get("mitre"),
            "description": r["description"],
            "matching": r["matching"],
            "explanation": r["explanation"],
            "inputs": list(r["inputs"]),
            "enabled": r["enabled"],
            "tunable": r["tunable"],
            "threshold": r.get("threshold"),
        })
    return out


@router.get("/rules/summary", summary="Registry counts derived from the implemented rules")
def get_rules_summary() -> Dict[str, Any]:
    """Reported counts come from ``RULE_REGISTRY`` itself, never a literal."""
    return rules_engine.registry_summary()


@router.post("/analyze", summary="Generate, detect and score an IDS payload")
def analyze(req: AnalyzeRequest) -> Dict[str, Any]:
    try:
        return analyze_payload(
            attack_id=req.attack_id,
            volume=req.volume,
            packet_count=req.packet_count,
            seed=req.seed,
            rule_overrides=req.rule_overrides,
            rule_enabled=req.rule_enabled,
            sensitivity=req.sensitivity,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).exception("IDS analyze failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"IDS analysis failed: {type(exc).__name__}")


@router.post("/preset/run", summary="Run every stage of a preset in sequence")
def run_preset(req: PresetRunRequest) -> Dict[str, Any]:
    try:
        preset = get_preset(req.preset_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

    import random
    base_seed = random.randint(1, 1_000_000)
    steps = []
    for i, stage in enumerate(preset["stages"]):
        result = analyze_payload(
            attack_id=stage["attack_id"],
            volume=req.volume,
            packet_count=req.packet_count,
            seed=base_seed + i,
            sensitivity=req.sensitivity,
        )
        steps.append({
            "beat": stage["beat"],
            "stage_index": i,
            "attack_name": result["attack"]["name"],
            "result": result,
        })

    # Overall preset threat = max stage threat (kill-chain escalation view)
    overall = max((s["result"]["verdict"]["threat_score"] for s in steps), default=0.0)
    return {
        "preset_id": preset["id"],
        "name": preset["name"],
        "tagline": preset["tagline"],
        "narrative": preset["narrative"],
        "overall_threat_score": overall,
        "steps": steps,
    }
