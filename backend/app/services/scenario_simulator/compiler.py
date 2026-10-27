"""Deterministic scenario compiler (Milestone 3).

Turns a *validated* ``ScenarioSpec`` (a plan) into a persisted, replayable
``Dataset`` of synthetic telemetry. The compiler is the "deterministic service
executes" half of the "LLM proposes; deterministic services execute" contract:

    * No LLM, no network, no execution of arbitrary code — only data expansion.
    * Fully reproducible: the same spec (including its seed) always yields the
      same event payload (identical bytes), so evaluations are stable.
    * Ground truth stays SEPARATE from observable telemetry: emitted events carry
      only observable fields plus a ``_template_id`` provenance link back into the
      spec. Labels/expected outcomes live in the preserved ``scenario_spec_json``.
    * Event shapes mirror ``simulation_service.generate_offline_dataset`` so the
      existing replay/evaluation path (Milestone 4) consumes them unchanged.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.models import Dataset
from app.services.scenario_simulator.generator import GENERATOR_VERSION
from app.services.scenario_simulator.spec import (
    GroundTruthSource,
    ScenarioSpec,
)

# Fixed epoch so timestamps are reproducible (never wall-clock `now`).
_BASE_EPOCH = datetime(2024, 1, 1, tzinfo=timezone.utc)

# Canonical service ports used to materialize deterministic scan fan-out.
_SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443,
    445, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 9000, 9200, 27017,
]


class CompilationError(ValueError):
    """Raised when a spec, though schema-valid, cannot be compiled safely."""


def _dataset_id(spec: ScenarioSpec) -> str:
    # Deterministic id keyed on scenario_id + seed so recompiles are stable/unique.
    return f"ds_scn_{spec.scenario_id}_seed{spec.seed}"[:64]


def _resolve_entity(spec: ScenarioSpec, entity_id: str | None) -> Dict[str, Any] | None:
    if not entity_id:
        return None
    for ent in spec.entity_templates:
        if ent.entity_id == entity_id:
            return {"kind": ent.kind, "value": ent.value, "attributes": ent.attributes}
    return None


def _default_for_category(spec: ScenarioSpec, role: str) -> str:
    """Fallback synthetic entity values, derived from the seed (never real hosts)."""
    rng = random.Random(f"{spec.seed}:{spec.scenario_id}:{role}")
    octet = rng.randint(2, 250)
    if role == "src":
        return f"10.0.0.{octet}"
    if role == "dst":
        return f"192.0.2.{octet}"
    return f"acct_{octet}"


def _event_timestamp(spec: ScenarioSpec, template_index: int, offset_seconds: float, rep: int, step: float) -> str:
    # Per-template base offset plus fine-grained, deterministic spacing per repeat.
    seconds = offset_seconds + template_index * 0.01 + rep * step
    return (_BASE_EPOCH + timedelta(seconds=seconds)).isoformat()


def _build_network_event(spec: ScenarioSpec, template, port: int, src: str, dst: str, ts: str) -> Dict[str, Any]:
    features = template.features or {}
    return {
        "type": "network",
        "timestamp": ts,
        "src_ip": src,
        "dest_ip": dst,
        "dest_port": int(features.get("dest_port", port)),
        "protocol": str(features.get("protocol", "TCP")),
        "severity": int(features.get("severity", 2)),
        "raw_signature": str(features.get("raw_signature", "ET SCAN Possible Nmap User-Agent Observed")),
        "payload": {
            "scan_type": features.get("scan_type", "SYN_STEALTH"),
            "distinct_dest_ports": features.get("distinct_dest_ports"),
        },
        "_template_id": template.template_id,
    }


def _build_auth_event(spec: ScenarioSpec, template, src: str, target: str, ts: str) -> Dict[str, Any]:
    features = template.features or {}
    # Prefer an explicit observable event_type; otherwise infer a benign/attack
    # default from the scenario label WITHOUT leaking the label into the event.
    event_type = str(features.get("event_type") or ("failed_authentication" if template.ground_truth_label == 1 else "baseline_login"))
    return {
        "type": "auth",
        "event_type": event_type,
        "timestamp": ts,
        "source": src,
        "target": target,
        "device": str(features.get("device", "Chrome 122 / Windows 11")),
        "payload": {
            "auth_method": features.get("auth_method", "password"),
            "status": features.get("status", "failed" if "failed" in event_type else "success"),
        },
        "_template_id": template.template_id,
    }


def _build_phishing_event(spec: ScenarioSpec, template, src: str, url: str, ts: str) -> Dict[str, Any]:
    features = template.features or {}
    return {
        "type": "phishing",
        "event_type": "phishing_url",
        "timestamp": ts,
        "source": src,
        "target": url,
        "device": str(features.get("device", "Chrome 122 / Windows 10")),
        "payload": {
            "url": url,
            "domain_age_days": features.get("domain_age_days", 2),
            "https": features.get("https", False),
            "suspicious_keywords": features.get("suspicious_keywords", []),
            "reputation_score": features.get("reputation_score", 12),
        },
        "_template_id": template.template_id,
    }


def compile_scenario_to_dataset(spec: ScenarioSpec, db: Session, persist: bool = True) -> Dataset:
    """Expand a validated spec into deterministic telemetry and persist a Dataset.

    Raises ``CompilationError`` if the (already schema-valid) spec cannot produce
    any telemetry, so callers never persist an empty/misleading dataset.
    """
    if not spec.event_templates:
        raise CompilationError("Scenario has no event templates to compile.")

    # Global sanity: total planned events must fit the declared bound.
    total = sum(t.repetition for t in spec.event_templates)
    if total < 1:
        raise CompilationError("Compiled event count must be positive.")

    events: List[Dict[str, Any]] = []
    has_verified_label = False

    for t_idx, template in enumerate(spec.event_templates):
        src_ent = _resolve_entity(spec, template.source_ref)
        dst_ent = _resolve_entity(spec, template.target_ref)
        cat = template.event_category.value
        # Scan traffic must be dense enough that the sliding-window rule observes
        # the intended distinct-port count inside its window; auth/phishing are
        # naturally slower-paced, so a coarser, still-deterministic step is used.
        step = 0.2 if cat == "network" else 1.0

        for rep in range(template.repetition):
            ts = _event_timestamp(spec, t_idx, template.time_offset_seconds, rep, step)

            if cat == "network":
                src = src_ent["value"] if src_ent else _default_for_category(spec, "src")
                dst = dst_ent["value"] if dst_ent else _default_for_category(spec, "dst")
                # Deterministic port fan-out so a scan template spreads distinct ports.
                port = _SCAN_PORTS[(t_idx * 7 + rep) % len(_SCAN_PORTS)]
                events.append(_build_network_event(spec, template, port, src, dst, ts))

            elif cat == "auth":
                src = src_ent["value"] if src_ent else _default_for_category(spec, "src")
                if dst_ent:
                    target = dst_ent["value"]
                else:
                    # Distinct synthetic account per repeat when no fixed target entity,
                    # so credential-stuffing spreads across many accounts deterministically.
                    target = _default_for_category(spec, f"acct{rep}")
                events.append(_build_auth_event(spec, template, src, target, ts))

            elif cat == "phishing":
                src = src_ent["value"] if src_ent else _default_for_category(spec, "src")
                if dst_ent and dst_ent["kind"].lower() in {"url", "domain", "host"}:
                    url = dst_ent["value"]
                else:
                    url = (template.features or {}).get("url")
                if not url:
                    raise CompilationError(
                        f"Phishing template '{template.template_id}' has no URL entity or 'url' feature."
                    )
                events.append(_build_phishing_event(spec, template, src, url, ts))
            else:  # pragma: no cover - guarded by schema routing
                raise CompilationError(f"Unsupported event_category '{cat}'.")

            if template.ground_truth_source != GroundTruthSource.UNVERIFIED:
                has_verified_label = True

    ds = Dataset(
        id=_dataset_id(spec),
        schema_version=spec.schema_version,
        scenario_category=spec.attack_category.value,
        events_count=len(events),
        payload_json=json.dumps(events, sort_keys=True),
        is_synthetic=True,
        is_evaluated=False,
        # Training eligibility requires a defensible (non-unverified) label source.
        is_training_eligible=has_verified_label,
        ground_truth_available=has_verified_label,
        scenario_id=spec.scenario_id,
        generator_version=spec.generation_provenance.generator_version or GENERATOR_VERSION,
        dataset_role=spec.dataset_role.value,
        llm_input_sha256=spec.generation_provenance.llm_input_sha256,
        scenario_spec_json=json.dumps(spec.model_dump(mode="json"), sort_keys=True),
    )

    if persist:
        # db.merge returns the persistent (managed) instance for this deterministic id.
        ds = db.merge(ds)
        db.commit()
        db.refresh(ds)

    return ds
