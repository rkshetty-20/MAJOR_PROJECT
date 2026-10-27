"""Fusion layer: combine generation, rules and ML into an explainable analysis.

Produces the complete response consumed by the results / analysis dashboard:
verdict, combined threat score, MITRE mapping, kill-chain stage, rule hits, ML
breakdown, packet-analysis summaries, threat intelligence and a flow timeline.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.services.ids.anomaly_scorer import score_anomaly
from app.services.ids.attack_catalog import get_attack
from app.services.ids.packet_generator import generate_packets
from app.services.ids.rules_engine import SEVERITY_RANK, run_rules

VERDICT_CLEAN = "Clean"
VERDICT_SUSPICIOUS = "Suspicious"
VERDICT_MALICIOUS = "Malicious"

# Sensitivity (0.0 conservative .. 1.0 aggressive) shifts verdict thresholds.
_BASE_THRESHOLDS = {"clean_max": 34, "suspicious_max": 62}


def _thresholds_for(sensitivity: float) -> Dict[str, float]:
    # More aggressive -> lower thresholds (flags sooner)
    shift = (sensitivity - 0.5) * 24
    return {
        "clean_max": max(10.0, _BASE_THRESHOLDS["clean_max"] - shift),
        "suspicious_max": max(_BASE_THRESHOLDS["clean_max"] + 6, _BASE_THRESHOLDS["suspicious_max"] - shift),
    }


def _fuse(rule_score: float, ml_score: float) -> float:
    blended = 0.55 * rule_score + 0.45 * ml_score
    # Reward a strong signal from either engine (so zero-days still surface)
    escalated = blended + (max(rule_score, ml_score) - blended) * 0.35
    return round(max(0.0, min(1.0, escalated)), 4)


def analyze_payload(
    attack_id: str,
    volume: str = "medium",
    packet_count: int = 20,
    seed: Optional[int] = None,
    rule_overrides: Dict[str, Any] = None,
    rule_enabled: Dict[str, bool] = None,
    sensitivity: float = 0.5,
) -> Dict[str, Any]:
    attack = get_attack(attack_id)
    gen = generate_packets(attack_id, packet_count=packet_count, volume=volume, seed=seed)
    packets = gen["packets"]

    rules = run_rules(packets, overrides=rule_overrides, enabled=rule_enabled)
    ml = score_anomaly(packets)

    rule_score = rules["rule_score"]
    ml_score = ml["overall_score"]
    threat = _fuse(rule_score, ml_score)
    threat_score = round(threat * 100, 1)

    thresholds = _thresholds_for(max(0.0, min(1.0, sensitivity)))
    has_critical = any(t["severity"] == "critical" for t in rules["triggered"])
    has_high = any(SEVERITY_RANK.get(t["severity"], 0) >= SEVERITY_RANK["high"] for t in rules["triggered"])

    if threat_score <= thresholds["clean_max"] and not rules["triggered"]:
        verdict = VERDICT_CLEAN
    elif has_critical or threat_score > thresholds["suspicious_max"] or (has_high and threat_score >= 50):
        verdict = VERDICT_MALICIOUS
    else:
        verdict = VERDICT_SUSPICIOUS

    # If benign catalog entry but rules/ml both near zero, force clean
    if attack["category"] == "baseline" and threat_score <= thresholds["clean_max"]:
        verdict = VERDICT_CLEAN

    mitre = _aggregate_mitre(attack, rules["triggered"])

    return {
        "analysis_id": f"ids_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{attack_id}",
        "attack": {
            "id": attack["id"],
            "name": attack["name"],
            "category": attack["category"],
            "description": attack["description"],
            "severity": attack["severity"],
        },
        "generation": {
            "volume": gen["volume"],
            "seed": gen["seed"],
            "packet_count": gen["generated_count"],
        },
        "verdict": {
            "label": verdict,
            "threat_score": threat_score,
            "rule_score": round(rule_score * 100, 1),
            "ml_score": round(ml_score * 100, 1),
        },
        "rules": {
            "triggered_count": len(rules["triggered"]),
            "triggered": rules["triggered"],
            "evaluated": rules["evaluated"],
        },
        "ml": ml,
        "kill_chain": _kill_chain(attack["kill_chain_stage"]),
        "mitre": mitre,
        "packets": packets,
        "packet_analysis": _packet_analysis(packets),
        "threat_intel": _threat_intel(attack),
    }


def _kill_chain(stage: str) -> Dict[str, Any]:
    stages = ["reconnaissance", "weaponization", "delivery", "exploitation",
              "installation", "command_and_control", "actions"]
    labels = {"reconnaissance": "Reconnaissance", "weaponization": "Weaponization",
              "delivery": "Delivery", "exploitation": "Exploitation",
              "installation": "Installation", "command_and_control": "Command & Control",
              "actions": "Actions on Objectives"}
    idx = stages.index(stage) if stage in stages else 0
    return {
        "current": stage,
        "current_label": labels.get(stage, stage),
        "index": idx,
        "stages": [{"key": s, "label": labels[s], "reached": i <= idx} for i, s in enumerate(stages)],
    }


def _aggregate_mitre(attack: Dict[str, Any], triggered: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for m in attack.get("mitre", []):
        if m["technique_id"] and m["technique_id"] != "-":
            seen[m["technique_id"]] = {**m, "source": "attack_profile"}
    for t in triggered:
        tid = t.get("mitre")
        if tid and tid not in seen:
            seen[tid] = {"technique_id": tid, "technique_name": t["name"], "tactic": "Detected via rule",
                         "source": t["rule_id"]}
    return list(seen.values())


def _packet_analysis(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not packets:
        return {"protocol_breakdown": {}, "port_breakdown": {}, "flag_breakdown": {},
                "size_stats": {}, "suspicious_indices": [], "total_bytes": 0}
    protocols = Counter(p["protocol"] for p in packets)
    ports = Counter(p["dst_port"] for p in packets)
    flags = Counter(p["flags"] for p in packets)
    sizes = [p["size"] for p in packets]
    total_bytes = sum(sizes)
    mean = total_bytes / len(sizes)
    # Suspicious = large entropy-ish or signature-ish markers
    suspicious = [
        p["index"] for p in packets
        if any(k in p.get("payload_text", "").lower() for k in
               ("script", "union select", "/dev/tcp", "base64_decode", "<?php", "entity", "waitfor", "nc -e"))
    ]
    return {
        "protocol_breakdown": dict(protocols),
        "port_breakdown": dict(ports.most_common(12)),
        "flag_breakdown": dict(flags),
        "size_stats": {"min": min(sizes), "max": max(sizes), "mean": round(mean, 1), "total_bytes": total_bytes},
        "suspicious_indices": suspicious[:100],
        "total_bytes": total_bytes,
    }


def _threat_intel(attack: Dict[str, Any]) -> Dict[str, Any]:
    intel = dict(attack.get("threat_intel", {}) or {})
    intel.setdefault("cves", [])
    intel.setdefault("actors", [])
    intel.setdefault("nist", [])
    intel.setdefault("owasp", [])
    intel.setdefault("mitigations", [])
    intel["frequency_note"] = (
        "Historical prevalence is illustrative for this sandboxed simulator; "
        "no real threat-feed is queried."
    )
    return intel
