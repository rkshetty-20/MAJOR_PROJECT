"""Multi-layer IDS rules engine: signature, threshold and stateful detection.

Rules operate on *generated packets* (not catalog labels) so detections are
genuine. The public surface:

  * ``RULE_REGISTRY``  - ordered rule metadata for the config / management panel
  * ``run_rules(packets, overrides)`` - evaluate enabled rules -> detections
  * severity ranking + combined rule score for verdict fusion

Each rule declares a ``layer`` (signature|threshold|stateful), a default
``severity`` and an optional tunable ``threshold`` used by the UI panel.
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from typing import Any, Callable, Dict, List

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_WEIGHT = {"info": 2, "low": 6, "medium": 14, "high": 24, "critical": 34}

# ---------------------------------------------------------------------------
# Signature catalog (regex, severity, MITRE hint). Kept as data so the panel
# and tests can enumerate them. Patterns are intentionally generic/benign.
# ---------------------------------------------------------------------------
_SIGNATURES: List[Dict[str, Any]] = [
    {"rule_id": "SIG-SQLI-UNION", "name": "SQL Injection (UNION SELECT)", "severity": "high",
     "mitre": "T1190", "pattern": r"union\s+select|UNION%20SELECT|%27%20UNION", "weight": 30},
    {"rule_id": "SIG-SQLI-BLIND", "name": "SQL Injection (Boolean blind)", "severity": "high",
     "mitre": "T1190", "pattern": r"(?i)(?:and|or)(?:%20|\+|\s)\s*\d\s*=\s*\d|'?\s*or\s*'?\d'?\s*=\s*'?\d|--\s*$|%27%20or", "weight": 26},
    {"rule_id": "SIG-SQLI-TIME", "name": "SQL Injection (Time-based)", "severity": "high",
     "mitre": "T1190", "pattern": r"(?i)waitfor(?:%20|\s)delay|sleep\(|benchmark\(|pg_sleep", "weight": 26},
    {"rule_id": "SIG-CMDINJ", "name": "OS Command Injection", "severity": "critical",
     "mitre": "T1190", "pattern": r";\s*(?:cat|rm|bash|nc)\b|\|\s*/bin/|`[^`]+`|\$\(.*\)", "weight": 34},
    {"rule_id": "SIG-XSS", "name": "Cross-Site Scripting", "severity": "medium",
     "mitre": "T1059.007", "pattern": r"<script|onerror=|javascript:|alert\(|document\.cookie", "weight": 22},
    {"rule_id": "SIG-XXE", "name": "XML External Entity", "severity": "high",
     "mitre": "T1190", "pattern": r"<!ENTITY|<!DOCTYPE|SYSTEM\s+\"file:", "weight": 26},
    {"rule_id": "SIG-LDAP", "name": "LDAP Injection Filter", "severity": "high",
     "mitre": "T1190", "pattern": r"\)\(\*\)|\(\|\(uid=|\)\(\|\(", "weight": 24},
    {"rule_id": "SIG-REVSHELL", "name": "Reverse Shell Indicator", "severity": "critical",
     "mitre": "T1059", "pattern": r"/dev/tcp/|nc\s+-e|bash\s+-i|subprocess", "weight": 34},
    {"rule_id": "SIG-WEBSHELL", "name": "Webshell Upload Indicator", "severity": "critical",
     "mitre": "T1100", "pattern": r"<\?php\s+system|shell\.php|filename=\"[^\"]+\.php", "weight": 34},
    {"rule_id": "SIG-ENCODED", "name": "Encoded Command Wrapper", "severity": "high",
     "mitre": "T1027", "pattern": r"base64_decode|atob\(|eval\(", "weight": 24},
    {"rule_id": "SIG-SESSIONHIJACK", "name": "Session Cookie Anomaly", "severity": "medium",
     "mitre": "T1563.001", "pattern": r"Cookie:\s*sessionid=", "weight": 16},
    {"rule_id": "SIG-TOKENREPLAY", "name": "Bearer Token Replay", "severity": "medium",
     "mitre": "T1550.004", "pattern": r"Authorization:\s*Bearer\s+eyJ", "weight": 16},
    {"rule_id": "SIG-MITM", "name": "MITM / Intercepted TLS", "severity": "critical",
     "mitre": "T1557", "pattern": r"issuer=EVIL|\(relayed\)|CN=\*\.", "weight": 34},
    {"rule_id": "SIG-SLOWLORIS", "name": "Slowloris Partial Header", "severity": "high",
     "mitre": "T1499.001", "pattern": r"\r\nX-a:\s*\d+$", "weight": 24},
    {"rule_id": "SIG-DNSTUNNEL", "name": "DNS Tunneling (long label)", "severity": "high",
     "mitre": "T1071.004", "pattern": r"DNS query [A-Z2-7]{20,}\.|tunnel\.", "weight": 24},
]

# ---------------------------------------------------------------------------
# Rule registry (includes threshold + stateful detectors defined below).
# ``check`` receives (packets, ctx, cfg). Signature rules are expanded into
# individual entries at module load.
# ---------------------------------------------------------------------------
RULE_REGISTRY: List[Dict[str, Any]] = []


def _register(rule: Dict[str, Any]) -> None:
    RULE_REGISTRY.append(rule)


for sig in _SIGNATURES:
    _register({
        "rule_id": sig["rule_id"], "name": sig["name"], "layer": "signature",
        "severity": sig["severity"], "mitre": sig.get("mitre"),
        "description": f"Signature match: {sig['name']}", "enabled": True,
        "tunable": False, "threshold": None, "_pattern": sig["pattern"], "_weight": sig["weight"],
    })


# ---- Threshold rules -------------------------------------------------------
_register({"rule_id": "THR-CONN-RATE", "name": "Excessive Connection Rate", "layer": "threshold",
           "severity": "high", "mitre": "T1498.001", "description": "Connection rate from a source exceeds limit",
           "enabled": True, "tunable": True, "threshold": {"connections_per_min": 100}})
_register({"rule_id": "THR-PORT-SCAN", "name": "Port Scan Fan-out", "layer": "threshold",
           "severity": "medium", "mitre": "T1046", "description": "Too many distinct ports in a time window",
           "enabled": True, "tunable": True, "threshold": {"distinct_ports": 12, "window_seconds": 15}})
_register({"rule_id": "THR-AUTH-FAIL", "name": "Failed Authentication Burst", "layer": "threshold",
           "severity": "high", "mitre": "T1110", "description": "Repeated failed authentication attempts",
           "enabled": True, "tunable": True, "threshold": {"failed_attempts": 5}})
_register({"rule_id": "THR-BANDWIDTH", "name": "Bandwidth Anomaly", "layer": "threshold",
           "severity": "medium", "mitre": "T1498", "description": "Aggregate throughput deviates from baseline",
           "enabled": True, "tunable": True, "threshold": {"bytes_per_sec": 200000}})

# ---- Stateful rules --------------------------------------------------------
_register({"rule_id": "ST-INC-HANDSHAKE", "name": "Incomplete TCP Handshake", "layer": "stateful",
           "severity": "medium", "mitre": "T1498.001", "description": "SYN packets without completing handshake",
           "enabled": True, "tunable": False, "threshold": None})
_register({"rule_id": "ST-FLAG-ANOMALY", "name": "Illegal TCP Flag Combination", "layer": "stateful",
           "severity": "medium", "mitre": "T1046", "description": "NULL/FIN/XMAS flag patterns typical of scans",
           "enabled": True, "tunable": False, "threshold": None})
_register({"rule_id": "ST-OUT-OF-SEQ", "name": "Out-of-Sequence / Fragmented Flow", "layer": "stateful",
           "severity": "low", "mitre": "T1027.003", "description": "Fragmented / non-monotonic flow order",
           "enabled": True, "tunable": False, "threshold": None})
_register({"rule_id": "ST-LATERAL", "name": "Lateral Movement Pattern", "layer": "stateful",
           "severity": "high", "mitre": "T1021", "description": "Single source reaching multiple internal targets",
           "enabled": True, "tunable": True, "threshold": {"distinct_dst_ports_service": 4}})
_register({"rule_id": "ST-BEACON", "name": "C2 Beacon Periodicity", "layer": "stateful",
           "severity": "high", "mitre": "T1071.001", "description": "Machine-regular low-jitter outbound cadence",
           "enabled": True, "tunable": True, "threshold": {"min_interval_seconds": 3.0, "max_cv": 0.12}})


def _window_stats(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Shared metrics computed once per run."""
    n = len(packets)
    if n == 0:
        return {"count": 0}
    ts = [p["unix_ts"] for p in packets]
    ts_gap = sorted(ts)
    span = max(ts) - min(ts) if n > 1 else 1.0
    total_bytes = sum(p["size"] for p in packets)
    per_src_ports: Dict[str, set] = defaultdict(set)
    per_src_conns: Counter = Counter()
    for p in packets:
        per_src_ports[p["src_ip"]].add(p["dst_port"])
        per_src_conns[p["src_ip"]] += 1
    duration_min = max(span / 60.0, 1 / 60.0)
    ia_mean = span / (n - 1) if n > 1 else span
    # Coefficient of variation of inter-arrival (approx via per-src uniform timing)
    gaps = [ts_gap[i + 1] - ts_gap[i] for i in range(len(ts_gap) - 1)] if n > 2 else [ia_mean]
    gaps = [g for g in gaps if g >= 0]
    if gaps:
        g_mean = sum(gaps) / len(gaps)
        g_std = math.sqrt(sum((g - g_mean) ** 2 for g in gaps) / len(gaps))
        ia_cv = g_std / g_mean if g_mean > 0 else 1.0
    else:
        g_mean, ia_cv = ia_mean, 1.0
    return {
        "count": n,
        "span_seconds": span,
        "total_bytes": total_bytes,
        "bytes_per_sec": total_bytes / max(span, 0.001),
        "inter_arrival_mean": g_mean,
        "inter_arrival_cv": ia_cv,
        "per_src_ports": per_src_ports,
        "per_src_conns": per_src_conns,
        "max_ports_per_src": max((len(v) for v in per_src_ports.values()), default=0),
        "max_conns_per_min": max((c / duration_min for c in per_src_conns.values()), default=0),
        "failed_auth": sum(1 for p in packets if "status=401" in p.get("payload_text", "")),
    }


def run_rules(
    packets: List[Dict[str, Any]],
    overrides: Dict[str, Any] = None,
    enabled: Dict[str, bool] = None,
) -> Dict[str, Any]:
    """Evaluate the rule registry against packets.

    Args:
        packets: generated packet stream.
        overrides: {rule_id: {"enabled": bool, "threshold": {...}}} from the UI.
        enabled: quick {rule_id: bool} map (merged after overrides).

    Returns:
        {triggered: [detection...], evaluated: [...], rule_score: float}
    """
    overrides = overrides or {}
    enabled = enabled or {}
    stats = _window_stats(packets)
    triggered: List[Dict[str, Any]] = []
    evaluated_ids: List[str] = []

    def _is_on(rule: Dict[str, Any]) -> bool:
        ov = overrides.get(rule["rule_id"], {})
        if rule["rule_id"] in enabled:
            return bool(enabled[rule["rule_id"]])
        if "enabled" in ov:
            return bool(ov["enabled"])
        return rule["enabled"]

    def _thr(rule: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(rule.get("threshold") or {})
        merged.update((overrides.get(rule["rule_id"], {}) or {}).get("threshold", {}))
        return merged

    # ---- Signature layer ----
    for rule in RULE_REGISTRY:
        if rule["layer"] != "signature" or not _is_on(rule):
            continue
        evaluated_ids.append(rule["rule_id"])
        pat = re.compile(rule["_pattern"], re.IGNORECASE)
        hits = [p["index"] for p in packets if pat.search(p.get("payload_text", ""))]
        if hits:
            triggered.append(_make_hit(rule, f"{len(hits)} packet(s) matched signature",
                                        rule["_weight"] / 34.0, hits[:50]))

    if stats.get("count", 0) == 0:
        return {"triggered": [], "evaluated": evaluated_ids, "rule_score": 0.0}

    # ---- Threshold: connection rate ----
    r = _by_id("THR-CONN-RATE")
    if _is_on(r):
        evaluated_ids.append(r["rule_id"])
        limit = _thr(r).get("connections_per_min", 100)
        # 1.3x headroom so a short benign sample can't spuriously cross the bar.
        if stats["count"] >= 8 and stats["max_conns_per_min"] >= limit * 1.3:
            triggered.append(_make_hit(r, f"{stats['max_conns_per_min']:.0f} conn/min from single source (limit {limit})",
                                        min(1.0, stats["max_conns_per_min"] / (limit * 2)), []))

    # ---- Threshold: port scan fan-out ----
    r = _by_id("THR-PORT-SCAN")
    if _is_on(r):
        evaluated_ids.append(r["rule_id"])
        t = _thr(r)
        if stats["max_ports_per_src"] >= t.get("distinct_ports", 12):
            triggered.append(_make_hit(r, f"{stats['max_ports_per_src']} distinct ports from one source",
                                        min(1.0, stats["max_ports_per_src"] / 20.0), []))

    # ---- Threshold: failed auth burst ----
    r = _by_id("THR-AUTH-FAIL")
    if _is_on(r):
        evaluated_ids.append(r["rule_id"])
        if stats["failed_auth"] >= _thr(r).get("failed_attempts", 5):
            triggered.append(_make_hit(r, f"{stats['failed_auth']} failed authentication attempts",
                                        min(1.0, stats["failed_auth"] / 10.0), []))

    # ---- Threshold: bandwidth ----
    r = _by_id("THR-BANDWIDTH")
    if _is_on(r):
        evaluated_ids.append(r["rule_id"])
        if stats["bytes_per_sec"] >= _thr(r).get("bytes_per_sec", 200000):
            triggered.append(_make_hit(r, f"{stats['bytes_per_sec']:.0f} B/s throughput anomaly",
                                        min(1.0, stats["bytes_per_sec"] / 500000.0), []))

    # ---- Stateful: incomplete handshake ----
    r = _by_id("ST-INC-HANDSHAKE")
    if _is_on(r):
        evaluated_ids.append(r["rule_id"])
        syn = sum(1 for p in packets if p["flags"] == "SYN")
        synack = sum(1 for p in packets if "SYN-ACK" in p["flags"])
        if syn >= 5 and synack == 0:
            triggered.append(_make_hit(r, f"{syn} SYN with no SYN-ACK completion", min(1.0, syn / 20.0), []))

    # ---- Stateful: illegal flag combo ----
    r = _by_id("ST-FLAG-ANOMALY")
    if _is_on(r):
        evaluated_ids.append(r["rule_id"])
        bad = [p["index"] for p in packets if p["flags"] in ("NONE", "FIN", "FIN,PSH,URG") or "URG" in p["flags"]]
        if len(bad) >= 3:
            triggered.append(_make_hit(r, f"{len(bad)} packets with scan-typical flag patterns", 0.6, bad[:50]))

    # ---- Stateful: out-of-sequence / fragmentation ----
    r = _by_id("ST-OUT-OF-SEQ")
    if _is_on(r):
        evaluated_ids.append(r["rule_id"])
        frag = sum(1 for p in packets if "fragment" in p.get("payload_text", "").lower())
        if frag >= 2:
            triggered.append(_make_hit(r, f"{frag} fragmented / re-ordered packets", min(1.0, frag / 6.0), []))

    # ---- Stateful: lateral movement (multi-service reach) ----
    r = _by_id("ST-LATERAL")
    if _is_on(r):
        evaluated_ids.append(r["rule_id"])
        if stats["max_ports_per_src"] >= _thr(r).get("distinct_dst_ports_service", 4) and \
           stats["count"] >= 6 and r["rule_id"] not in {t["rule_id"] for t in triggered}:
            # Only fire when it looks like service sweeping, not volumetric flood
            if stats["bytes_per_sec"] < _by_id("THR-BANDWIDTH")["threshold"]["bytes_per_sec"]:
                triggered.append(_make_hit(r, "single source reaching multiple distinct services", 0.55, []))

    # ---- Stateful: C2 beacon periodicity ----
    r = _by_id("ST-BEACON")
    if _is_on(r):
        evaluated_ids.append(r["rule_id"])
        t = _thr(r)
        if (stats["count"] >= 6
                and stats.get("inter_arrival_mean", 0) >= t.get("min_interval_seconds", 3.0)
                and stats.get("inter_arrival_cv", 1.0) <= t.get("max_cv", 0.12)):
            triggered.append(_make_hit(
                r,
                f"Beacon-like cadence every {stats['inter_arrival_mean']:.1f}s (jitter CV {stats['inter_arrival_cv']:.3f})",
                0.7, []))

    rule_score = _fuse_score(triggered)
    return {"triggered": triggered, "evaluated": evaluated_ids, "rule_score": rule_score}


def _by_id(rule_id: str) -> Dict[str, Any]:
    for r in RULE_REGISTRY:
        if r["rule_id"] == rule_id:
            return r
    raise KeyError(rule_id)


def _make_hit(rule: Dict[str, Any], detail: str, confidence: float, packet_indices: List[int]) -> Dict[str, Any]:
    return {
        "rule_id": rule["rule_id"],
        "name": rule["name"],
        "layer": rule["layer"],
        "severity": rule["severity"],
        "mitre": rule.get("mitre"),
        "confidence": round(max(0.0, min(1.0, confidence)), 3),
        "detail": detail,
        "matched_packets": packet_indices,
        "weight": SEVERITY_WEIGHT.get(rule["severity"], 10),
    }


def _fuse_score(triggered: List[Dict[str, Any]]) -> float:
    """Combine rule hits into a 0..1 rule score (soft, saturating)."""
    if not triggered:
        return 0.0
    total = 0.0
    for t in triggered:
        total += SEVERITY_WEIGHT.get(t["severity"], 10) * (0.5 + 0.5 * t["confidence"])
    # Sigmoid-ish saturation, ~120 weighted points => near-certain
    return round(1.0 - math.exp(-total / 42.0), 4)
