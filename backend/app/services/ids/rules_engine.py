"""Multi-layer IDS rules engine: signature, threshold and stateful detection.

Research-aligned contract (Section C of the reconstruction directive)
----------------------------------------------------------------------
The registry is the single source of truth for the advertised rule count.
It is built from three declarative tables and expanded at import time, so the
number reported by the UI/API (``GET /api/ids/rules/summary``) is *derived from
the implemented rules*, never hardcoded:

  * 15 signature rules  (pattern matching against packet payloads)
  *  4 threshold rules  (rate / fan-out / volume limits)
  *  5 stateful rules   (flow correlation across the packet stream)
  = 24 rules total

Every rule entry carries the full contract the directive asks for:
``rule_id`` (stable), ``name``, ``category``/``layer``, ``version``,
``inputs`` (required packet fields), ``matching`` (the matching logic in words),
``severity``, ``weight``, ``threshold`` (explicit, overridable tunables),
``description``/``explanation`` and a ``mitre`` ATT&CK reference where the
documented behaviour maps to one. ``_register`` raises at import time if any
entry is missing a contract field, so a rule cannot be silently half-implemented.

Input scope / non-claim
----------------------------------------------------------------------
Rules operate on packets produced by the seeded synthetic generator or replayed
from stored telemetry. **No live-interface capture is performed and no
authorized real-time ingestion path exists or is tested here**, so this module
must not be described as real-time traffic monitoring. Malformed packets are
validated and skipped (reported in ``skipped``) rather than crashing detection.

Public surface
  * ``RULE_REGISTRY`` / ``registry_summary()`` / ``rule_spec(rule_id)``
  * ``run_rules(packets, overrides, enabled)`` -> detections + fused rule score
  * ``SEVERITY_RANK`` / ``SEVERITY_WEIGHT`` for verdict fusion
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

# Version of the whole ruleset (individual rules also carry their own version).
RULESET_VERSION = "1.0.0"

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_WEIGHT = {"info": 2, "low": 6, "medium": 14, "high": 24, "critical": 34}

LAYER_ORDER = ("signature", "threshold", "stateful")

# Every accepted packet must expose these fields with these types. Anything else
# is skipped deterministically and reported, instead of raising mid-detection.
PACKET_REQUIRED_FIELDS: Dict[str, Tuple[type, ...]] = {
    "index": (int,),
    "unix_ts": (int, float),
    "size": (int, float),
    "src_ip": str,
    "dst_ip": str,
    "dst_port": (int,),
    "protocol": str,
    "flags": str,
    "ttl": (int,),
    "payload_text": str,
}

# Fields a rule needs beyond the common packet schema (documented per rule).
_BASE_INPUTS = ("index", "unix_ts")
_ADDRESSING_INPUTS = _BASE_INPUTS + ("src_ip", "dst_ip", "dst_port", "protocol", "size", "ttl", "flags")

_EVIDENCE_LIMIT = 50          # max packet indices attached to a detection
_EVIDENCE_DETAIL_LIMIT = 5    # max fully-rendered evidence records per detection

# ---------------------------------------------------------------------------
# Signature catalog (regex, severity, MITRE hint, weight, explanation).
# Patterns are documentation-grade and match the synthetic payloads only.
# ---------------------------------------------------------------------------
_SIGNATURES: List[Dict[str, Any]] = [
    {"rule_id": "SIG-SQLI-UNION", "name": "SQL Injection (UNION SELECT)", "severity": "high",
     "mitre": "T1190", "pattern": r"union\s+select|UNION%20SELECT|%27%20UNION", "weight": 30,
     "explanation": "Packet payload contains a UNION SELECT injection sequence (plain or URL-encoded)."},
    {"rule_id": "SIG-SQLI-BLIND", "name": "SQL Injection (Boolean blind)", "severity": "high",
     "mitre": "T1190", "pattern": r"(?i)(?:and|or)(?:%20|\+|\s)\s*\d\s*=\s*\d|'?\s*or\s*'?\d'?\s*=\s*'?\d|--\s*$|%27%20or", "weight": 26,
     "explanation": "Payload carries a boolean-algebra injection marker (AND/OR <n>=<n> or a SQL comment terminator)."},
    {"rule_id": "SIG-SQLI-TIME", "name": "SQL Injection (Time-based)", "severity": "high",
     "mitre": "T1190", "pattern": r"(?i)waitfor(?:%20|\s)delay|sleep\(|benchmark\(|pg_sleep", "weight": 26,
     "explanation": "Payload invokes a time-delay primitive (WAITFOR DELAY / SLEEP / BENCHMARK / PG_SLEEP)."},
    {"rule_id": "SIG-CMDINJ", "name": "OS Command Injection", "severity": "critical",
     "mitre": "T1190", "pattern": r";\s*(?:cat|rm|bash|nc)\b|\|\s*/bin/|`[^`]+`|\$\(.*\)", "weight": 34,
     "explanation": "Payload chains a shell command using metacharacters (;, |, backticks, $())."},
    {"rule_id": "SIG-XSS", "name": "Cross-Site Scripting", "severity": "medium",
     "mitre": "T1059.007", "pattern": r"<script|onerror=|javascript:|alert\(|document\.cookie", "weight": 22,
     "explanation": "Payload embeds an executable script marker (script tag, event handler, javascript: URI)."},
    {"rule_id": "SIG-XXE", "name": "XML External Entity", "severity": "high",
     "mitre": "T1190", "pattern": r"<!ENTITY|<!DOCTYPE|SYSTEM\s+\"file:", "weight": 26,
     "explanation": "XML document declares an external entity / DOCTYPE pointing at a local resource."},
    {"rule_id": "SIG-LDAP", "name": "LDAP Injection Filter", "severity": "high",
     "mitre": "T1190", "pattern": r"\)\(\*\)|\(\|\(uid=|\)\(\|\(", "weight": 24,
     "explanation": "Query string contains LDAP filter syntax used to bypass an authentication filter."},
    {"rule_id": "SIG-REVSHELL", "name": "Reverse Shell Indicator", "severity": "critical",
     "mitre": "T1059", "pattern": r"/dev/tcp/|nc\s+-e|bash\s+-i|subprocess", "weight": 34,
     "explanation": "Payload contains a reverse-shell primitive (/dev/tcp, nc -e, interactive bash, subprocess)."},
    {"rule_id": "SIG-WEBSHELL", "name": "Webshell Upload Indicator", "severity": "critical",
     "mitre": "T1100", "pattern": r"<\?php\s+system|shell\.php|filename=\"[^\"]+\.php", "weight": 34,
     "explanation": "Upload/multipart content presents an executable server-side script."},
    {"rule_id": "SIG-ENCODED", "name": "Encoded Command Wrapper", "severity": "high",
     "mitre": "T1027", "pattern": r"base64_decode|atob\(|eval\(", "weight": 24,
     "explanation": "Payload decodes and evaluates an encoded blob, a common defence-evasion wrapper."},
    {"rule_id": "SIG-SESSIONHIJACK", "name": "Session Cookie Anomaly", "severity": "medium",
     "mitre": "T1563.001", "pattern": r"Cookie:\s*sessionid=", "weight": 16,
     "explanation": "Request replays a raw session identifier cookie, consistent with token reuse/hijack."},
    {"rule_id": "SIG-TOKENREPLAY", "name": "Bearer Token Replay", "severity": "medium",
     "mitre": "T1550.004", "pattern": r"Authorization:\s*Bearer\s+eyJ", "weight": 16,
     "explanation": "Authorization header carries a JWT-shaped bearer token captured from another flow."},
    {"rule_id": "SIG-MITM", "name": "MITM / Intercepted TLS", "severity": "critical",
     "mitre": "T1557", "pattern": r"issuer=EVIL|\(relayed\)|CN=\*\.", "weight": 34,
     "explanation": "TLS record indicates a relayed/roguously issued certificate (interception)."},
    {"rule_id": "SIG-SLOWLORIS", "name": "Slowloris Partial Header", "severity": "high",
     "mitre": "T1499.001", "pattern": r"\r\nX-a:\s*\d+$", "weight": 24,
     "explanation": "HTTP request ends inside a fabricated header without terminating the request line."},
    {"rule_id": "SIG-DNSTUNNEL", "name": "DNS Tunneling (long label)", "severity": "high",
     "mitre": "T1071.004", "pattern": r"DNS query [A-Z2-7]{20,}\.|tunnel\.", "weight": 24,
     "explanation": "DNS query name contains an over-long base32-ish label, typical of tunneling."},
]

# ---------------------------------------------------------------------------
# Threshold rules: explicit, overridable tunables and windowed statistics.
# ---------------------------------------------------------------------------
_THRESHOLD_RULES: List[Dict[str, Any]] = [
    {"rule_id": "THR-CONN-RATE", "name": "Excessive Connection Rate", "severity": "high",
     "mitre": "T1498.001", "weight": 24,
     "description": "Connection rate from a single source exceeds the configured limit.",
     "threshold": {"connections_per_min": 100, "window_seconds": 60, "min_packets": 8, "headroom": 1.3},
     "matching": ("Per source, take the peak number of packets inside a sliding "
                  "window of `window_seconds`, expressed per minute; fire when the rate "
                  "reaches `connections_per_min * headroom` and the stream holds at "
                  "least `min_packets` packets."),
     "inputs": _ADDRESSING_INPUTS,
     "explanation": "One source produced {detail}."},
    {"rule_id": "THR-PORT-SCAN", "name": "Port Scan Fan-out", "severity": "medium",
     "mitre": "T1046", "weight": 14,
     "description": "Too many distinct destination ports from one source inside the time window.",
     "threshold": {"distinct_ports": 12, "window_seconds": 15},
     "matching": ("For each source, slide a window of `window_seconds` over its "
                  "time-ordered packets and count distinct destination ports; fire when "
                  "the peak reaches `distinct_ports`."),
     "inputs": _ADDRESSING_INPUTS,
     "explanation": "A single source touched {detail}."},
    {"rule_id": "THR-AUTH-FAIL", "name": "Failed Authentication Burst", "severity": "high",
     "mitre": "T1110", "weight": 24,
     "description": "Repeated failed authentication attempts against an endpoint.",
     "threshold": {"failed_attempts": 5, "window_seconds": 0},
     "matching": ("Count payloads carrying an authentication-failure marker "
                  "(HTTP 401 / FTP 530 login incorrect); `window_seconds` = 0 evaluates "
                  "the whole stream, otherwise a sliding per-source window; fire when "
                  "the count reaches `failed_attempts`."),
     "inputs": _ADDRESSING_INPUTS + ("payload_text",),
     "explanation": "{detail}."},
    {"rule_id": "THR-BANDWIDTH", "name": "Bandwidth Anomaly", "severity": "medium",
     "mitre": "T1498", "weight": 14,
     "description": "Aggregate throughput deviates from the benign baseline.",
     "threshold": {"bytes_per_sec": 200000, "window_seconds": 10},
     "matching": ("Sum packet bytes over a sliding `window_seconds` window and convert "
                  "to bytes/second; fire when the peak reaches `bytes_per_sec`."),
     "inputs": _ADDRESSING_INPUTS,
     "explanation": "{detail}."},
]

# ---------------------------------------------------------------------------
# Stateful rules: flow correlation across the stream.
# ---------------------------------------------------------------------------
_STATEFUL_RULES: List[Dict[str, Any]] = [
    {"rule_id": "ST-INC-HANDSHAKE", "name": "Incomplete TCP Handshake", "severity": "medium",
     "mitre": "T1498.001", "weight": 14,
     "description": "SYN packets that never receive a SYN-ACK completion.",
     "threshold": {"min_syn_without_response": 5},
     "matching": ("Group SYN packets per source and drop those for which any SYN-ACK was "
                  "observed on the same destination port; fire when `min_syn_without_response` "
                  "half-open SYNs remain."),
     "inputs": _ADDRESSING_INPUTS,
     "explanation": "{detail}."},
    {"rule_id": "ST-FLAG-ANOMALY", "name": "Illegal TCP Flag Combination", "severity": "medium",
     "mitre": "T1046", "weight": 14,
     "description": "NULL / SYN-FIN / XMAS / bare-FIN flag patterns typical of stealth scans.",
     "threshold": {"min_anomalous_flag_packets": 3},
     "matching": ("Normalise the flag string to a set and flag empty (NULL), SYN+FIN, "
                  "any set containing URG with FIN/PSH (XMAS) and bare FIN probes; fire "
                  "when `min_anomalous_flag_packets` packets match."),
     "inputs": _BASE_INPUTS + ("flags",),
     "explanation": "{detail}."},
    {"rule_id": "ST-OUT-OF-SEQ", "name": "Out-of-Sequence / Fragmented Flow", "severity": "low",
     "mitre": "T1027.003", "weight": 6,
     "description": "Fragmented payloads and non-monotonic flow ordering.",
     "threshold": {"min_out_of_sequence_packets": 2},
     "matching": ("Count packets whose timestamp decreases relative to the previous "
                  "packet in sequence order, plus packets carrying an IP-fragment marker; "
                  "fire when the total reaches `min_out_of_sequence_packets`."),
     "inputs": _BASE_INPUTS + ("payload_text",),
     "explanation": "{detail}."},
    {"rule_id": "ST-LATERAL", "name": "Lateral Movement Pattern", "severity": "high",
     "mitre": "T1021", "weight": 24,
     "description": "Single source sweeping multiple distinct services without volumetric flood.",
     "threshold": {"distinct_dst_ports_service": 4, "min_packets": 6},
     "matching": ("Per source, count distinct destination ports; fire when the count "
                  "reaches `distinct_dst_ports_service` on at least `min_packets` packets, "
                  "and the observed throughput stays below the effective THR-BANDWIDTH "
                  "limit (so this reports service sweeping rather than a volumetric "
                  "flood). NOTE: the seeded generator emits a single destination host per "
                  "stream, so distinct *services* are used as the lateral-movement proxy "
                  "rather than distinct hosts."),
     "inputs": _ADDRESSING_INPUTS,
     "explanation": "{detail}."},
    {"rule_id": "ST-BEACON", "name": "C2 Beacon Periodicity", "severity": "high",
     "mitre": "T1071.001", "weight": 24,
     "description": "Machine-regular, low-jitter outbound cadence.",
     "threshold": {"min_interval_seconds": 3.0, "max_cv": 0.12, "min_samples": 6},
     "matching": ("For the aggregate stream and each (src, dst, dst_port) flow with at "
                  "least `min_samples` packets, compute the mean inter-arrival time and "
                  "its coefficient of variation; fire when the mean is at least "
                  "`min_interval_seconds` and the CV is at most `max_cv`."),
     "inputs": _ADDRESSING_INPUTS,
     "explanation": "{detail}."},
]

# ---------------------------------------------------------------------------
# Registry construction.
# ---------------------------------------------------------------------------
RULE_REGISTRY: List[Dict[str, Any]] = []

_REQUIRED_CONTRACT = ("rule_id", "name", "category", "version", "inputs",
                      "matching", "severity", "weight", "description",
                      "explanation", "mitre", "enabled", "tunable", "threshold")

# ``mitre`` may legitimately be None (no documented ATT&CK mapping) and
# ``threshold`` is validated separately against ``tunable``.
_NULLABLE_CONTRACT = {"mitre"}


def _register(rule: Dict[str, Any]) -> None:
    """Append one rule after asserting it satisfies the full contract."""
    missing = [k for k in _REQUIRED_CONTRACT if k not in rule]
    if missing:
        raise RuntimeError(
            f"Rule {rule.get('rule_id', '<unknown>')} is missing contract fields: {missing}"
        )
    bad = [k for k in _REQUIRED_CONTRACT
           if k not in _NULLABLE_CONTRACT and k != "threshold" and rule[k] in (None, "", ())]
    if bad:
        raise RuntimeError(
            f"Rule {rule['rule_id']} has empty required contract fields: {bad}"
        )
    if rule["tunable"]:
        if not isinstance(rule["threshold"], dict) or not rule["threshold"]:
            raise RuntimeError(f"Rule {rule['rule_id']} is tunable but declares no threshold config")
        non_numeric = [k for k, v in rule["threshold"].items() if not isinstance(v, (int, float))]
        if non_numeric:
            raise RuntimeError(f"Rule {rule['rule_id']} has non-numeric tunables: {non_numeric}")
    elif rule["threshold"] is not None:
        raise RuntimeError(f"Rule {rule['rule_id']} is not tunable but declares a threshold")
    if rule["severity"] not in SEVERITY_RANK:
        raise RuntimeError(f"Rule {rule['rule_id']} declares unknown severity {rule['severity']!r}")
    if rule["category"] != rule["layer"]:
        raise RuntimeError(f"Rule {rule['rule_id']} category/layer mismatch")
    if not isinstance(rule["weight"], (int, float)) or rule["weight"] <= 0:
        raise RuntimeError(f"Rule {rule['rule_id']} has a non-positive weight")
    if not rule["inputs"]:
        raise RuntimeError(f"Rule {rule['rule_id']} declares no input requirements")
    RULE_REGISTRY.append(rule)


def _signature_entry(sig: Dict[str, Any], version: str) -> Dict[str, Any]:
    return {
        "rule_id": sig["rule_id"], "name": sig["name"],
        "layer": "signature", "category": "signature", "version": version,
        "severity": sig["severity"], "weight": sig["weight"], "mitre": sig.get("mitre"),
        "description": f"Signature match: {sig['name']}",
        "matching": f"Case-insensitive regular expression `{sig['pattern']}` against packet payload_text.",
        "inputs": _BASE_INPUTS + ("payload_text",),
        "explanation": sig["explanation"],
        "enabled": True, "tunable": False, "threshold": None,
        "_pattern": sig["pattern"],
    }


for _sig in _SIGNATURES:
    _register(_signature_entry(_sig, "1.0.0"))

for _thr in _THRESHOLD_RULES:
    _register({
        "rule_id": _thr["rule_id"], "name": _thr["name"],
        "layer": "threshold", "category": "threshold", "version": _thr.get("version", "1.0.0"),
        "severity": _thr["severity"], "weight": _thr["weight"], "mitre": _thr.get("mitre"),
        "description": _thr["description"], "matching": _thr["matching"],
        "inputs": tuple(_thr["inputs"]), "explanation": _thr["explanation"],
        "enabled": True, "tunable": True, "threshold": dict(_thr["threshold"]),
    })

for _st in _STATEFUL_RULES:
    _register({
        "rule_id": _st["rule_id"], "name": _st["name"],
        "layer": "stateful", "category": "stateful", "version": _st.get("version", "1.0.0"),
        "severity": _st["severity"], "weight": _st["weight"], "mitre": _st.get("mitre"),
        "description": _st["description"], "matching": _st["matching"],
        "inputs": tuple(_st["inputs"]), "explanation": _st["explanation"],
        "enabled": True, "tunable": True, "threshold": dict(_st["threshold"]),
    })


def rule_spec(rule_id: str) -> Dict[str, Any]:
    """Return the registry entry for ``rule_id`` (KeyError when unknown)."""
    for r in RULE_REGISTRY:
        if r["rule_id"] == rule_id:
            return r
    raise KeyError(rule_id)


def _by_id(rule_id: str) -> Dict[str, Any]:  # kept for internal use / compatibility
    return rule_spec(rule_id)


def registry_summary() -> Dict[str, Any]:
    """Counts derived from the implemented registry - the honest source for the UI."""
    per_layer = Counter(r["layer"] for r in RULE_REGISTRY)
    return {
        "ruleset_version": RULESET_VERSION,
        "total": len(RULE_REGISTRY),
        "layers": {layer: per_layer.get(layer, 0) for layer in LAYER_ORDER},
        "enabled": sum(1 for r in RULE_REGISTRY if r["enabled"]),
        "tunable": sum(1 for r in RULE_REGISTRY if r["tunable"]),
        "with_mitre_mapping": sum(1 for r in RULE_REGISTRY if r.get("mitre")),
        "severities": {s: sum(1 for r in RULE_REGISTRY if r["severity"] == s) for s in SEVERITY_RANK},
        "input_scope": ("Seed-generated or replayed synthetic packets. No authorized live "
                        "capture is wired or tested, so no real-time monitoring is claimed."),
    }


# ---------------------------------------------------------------------------
# Packet validation
# ---------------------------------------------------------------------------
def _packet_problem(packet: Any) -> Optional[str]:
    """Return a stable reason string when a packet cannot be evaluated."""
    if not isinstance(packet, dict):
        return "not-a-dict"
    for field, expected in PACKET_REQUIRED_FIELDS.items():
        if field not in packet:
            return f"missing:{field}"
        value = packet[field]
        if expected == (int,) and (isinstance(value, bool) or not isinstance(value, int)):
            return f"type:{field}"
        if not isinstance(value, expected):
            return f"type:{field}"
    ts = packet["unix_ts"]
    if isinstance(ts, float) and (math.isnan(ts) or math.isinf(ts)):
        return "non-finite:unix_ts"
    if packet["size"] < 0:
        return "negative:size"
    if packet["dst_port"] < 0 or packet["dst_port"] > 65535:
        return "out-of-range:dst_port"
    return None


def _validate_packets(packets: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split input into (usable, skipped). Order preserving and fully deterministic."""
    if packets is None:
        return [], []
    accepted: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for position, packet in enumerate(packets):
        problem = _packet_problem(packet)
        if problem is None:
            accepted.append(packet)
        else:
            skipped.append({
                "position": position,
                "index": packet.get("index") if isinstance(packet, dict) else None,
                "reason": problem,
            })
    return accepted, skipped


# ---------------------------------------------------------------------------
# Shared stream statistics (computed once per run)
# ---------------------------------------------------------------------------
def _window_max_distinct(seq: List[Dict[str, Any]], key: str, window: float) -> Tuple[int, List[int], int, int]:
    """Peak distinct ``key`` values inside any sliding ``window``-second span.

    Returns (peak, indices_in_best_window, first_ts_rank, last_ts_rank). A window
    of ``0`` (or a stream shorter than the window) collapses to the whole stream,
    which keeps the historical whole-stream semantics for short captures.
    """
    n = len(seq)
    if n == 0:
        return 0, [], 0, 0
    if window <= 0:
        values = {p[key] for p in seq}
        return len(values), [p["index"] for p in seq], seq[0]["unix_ts"], seq[-1]["unix_ts"]
    counts: Counter = Counter()
    left = 0
    best, best_left, best_right = 0, 0, -1
    for right in range(n):
        counts[seq[right][key]] += 1
        while seq[right]["unix_ts"] - seq[left]["unix_ts"] > window:
            counts[seq[left][key]] -= 1
            if counts[seq[left][key]] == 0:
                del counts[seq[left][key]]
            left += 1
        if len(counts) > best:
            best, best_left, best_right = len(counts), left, right
    span_start = seq[best_left]["unix_ts"]
    span_end = seq[best_right]["unix_ts"]
    return best, [p["index"] for p in seq[best_left:best_right + 1]], span_start, span_end


def _window_peak_count(seq: List[Dict[str, Any]], window: float) -> Tuple[int, List[int]]:
    """Largest number of packets that fall inside one sliding ``window``-second span."""
    n = len(seq)
    if n == 0:
        return 0, []
    if window <= 0:
        return n, [p["index"] for p in seq]
    left = 0
    best, best_left, best_right = 0, 0, 0
    for right in range(n):
        while seq[right]["unix_ts"] - seq[left]["unix_ts"] > window:
            left += 1
        if right - left + 1 > best:
            best, best_left, best_right = right - left + 1, left, right
    return best, [p["index"] for p in seq[best_left:best_right + 1]]


def _window_max_count(seq: List[Dict[str, Any]], window: float, stream_span: float) -> Tuple[float, List[int]]:
    """Peak arrival rate per minute inside a sliding ``window``-second span.

    The denominator is ``min(window, stream_span)``, so a capture shorter than the
    window is scaled by its own span (the historical whole-stream estimator) and a
    longer capture reports the true burst rate rather than the average.
    """
    n = len(seq)
    if n == 0:
        return 0.0, []
    if window <= 0:
        return n * 60.0 / max(stream_span, 1.0), [p["index"] for p in seq]
    count, idx = _window_peak_count(seq, window)
    # Denominator floored at 1 second, matching the historical estimator, so a
    # sub-second burst cannot be scaled into an absurd per-minute rate.
    used = max(min(window, max(stream_span, 1e-3)), 1.0)
    return count * 60.0 / used, idx


def _window_peak_bytes_per_sec(seq: List[Dict[str, Any]], window: float,
                               stream_span: float) -> Tuple[float, List[int]]:
    """Peak throughput (bytes/s) over a sliding ``window``-second span.

    Two candidates are compared: the whole-stream average (the historical
    estimator, and the only valid one when the capture is shorter than the
    window) and the peak over *settled* windows - windows that actually span at
    least half the requested width, because dividing a few bytes by a
    near-zero elapsed time would invent a huge rate.
    """
    n = len(seq)
    if n == 0:
        return 0.0, []
    total = sum(p["size"] for p in seq)
    best = total / max(stream_span, 0.001)
    best_idx = [p["index"] for p in seq]
    if window <= 0 or stream_span <= window:
        return best, best_idx
    left = 0
    acc = 0
    for right in range(n):
        acc += seq[right]["size"]
        while seq[right]["unix_ts"] - seq[left]["unix_ts"] > window:
            acc -= seq[left]["size"]
            left += 1
        elapsed = seq[right]["unix_ts"] - seq[left]["unix_ts"]
        if elapsed < 0.5 * window:
            continue
        rate = acc / elapsed
        if rate > best:
            best = rate
            best_idx = [p["index"] for p in seq[left:right + 1]]
    return best, best_idx


# The generator marks a failed authentication attempt with ``status=401`` in the
# request payload. Declared as data so the marker is explicit and configurable.
# Service banners such as "530 Login incorrect." are server flavour, not a
# per-attempt auth event, and are deliberately not counted here.
AUTH_FAILURE_MARKERS = ("status=401",)


def _is_auth_failure(packet: Dict[str, Any]) -> bool:
    text = packet["payload_text"].lower()
    return any(marker in text for marker in AUTH_FAILURE_MARKERS)


def _normalise_flags(raw: str) -> Tuple[str, ...]:
    parts = re.split(r"[,/+ \t]+|->|-", raw.strip().upper()) if raw.strip() else []
    return tuple(sorted({p for p in parts if p and p != "NONE"}))


def _flag_set(packet: Dict[str, Any]) -> Tuple[str, ...]:
    return _normalise_flags(packet["flags"])


def _is_illegal_flag(flags: Tuple[str, ...]) -> bool:
    if not flags:
        return True                      # NULL scan: no flags at all
    s = set(flags)
    if s == {"SYN", "FIN"}:
        return True                      # SYN-FIN
    if "URG" in s and ({"FIN", "PSH"} <= s or "XMAS" in s):
        return True                      # XMAS-style
    if s == {"FIN"}:
        return True                      # bare-FIN probe
    return False


def _inter_arrival(seq: List[Dict[str, Any]]) -> Tuple[float, float]:
    ts = sorted(p["unix_ts"] for p in seq)
    if len(ts) < 2:
        return 0.0, 1.0
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    mean = sum(gaps) / len(gaps)
    if mean <= 0:
        return 0.0, 1.0
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    return mean, math.sqrt(var) / mean


def _window_stats(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Shared metrics computed once per run (over validated packets only)."""
    n = len(packets)
    if n == 0:
        return {"count": 0, "per_src": {}, "flows": {}, "per_src_ports": {}, "per_src_conns": Counter()}

    ordered = sorted(packets, key=lambda p: (p["unix_ts"], p["index"]))
    per_src: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    flows: Dict[Tuple[str, str, int], List[Dict[str, Any]]] = defaultdict(list)
    per_src_ports: Dict[str, set] = defaultdict(set)
    per_src_dsts: Dict[str, set] = defaultdict(set)
    per_src_conns: Counter = Counter()
    for p in ordered:
        per_src[p["src_ip"]].append(p)
        flows[(p["src_ip"], p["dst_ip"], p["dst_port"])].append(p)
        per_src_ports[p["src_ip"]].add(p["dst_port"])
        per_src_dsts[p["src_ip"]].add(p["dst_ip"])
        per_src_conns[p["src_ip"]] += 1

    ts = [p["unix_ts"] for p in ordered]
    span = max(ts) - min(ts) if n > 1 else 1.0
    total_bytes = sum(p["size"] for p in ordered)
    ia_mean, ia_cv = _inter_arrival(ordered)
    # "Out of sequence" is judged in recorded order (ascending packet index),
    # so a stream whose timestamps run backwards is still detected.
    by_record_order = sorted(packets, key=lambda p: p["index"])
    out_of_order = [by_record_order[i]["index"] for i in range(1, n)
                    if by_record_order[i]["unix_ts"] < by_record_order[i - 1]["unix_ts"]]

    return {
        "count": n,
        "span_seconds": span,
        "total_bytes": total_bytes,
        "bytes_per_sec": total_bytes / max(span, 0.001),
        "inter_arrival_mean": ia_mean,
        "inter_arrival_cv": ia_cv,
        "per_src": dict(per_src),
        "flows": dict(flows),
        "per_src_ports": dict(per_src_ports),
        "per_src_dsts": dict(per_src_dsts),
        "per_src_conns": per_src_conns,
        "max_ports_per_src": max((len(v) for v in per_src_ports.values()), default=0),
        "max_conns_per_min": max((c / max(span / 60.0, 1 / 60.0) for c in per_src_conns.values()), default=0.0),
        "failed_auth": sum(1 for p in ordered if _is_auth_failure(p)),
        "failed_auth_indices": [p["index"] for p in ordered if _is_auth_failure(p)],
        "out_of_order_indices": out_of_order,
        "fragmented_indices": [p["index"] for p in ordered
                               if "fragment" in p["payload_text"].lower()],
        "auth_synack": [p for p in ordered if "SYN" in _flag_set(p) and "ACK" in _flag_set(p)],
    }


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------
def _evidence(packets: List[Dict[str, Any]], indices: List[int]) -> List[Dict[str, Any]]:
    """Reproducible evidence references for a detection (bounded for the API)."""
    by_index = {p["index"]: p for p in packets}
    out: List[Dict[str, Any]] = []
    for idx in indices[:_EVIDENCE_DETAIL_LIMIT]:
        p = by_index.get(idx)
        if p is None:
            continue
        ts = p.get("timestamp")
        if not isinstance(ts, str):
            ts = datetime.fromtimestamp(p["unix_ts"], tz=timezone.utc).isoformat()
        preview = p["payload_text"][:120]
        out.append({
            "type": "packet",
            "packet_index": idx,
            "timestamp": ts,
            "src_ip": p["src_ip"],
            "dst_ip": p["dst_ip"],
            "dst_port": p["dst_port"],
            "protocol": p["protocol"],
            "flags": p["flags"],
            "size": p["size"],
            "ttl": p["ttl"],
            "payload_preview": preview,
        })
    return out


def _make_hit(rule: Dict[str, Any], detail: str, confidence: float,
              packet_indices: List[int], packets: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    indices = sorted({int(i) for i in (packet_indices or [])})[:_EVIDENCE_LIMIT]
    explanation = str(rule["explanation"]).replace("{detail}", detail)
    return {
        "rule_id": rule["rule_id"],
        "name": rule["name"],
        "layer": rule["layer"],
        "category": rule["category"],
        "version": rule["version"],
        "severity": rule["severity"],
        "weight": rule["weight"],
        "mitre": rule.get("mitre"),
        "confidence": round(max(0.0, min(1.0, confidence)), 3),
        "detail": detail,
        "explanation": explanation,
        "inputs_used": list(rule["inputs"]),
        "matched_packets": indices,
        "evidence": _evidence(packets or [], indices),
    }


def _fuse_score(triggered: List[Dict[str, Any]]) -> float:
    """Combine rule hits into a 0..1 rule score (soft, saturating)."""
    if not triggered:
        return 0.0
    total = 0.0
    for t in triggered:
        total += SEVERITY_WEIGHT.get(t["severity"], 10) * (0.5 + 0.5 * t["confidence"])
    # Saturating: ~120 weighted points => near-certain
    return round(1.0 - math.exp(-total / 42.0), 4)


# ---------------------------------------------------------------------------
# Rule matchers - one function per rule id, dispatched from the registry so a
# rule cannot be registered without an implemented matcher.
# ---------------------------------------------------------------------------
def _match_signature(rule: Dict[str, Any], ctx: "StreamContext") -> Optional[Dict[str, Any]]:
    pat = re.compile(rule["_pattern"], re.IGNORECASE)
    hits = [p["index"] for p in ctx.packets if pat.search(p["payload_text"])]
    if not hits:
        return None
    return _make_hit(rule, f"{len(hits)} packet(s) matched signature",
                     rule["weight"] / 34.0, hits, ctx.packets)


def _match_conn_rate(rule: Dict[str, Any], ctx: "StreamContext") -> Optional[Dict[str, Any]]:
    t = ctx.thresholds(rule)
    limit = t.get("connections_per_min", 100)
    window = t.get("window_seconds", 60)
    min_packets = t.get("min_packets", 8)
    headroom = t.get("headroom", 1.3)
    if ctx.stats["count"] < min_packets:
        return None
    best_rate, best_src, best_idx = 0.0, "", []
    for src, seq in ctx.stats["per_src"].items():
        rate, idx = _window_max_count(seq, window, ctx.stats["span_seconds"])
        if rate > best_rate:
            best_rate, best_src, best_idx = rate, src, idx
    if best_rate < limit * headroom:
        return None
    detail = f"{best_rate:.0f} conn/min from {best_src} (limit {limit}/min)"
    return _make_hit(rule, detail, min(1.0, best_rate / (limit * 2)), best_idx, ctx.packets)


def _match_port_scan(rule: Dict[str, Any], ctx: "StreamContext") -> Optional[Dict[str, Any]]:
    t = ctx.thresholds(rule)
    needed = t.get("distinct_ports", 12)
    window = t.get("window_seconds", 15)
    best, best_idx, best_src = 0, [], ""
    for src, seq in ctx.stats["per_src"].items():
        peak, idx, _s, _e = _window_max_distinct(seq, "dst_port", window)
        if peak > best:
            best, best_idx, best_src = peak, idx, src
    if best < needed:
        return None
    detail = f"{best} distinct ports from {best_src} within {window}s (limit {needed})"
    return _make_hit(rule, detail, min(1.0, best / 20.0), best_idx, ctx.packets)


def _match_auth_fail(rule: Dict[str, Any], ctx: "StreamContext") -> Optional[Dict[str, Any]]:
    t = ctx.thresholds(rule)
    needed = t.get("failed_attempts", 5)
    window = t.get("window_seconds", 0)
    failures = [p for p in ctx.packets if _is_auth_failure(p)]
    if not failures:
        return None
    if window and window > 0:
        best, best_idx = 0, []
        for seq in ctx.stats["per_src"].values():
            sub = sorted((p for p in seq if _is_auth_failure(p)),
                         key=lambda p: (p["unix_ts"], p["index"]))
            if not sub:
                continue
            peak, idx = _window_peak_count(sub, window)
            if peak > best:
                best, best_idx = peak, idx
        if best < needed:
            return None
        detail = f"{best} failed authentication attempts within {window}s (limit {needed})"
        return _make_hit(rule, detail, min(1.0, best / 10.0), best_idx, ctx.packets)
    if len(failures) < needed:
        return None
    detail = f"{len(failures)} failed authentication attempts (limit {needed})"
    return _make_hit(rule, detail, min(1.0, len(failures) / 10.0),
                     [p["index"] for p in failures], ctx.packets)


def _match_bandwidth(rule: Dict[str, Any], ctx: "StreamContext") -> Optional[Dict[str, Any]]:
    t = ctx.thresholds(rule)
    limit = t.get("bytes_per_sec", 200000)
    window = t.get("window_seconds", 10)
    peak, idx = _window_peak_bytes_per_sec(
        sorted(ctx.packets, key=lambda p: (p["unix_ts"], p["index"])), window, ctx.stats["span_seconds"])
    if peak < limit:
        return None
    detail = f"{peak:.0f} B/s throughput over a {window}s window (limit {limit} B/s)"
    return _make_hit(rule, detail, min(1.0, peak / 500000.0), idx, ctx.packets)


def _match_incomplete_handshake(rule: Dict[str, Any], ctx: "StreamContext") -> Optional[Dict[str, Any]]:
    t = ctx.thresholds(rule)
    needed = t.get("min_syn_without_response", 5)
    answered: set = set()
    for p in ctx.packets:
        flags = set(_flag_set(p))
        if "SYN" in flags and "ACK" in flags:
            answered.add((p["src_ip"], p["dst_port"]))
    half_open: List[int] = []
    for src, seq in ctx.stats["per_src"].items():
        for p in seq:
            flags = set(_flag_set(p))
            if flags == {"SYN"} and (src, p["dst_port"]) not in answered:
                half_open.append(p["index"])
    if len(half_open) < needed:
        return None
    detail = f"{len(half_open)} SYN probes with no SYN-ACK completion (limit {needed})"
    return _make_hit(rule, detail, min(1.0, len(half_open) / 20.0), half_open, ctx.packets)


def _match_flag_anomaly(rule: Dict[str, Any], ctx: "StreamContext") -> Optional[Dict[str, Any]]:
    t = ctx.thresholds(rule)
    needed = t.get("min_anomalous_flag_packets", 3)
    bad = [p["index"] for p in ctx.packets if _is_illegal_flag(_flag_set(p))]
    if len(bad) < needed:
        return None
    detail = f"{len(bad)} packets with scan-typical flag patterns (limit {needed})"
    return _make_hit(rule, detail, 0.6, bad, ctx.packets)


def _match_out_of_sequence(rule: Dict[str, Any], ctx: "StreamContext") -> Optional[Dict[str, Any]]:
    t = ctx.thresholds(rule)
    needed = t.get("min_out_of_sequence_packets", 2)
    indices = sorted(set(ctx.stats["out_of_order_indices"]) | set(ctx.stats["fragmented_indices"]))
    if len(indices) < needed:
        return None
    detail = (f"{len(indices)} out-of-sequence / fragmented packets "
              f"({len(ctx.stats['fragmented_indices'])} fragment markers, "
              f"{len(ctx.stats['out_of_order_indices'])} non-monotonic timestamps)")
    return _make_hit(rule, detail, min(1.0, len(indices) / 6.0), indices, ctx.packets)


def _match_lateral(rule: Dict[str, Any], ctx: "StreamContext") -> Optional[Dict[str, Any]]:
    t = ctx.thresholds(rule)
    needed = t.get("distinct_dst_ports_service", 4)
    min_packets = t.get("min_packets", 6)
    bw_limit = ctx.thresholds(rule_spec("THR-BANDWIDTH")).get("bytes_per_sec", 200000)
    if ctx.stats["count"] < min_packets:
        return None
    # Throughput ceiling comes from the *effective* (override-aware) bandwidth
    # limit, so tuning THR-BANDWIDTH cannot leave this rule on a stale default.
    if ctx.stats["bytes_per_sec"] >= bw_limit:
        return None
    best, best_idx, best_src = 0, [], ""
    for src, ports in ctx.stats["per_src_ports"].items():
        if len(ports) < best or len(ports) < needed:
            continue
        indices = [p["index"] for p in ctx.stats["per_src"][src] if p["dst_port"] in ports]
        best, best_idx, best_src = len(ports), indices, src
    if best < needed:
        return None
    # THR-PORT-SCAN and ST-LATERAL are complementary observations (volumetric
    # fan-out vs service sweeping) and are both reported when both hold, as in
    # the paper's registry; the fused rule score saturates so the overlap does
    # not inflate the verdict without bound.
    detail = (f"source {best_src} reached {best} distinct services across "
              f"{len(ctx.stats['per_src_dsts'].get(best_src, ()))} destination host(s)")
    return _make_hit(rule, detail, 0.55, best_idx, ctx.packets)


def _match_beacon(rule: Dict[str, Any], ctx: "StreamContext") -> Optional[Dict[str, Any]]:
    t = ctx.thresholds(rule)
    min_interval = t.get("min_interval_seconds", 3.0)
    max_cv = t.get("max_cv", 0.12)
    min_samples = t.get("min_samples", 6)
    candidates: List[Tuple[float, float, List[int], str]] = []
    if len(ctx.packets) >= min_samples:
        mean, cv = _inter_arrival(ctx.packets)
        candidates.append((mean, cv, [p["index"] for p in ctx.packets], "aggregate stream"))
    for flow, seq in ctx.stats["flows"].items():
        if len(seq) >= min_samples:
            mean, cv = _inter_arrival(seq)
            candidates.append((mean, cv, [p["index"] for p in seq], f"flow {flow[0]} -> {flow[1]}:{flow[2]}"))
    qualifying = [c for c in candidates if c[0] >= min_interval and c[1] <= max_cv]
    if not qualifying:
        return None
    mean, cv, indices, label = min(qualifying, key=lambda c: (c[1], -c[0]))
    detail = f"Beacon-like cadence every {mean:.1f}s (jitter CV {cv:.3f}) in the {label}"
    return _make_hit(rule, detail, 0.7, indices, ctx.packets)


_MATCHERS: Dict[str, Callable[[Dict[str, Any], "StreamContext"], Optional[Dict[str, Any]]]] = {
    "THR-CONN-RATE": _match_conn_rate,
    "THR-PORT-SCAN": _match_port_scan,
    "THR-AUTH-FAIL": _match_auth_fail,
    "THR-BANDWIDTH": _match_bandwidth,
    "ST-INC-HANDSHAKE": _match_incomplete_handshake,
    "ST-FLAG-ANOMALY": _match_flag_anomaly,
    "ST-OUT-OF-SEQ": _match_out_of_sequence,
    "ST-LATERAL": _match_lateral,
    "ST-BEACON": _match_beacon,
}
for _r in RULE_REGISTRY:
    if _r["layer"] == "signature":
        _MATCHERS[_r["rule_id"]] = _match_signature

# Fail loudly at import if the registry and the matchers ever diverge.
_UNIMPLEMENTED = [r["rule_id"] for r in RULE_REGISTRY if r["rule_id"] not in _MATCHERS]
if _UNIMPLEMENTED:
    raise RuntimeError(f"Registry entries without an implemented matcher: {_UNIMPLEMENTED}")

KNOWN_RULE_IDS = frozenset(r["rule_id"] for r in RULE_REGISTRY)


class StreamContext:
    """Everything a matcher needs, with override-aware thresholds."""

    def __init__(self, packets: List[Dict[str, Any]], stats: Dict[str, Any],
                 overrides: Dict[str, Any], enabled: Dict[str, bool]) -> None:
        self.packets = packets
        self.stats = stats
        self.overrides = overrides
        self.enabled = enabled
        self.triggered_ids: set = set()

    def is_on(self, rule: Dict[str, Any]) -> bool:
        rid = rule["rule_id"]
        if rid in self.enabled:
            return bool(self.enabled[rid])
        ov = self.overrides.get(rid) or {}
        if "enabled" in ov:
            return bool(ov["enabled"])
        return bool(rule["enabled"])

    def thresholds(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(rule.get("threshold") or {})
        ov = self.overrides.get(rule["rule_id"]) or {}
        merged.update(ov.get("threshold", {}) or {})
        return merged


def run_rules(
    packets: List[Dict[str, Any]],
    overrides: Dict[str, Any] = None,
    enabled: Dict[str, bool] = None,
) -> Dict[str, Any]:
    """Evaluate the full rule registry against a packet stream.

    Args:
        packets: generated or replayed packet records.
        overrides: {rule_id: {"enabled": bool, "threshold": {...}}} from the UI.
        enabled: quick {rule_id: bool} map (takes precedence over overrides).

    Returns:
        {triggered, evaluated, rule_score, skipped, accepted_count,
         registry_size, ruleset_version}
    """
    accepted, skipped = _validate_packets(packets)
    stats = _window_stats(accepted)
    ctx = StreamContext(accepted, stats, overrides or {}, enabled or {})

    triggered: List[Dict[str, Any]] = []
    evaluated: List[str] = []

    for rule in RULE_REGISTRY:
        if not ctx.is_on(rule):
            continue
        evaluated.append(rule["rule_id"])
        if not accepted and rule["layer"] != "signature":
            continue  # nothing to correlate against on an empty stream
        hit = _MATCHERS[rule["rule_id"]](rule, ctx)
        if hit is not None:
            triggered.append(hit)
            ctx.triggered_ids.add(rule["rule_id"])

    return {
        "triggered": triggered,
        "evaluated": evaluated,
        "rule_score": _fuse_score(triggered),
        "skipped": skipped,
        "accepted_count": len(accepted),
        "registry_size": len(RULE_REGISTRY),
        "ruleset_version": RULESET_VERSION,
        "unrecognized_overrides": sorted(
            (set(overrides or {}) | set(enabled or {})) - KNOWN_RULE_IDS
        ),
    }
