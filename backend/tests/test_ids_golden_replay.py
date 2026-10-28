"""Locked detection baseline for the packet-level IDS (regression gate).

``data/ids_detection_golden.json`` holds the rule hits, rule score and anomaly
score for every catalog attack at 10/20/60 packets under low/medium/high traffic
volume - 378 replayed streams in total. It was captured from the rebuilt rules
engine *after* that engine was proved behaviour-identical to the previously
committed engine on these same streams, so this file is a genuine "no semantic
drift" lock rather than a snapshot of whatever the code currently does.

If a change here is intentional (a new rule, a corrected threshold, a versioned
semantics change) the baseline must be regenerated deliberately, and the change
explained in the commit; a failing assertion below otherwise means detection
behaviour moved without anyone deciding it should.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from app.services.ids.anomaly_scorer import score_anomaly
from app.services.ids.attack_catalog import CATALOG
from app.services.ids.packet_generator import generate_packets
from app.services.ids.rules_engine import RULESET_VERSION, rule_spec, run_rules

GOLDEN_PATH = Path(__file__).parent / "data" / "ids_detection_golden.json"
SEED = 1
COUNTS = (10, 20, 60)
VOLUMES = ("low", "medium", "high")


def _golden() -> Dict[str, Any]:
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))


def _replay(attack_id: str, count: int, volume: str) -> Dict[str, Any]:
    return _replay_with(attack_id, count, volume, disable=())


def _replay_with(attack_id: str, count: int, volume: str,
                 disable: tuple = ()) -> Dict[str, Any]:
    packets = generate_packets(attack_id, packet_count=count, volume=volume, seed=SEED)["packets"]
    rules = run_rules(packets, enabled={rid: False for rid in disable})
    return {
        "hits": [t["rule_id"] for t in rules["triggered"]],
        "rule_score": rules["rule_score"],
        "ml_score": score_anomaly(packets)["overall_score"],
    }


def test_the_baseline_file_covers_the_whole_catalog_and_nothing_stale():
    golden = _golden()
    cases = golden["cases"]
    expected = {f"{a}|{n}|{v}" for a in CATALOG for n in COUNTS for v in VOLUMES}
    assert set(cases) == expected, (
        f"missing={sorted(expected - set(cases))[:5]} stale={sorted(set(cases) - expected)[:5]}"
    )
    assert golden["seed"] == SEED
    assert len(cases) == len(CATALOG) * len(COUNTS) * len(VOLUMES) == 378


def test_the_baseline_is_locked_to_the_engine_ruleset_version():
    golden = _golden()
    assert golden["ruleset_version"] == RULESET_VERSION, (
        f"baseline captured for ruleset {golden['ruleset_version']!r} but the engine reports "
        f"{RULESET_VERSION!r}; regenerate the baseline only with a documented change"
    )


def test_replaying_every_stream_reproduces_the_locked_detections_exactly():
    golden = _golden()["cases"]
    differences: List[str] = []
    for key, expected in sorted(golden.items()):
        attack_id, count, volume = key.split("|")
        actual = _replay(attack_id, int(count), volume)
        if (actual["hits"] != expected["hits"]
                or actual["rule_score"] != pytest.approx(expected["rule_score"], abs=1e-9)
                or actual["ml_score"] != pytest.approx(expected["ml_score"], abs=1e-9)):
            differences.append(
                f"{key}: expected {expected['hits']} r={expected['rule_score']} "
                f"m={expected['ml_score']}, got {actual['hits']} "
                f"r={actual['rule_score']} m={actual['ml_score']}"
            )
    assert not differences, f"{len(differences)} drifted case(s):\n" + "\n".join(differences[:15])


def test_replay_is_deterministic_across_runs_of_the_same_case():
    for attack_id in ("normal_traffic", "port_scan_syn", "sqli_union", "c2_beacon"):
        first = _replay(attack_id, 20, "medium")
        second = _replay(attack_id, 20, "medium")
        assert first == second


def test_the_locked_baseline_is_not_an_empty_or_trivial_snapshot():
    """A baseline that recorded nothing everywhere would pass silently."""
    golden = _golden()["cases"]
    values = list(golden.values())
    fired = [k for k, v in golden.items() if v["hits"]]
    assert len(fired) > len(golden) * 0.8, "most catalog streams record no rule hit"
    scores = [v["rule_score"] for v in values]
    assert 0.0 <= min(scores) and max(scores) <= 1.0
    assert any(s == 0.0 for s in scores), "nothing is ever reported as quiet"
    assert len({round(s, 3) for s in scores}) > 20, "rule scores are not discriminating"
    assert any(v["ml_score"] > 0.5 for v in values)


def test_benign_ground_truth_behaviour_is_recorded_with_its_false_positive():
    """Honest measurement, not an assumed clean-benign property.

    Benign browsing at low/medium volume trips no rule at all. The same traffic
    generated at *high* volume exceeds the connection-rate threshold - a real
    false positive of any fixed rate rule. It is pinned here so the limitation
    stays visible (and so no report can claim a precision figure for this
    detector without a labelled evaluation of its own).
    """
    golden = _golden()["cases"]
    for volume in ("low", "medium"):
        for count in COUNTS:
            case = golden[f"normal_traffic|{count}|{volume}"]
            assert case["hits"] == [], f"benign {count}/{volume} fired {case['hits']}"
            assert case["rule_score"] == 0.0
    for count in COUNTS:
        case = golden[f"normal_traffic|{count}|high"]
        assert case["hits"] == ["THR-CONN-RATE"], case["hits"]
    # And that rate rule is the one an operator can retune or disable.
    assert rule_spec("THR-CONN-RATE")["tunable"] is True
    quiet = _replay_with("normal_traffic", 20, "high", disable=("THR-CONN-RATE",))
    assert quiet["hits"] == []
