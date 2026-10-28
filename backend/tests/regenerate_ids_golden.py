"""Deliberate regeneration tool for the locked IDS detection baseline.

Run from ``backend/`` only when a *documented* change to detection semantics
justifies moving the baseline that ``tests/test_ids_golden_replay.py`` enforces::

    python tests/regenerate_ids_golden.py

The script prints a diff summary against the previously committed baseline so an
accidental behaviour change is visible before it is baked into the fixture. It
is named without the ``test_`` prefix on purpose: pytest must never rewrite a
lock file as a side effect of running the suite.
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.services.ids.anomaly_scorer import score_anomaly      # noqa: E402
from app.services.ids.attack_catalog import CATALOG            # noqa: E402
from app.services.ids.packet_generator import generate_packets  # noqa: E402
from app.services.ids.rules_engine import RULESET_VERSION, run_rules  # noqa: E402

SEED = 1
COUNTS = (10, 20, 60)
VOLUMES = ("low", "medium", "high")
OUT = pathlib.Path(__file__).resolve().parent / "data" / "ids_detection_golden.json"


def capture() -> dict:
    cases = {}
    for attack_id in sorted(CATALOG):
        for count in COUNTS:
            for volume in VOLUMES:
                packets = generate_packets(
                    attack_id, packet_count=count, volume=volume, seed=SEED)["packets"]
                rules = run_rules(packets)
                cases[f"{attack_id}|{count}|{volume}"] = {
                    "hits": [t["rule_id"] for t in rules["triggered"]],
                    "rule_score": rules["rule_score"],
                    "ml_score": score_anomaly(packets)["overall_score"],
                }
    return {
        "comment": (
            "Locked detection baseline for the packet-level IDS. Produced by the rebuilt "
            "rules engine after it was proved behaviour-identical to the committed engine "
            "over these same 378 generated streams. Regenerate only together with a "
            "deliberate, documented change to detection semantics."
        ),
        "seed": SEED,
        "ruleset_version": RULESET_VERSION,
        "cases": cases,
    }


def main() -> int:
    fresh = capture()
    previous = json.loads(OUT.read_text(encoding="utf-8")) if OUT.exists() else None

    if previous:
        diffs = [k for k in fresh["cases"]
                 if previous["cases"].get(k) != fresh["cases"][k]]
        print(f"previous ruleset {previous['ruleset_version']}, new ruleset {RULESET_VERSION}")
        print(f"changed cases: {len(diffs)}")
        for key in diffs[:20]:
            print(f"  {key}: {previous['cases'].get(key)} -> {fresh['cases'][key]}")
    else:
        print("no previous baseline found; creating it")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fresh, indent=1, sort_keys=True), encoding="utf-8")
    print(f"wrote {OUT.name}: {len(fresh['cases'])} cases, {OUT.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
