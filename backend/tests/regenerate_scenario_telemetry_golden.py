"""Regenerate the locked synthetic-telemetry baseline (Section A).

    python tests/regenerate_scenario_telemetry_golden.py --out tests/data/scenario_telemetry_golden.json

Deliberately NOT named ``test_*`` so pytest can never rewrite the lock as a side
effect of running the suite. The corpus it compiles lives in
``tests/telemetry_corpus.py`` and is imported unchanged by
``tests/test_scenario_telemetry_contract.py``, so the lock and the assertions can
never drift apart.

Regenerate only together with a deliberate, documented change to generation
semantics. A diff in this file is a change to the telemetry contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from collections import Counter
from typing import Any, Dict, List

BACKEND_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services.scenario_simulator.compiler import compile_scenario_to_dataset  # noqa: E402
from app.services.scenario_simulator.spec import (  # noqa: E402
    SCENARIO_SPEC_SCHEMA_VERSION,
)
from telemetry_corpus import build_corpus  # noqa: E402


def digest(spec) -> Dict[str, Any]:
    """Compact, human-reviewable summary of one compiled dataset."""
    dataset = compile_scenario_to_dataset(spec, db=None, persist=False)
    events: List[Dict[str, Any]] = json.loads(dataset.payload_json)

    event_kinds = Counter(
        str(ev.get("event_type") or ev.get("type")) for ev in events
    )
    return {
        "payload_sha256": hashlib.sha256(dataset.payload_json.encode("utf-8")).hexdigest(),
        "dataset_id": dataset.id,
        "seed": spec.seed,
        "events_count": dataset.events_count,
        "timestamp_min": min(ev["timestamp"] for ev in events),
        "timestamp_max": max(ev["timestamp"] for ev in events),
        "event_kinds": dict(sorted(event_kinds.items())),
        "raw_signatures": sorted({str(ev["raw_signature"]) for ev in events if "raw_signature" in ev}),
        "src_ips": sorted({str(ev["src_ip"]) for ev in events if "src_ip" in ev}),
        "dest_ips": sorted({str(ev["dest_ip"]) for ev in events if "dest_ip" in ev}),
        "sources": sorted({str(ev["source"]) for ev in events if "source" in ev}),
        "targets": sorted({str(ev["target"]) for ev in events if "target" in ev}),
        "labels": [int(t.ground_truth_label) for t in spec.event_templates],
        "label_sources": [t.ground_truth_source.value for t in spec.event_templates],
        "dataset_role": dataset.dataset_role,
        "generator_version": dataset.generator_version,
    }


def build_lock() -> Dict[str, Any]:
    cases = {name: digest(spec) for name, spec in build_corpus().items()}
    return {
        "comment": (
            "Locked synthetic-telemetry baseline for the Attack Scenario Studio compiler. "
            "Each digest is produced from tests/telemetry_corpus.py by the deterministic "
            "compiler; replay is asserted by tests/test_scenario_telemetry_contract.py. "
            "Regenerate only with a deliberate, documented change to generation semantics."
        ),
        "schema_version": SCENARIO_SPEC_SCHEMA_VERSION,
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate the scenario telemetry lock.")
    parser.add_argument("--out", required=True, help="Path of the JSON lock file to write.")
    args = parser.parse_args()

    lock = build_lock()
    out_path = pathlib.Path(args.out)
    if not out_path.is_absolute():
        out_path = BACKEND_DIR / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {out_path}  corpus={sum(len(c['event_kinds']) for c in lock['cases'].values())} "
          f"event-kinds  cases={len(lock['cases'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
