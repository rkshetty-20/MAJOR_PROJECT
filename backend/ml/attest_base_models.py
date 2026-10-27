"""Retro-attest a bundled model artifact with a verifiable provenance sidecar.

The bundled ``port_scan_rf.joblib`` shipped with the project predates the
metadata registry, so it had no ``.meta.json``. The service refuses to score
features against an unverifiable model, which means the artifact must either be
retrained or attested.

Attestation does **not** retrain or modify the estimator. It records only what
can be verified:

  * the estimator's own hyper-parameters, input count and class ordering;
  * the declared feature schema the trainer used;
  * a deterministic digest of the dataset that ``train_port_scan_model.py``
    regenerates from seed 42 (the documented training source);
  * the metrics already present in ``port_scan_rf_metrics.json``, tagged as
    *reported* rather than re-measured here.

Anything that cannot be verified is recorded as ``null`` with a reason, so the
provenance is honest about its own limits.

Usage::

    python -m ml.attest_base_models            # attest the bundled baseline
    python -m ml.attest_base_models --check    # verify without writing
"""

import argparse
import hashlib
import json
import os
import sys
from typing import Any, Dict, Optional

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

import joblib  # noqa: E402

from ml import registry  # noqa: E402
from ml.features import (  # noqa: E402
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    describe_classifier,
)
from ml.registry import SYNTHETIC_LIMITATION, TRAINING_SEED  # noqa: E402

BASE_ARTIFACTS = {
    "port_scan": ("port_scan_rf.joblib", "port_scan_rf_metrics.json"),
}


def _dataset_digest() -> str:
    """Digest the deterministic dataset the documented trainer produces."""
    from ml.train_port_scan_model import generate_synthetic_dataset

    X, y = generate_synthetic_dataset(num_normal=250, num_scan=250, random_seed=TRAINING_SEED)
    material = json.dumps({"X": X, "y": y}, sort_keys=True)
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _read_reported_metrics(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    payload = dict(payload)
    payload["provenance"] = "reported_by_existing_metrics_sidecar_not_remeasured"
    return payload


def attest(task_name: str, write: bool = True) -> Dict[str, Any]:
    filename, metrics_filename = BASE_ARTIFACTS[task_name]
    artifact = os.path.join(registry.MODELS_DIR, filename)
    if not os.path.isfile(artifact):
        raise SystemExit(f"[ABORT] {artifact} is not present; nothing to attest.")

    clf = joblib.load(artifact)
    n_features = getattr(clf, "n_features_in_", None)
    if n_features is not None and int(n_features) != len(FEATURE_NAMES):
        raise SystemExit(
            f"[ABORT] {filename} exposes {n_features} inputs but the declared schema for "
            f"{task_name} has {len(FEATURE_NAMES)}: {FEATURE_NAMES}. Refusing to attest a "
            f"model whose inputs cannot be named."
        )

    payload = {
        "task_name": task_name,
        "model_version": "base_model",
        "feature_names": list(FEATURE_NAMES),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "model_config": describe_classifier(clf),
        "random_seed": getattr(clf, "random_state", None),
        "data_random_seed": TRAINING_SEED,
        "training_data_version": _dataset_digest(),
        "training_data_source": "ml/train_port_scan_model.py::generate_synthetic_dataset(250+250, seed=42)",
        "evaluation": _read_reported_metrics(os.path.join(registry.MODELS_DIR, metrics_filename)),
        "samples": {"total": 500, "train": 375, "test": 125},
        "n_features_in": int(n_features) if n_features is not None else len(FEATURE_NAMES),
        "classes": [int(c) for c in list(getattr(clf, "classes_", []))],
        "sklearn_version": registry._sklearn_version(),
        "limitations": SYNTHETIC_LIMITATION,
        "provenance": "retro_attested_from_bundled_artifact",
        "attested_at_note": (
            "The estimator was not retrained by this tool. Hyper-parameters, input count "
            "and class ordering are read from the artifact itself; the dataset digest is "
            "recomputed from the documented generator; metrics are copied from the "
            "existing *_metrics.json and flagged as reported, not re-measured."
        ),
    }

    if write:
        path = registry.write_metadata(artifact, payload)
        print(f"[OK] Wrote provenance sidecar: {path}")
    else:
        print(f"[CHECK] Would write provenance for {artifact}:")
        print(json.dumps(payload, indent=2, sort_keys=True))
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Attest bundled model artifacts with provenance metadata")
    parser.add_argument("--check", action="store_true", help="Print the metadata without writing")
    args = parser.parse_args()
    for task in BASE_ARTIFACTS:
        attest(task, write=not args.check)


if __name__ == "__main__":
    main()
