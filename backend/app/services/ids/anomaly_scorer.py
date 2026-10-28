"""Packet feature extraction and anomaly scoring for the IDS module.

Research-aligned status (Section C of the reconstruction directive)
-------------------------------------------------------------------
The paper describes four statistical anomaly scorers over 14 packet features,
"modelled on" isolation forests, autoencoders, z-scores and density clustering,
and explicitly characterises them as *deterministic proxies rather than trained
models*. That distinction is preserved here and exported as ``MODEL_STATUS`` so
no caller can accidentally present these numbers as fitted ML output:

  * Isolation-Forest proxy   - emphasises sparse/extreme feature outliers
  * Autoencoder proxy        - reconstruction error vs a benign prototype
  * Statistical (Z-score)    - count/magnitude of features beyond baseline
  * DBSCAN / density proxy   - distance from the benign feature centroid

No model fitting, no learned parameters and no training data are involved; the
baseline in ``_NORMAL`` is a hand-declared reference range and every score is a
closed-form function of the extracted features. Input is the seeded synthetic /
replayed packet stream - there is no authorized live-capture path, so no
real-time traffic monitoring is claimed.

Each detector emits a 0..1 score; the ensemble fuses them, and the engine
returns per-feature contributions, confidence, a false-positive estimate and a
plain-language explanation of the strongest drivers.
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Any, Dict, List

MODEL_STATUS = (
    "Deterministic statistical proxies over 14 packet features - not trained "
    "models. Scores are reproducible closed-form functions of the declared "
    "baseline; no fitting, no learned parameters, no live-capture input."
)
SCORER_NAMES = ("isolation_forest", "autoencoder", "statistical_zscore", "dbscan_density")

# Ensemble weights (hand-declared, sum to 1.0) and the fixed feature list.
ENSEMBLE_WEIGHTS = {
    "isolation_forest": 0.30,
    "autoencoder": 0.28,
    "statistical_zscore": 0.22,
    "dbscan_density": 0.20,
}

# ---------------------------------------------------------------------------
# Benign baseline profile (reference ranges for normal traffic). Values chosen
# to reflect ordinary web/DNS behaviour; deviation drives anomaly.
# ---------------------------------------------------------------------------
_NORMAL = {
    "size_mean": (120, 700),
    "size_std": (0, 260),
    "inter_arrival_mean": (0.05, 5.0),   # seconds
    "inter_arrival_std": (0.0, 2.5),
    "distinct_dst_ports": (1, 4),
    "distinct_src": (1, 6),
    "protocol_diversity": (1, 2),
    "payload_entropy": (0.0, 5.2),       # bits/byte for text-ish payloads
    "byte_entropy": (0.0, 5.2),
    "ttl_diversity": (1, 4),
    "flag_diversity": (1, 2),
    "ngram_repetition": (0.0, 0.7),
    "packets_per_sec": (0.5, 40),
    "periodicity": (0.10, 1.5),          # CV of inter-arrival (machine-regular => low)
}

_FEATURE_LABELS = {
    "size_mean": "Packet Size (mean bytes)",
    "size_std": "Packet Size Variance",
    "inter_arrival_mean": "Inter-Arrival Time (mean s)",
    "inter_arrival_std": "Inter-Arrival Jitter",
    "distinct_dst_ports": "Destination Port Fan-out",
    "distinct_src": "Source Dispersion",
    "protocol_diversity": "Protocol Diversity",
    "payload_entropy": "Payload Text Entropy",
    "byte_entropy": "Byte-Level Entropy",
    "ttl_diversity": "TTL Diversity",
    "flag_diversity": "TCP Flag Diversity",
    "ngram_repetition": "N-gram Repetition",
    "packets_per_sec": "Arrival Rate (pps)",
    "periodicity": "Beacon Periodicity (low jitter)",
}


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    ent = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return round(ent, 3)


def _ngram_repetition(texts: List[str], n: int = 4) -> float:
    grams: Counter = Counter()
    for t in texts:
        s = t.lower()
        for i in range(max(0, len(s) - n + 1)):
            grams[s[i:i + n]] += 1
    total = sum(grams.values())
    if total == 0:
        return 0.0
    repeated = sum(c - 1 for c in grams.values() if c > 1)
    return round(repeated / total, 3)


def extract_features(packets: List[Dict[str, Any]]) -> Dict[str, float]:
    n = len(packets)
    if n == 0:
        return {k: 0.0 for k in _NORMAL}
    sizes = [p["size"] for p in packets]
    ts = sorted(p["unix_ts"] for p in packets)
    gaps = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)] or [0.0]
    payload_bytes = b"".join(p.get("payload_text", "").encode() for p in packets)
    texts = [p.get("payload_text", "") for p in packets]
    try:
        sample_bytes = b"".join(bytes.fromhex(p.get("payload_sample_hex", "")) for p in packets)
    except ValueError:
        sample_bytes = payload_bytes

    size_mean = sum(sizes) / n
    size_std = math.sqrt(sum((s - size_mean) ** 2 for s in sizes) / n)
    ia_mean = sum(gaps) / len(gaps)
    ia_std = math.sqrt(sum((g - ia_mean) ** 2 for g in gaps) / len(gaps))
    span = (ts[-1] - ts[0]) or 1.0

    return {
        "size_mean": round(size_mean, 1),
        "size_std": round(size_std, 1),
        "inter_arrival_mean": round(ia_mean, 4),
        "inter_arrival_std": round(ia_std, 4),
        "distinct_dst_ports": len({p["dst_port"] for p in packets}),
        "distinct_src": len({p["src_ip"] for p in packets}),
        "protocol_diversity": len({p["protocol"] for p in packets}),
        "payload_entropy": _shannon_entropy(payload_bytes),
        "byte_entropy": _shannon_entropy(sample_bytes),
        "ttl_diversity": len({p["ttl"] for p in packets}),
        "flag_diversity": len({p["flags"] for p in packets}),
        "ngram_repetition": _ngram_repetition(texts),
        "packets_per_sec": round(n / span, 2),
        "periodicity": round(ia_std / ia_mean, 3) if ia_mean > 0 else 0.0,
    }


def _feature_anomaly(name: str, value: float) -> float:
    """Map a feature value to a 0..1 anomaly contribution via baseline range."""
    lo, hi = _NORMAL[name]
    if lo <= value <= hi:
        return 0.0
    if value < lo:
        ref = lo if lo != 0 else 1.0
        dev = (lo - value) / max(abs(ref), 1e-6)
    else:
        ref = hi if hi != 0 else 1.0
        dev = (value - hi) / max(abs(ref), 1e-6)
    return round(min(1.0, dev / (dev + 1.0)), 4)  # saturating


def score_anomaly(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not packets:
        return {"overall_score": 0.0, "models": {}, "features": [], "top_contributors": [],
                "confidence": 0.5, "false_positive_probability": 0.5,
                "model_status": MODEL_STATUS, "feature_count": len(_NORMAL),
                "scorers": list(SCORER_NAMES),
                "explanation": "No packets to score."}

    feats = extract_features(packets)
    per_feature = {name: _feature_anomaly(name, val) for name, val in feats.items()}
    contributions = sorted(
        ({"feature": k, "label": _FEATURE_LABELS[k], "value": feats[k], "anomaly": v}
         for k, v in per_feature.items()),
        key=lambda d: d["anomaly"], reverse=True,
    )

    anomalies = [v for v in per_feature.values() if v > 0]
    if anomalies:
        mean_dev = sum(anomalies) / len(anomalies)
        max_dev = max(anomalies)
        beyond_strong = sum(1 for a in anomalies if a > 0.5)
        norm = math.sqrt(sum(a * a for a in per_feature.values())) / math.sqrt(len(per_feature))

        # Isolation-Forest proxy: rewards a few extreme outliers
        iforest = min(1.0, 0.55 * max_dev + 0.45 * mean_dev)
        # Autoencoder proxy: reconstruction error across all dims
        autoenc = min(1.0, 1.2 * norm)
        # Statistical Z-score proxy: count of strongly deviating features
        stat = min(1.0, beyond_strong / 4.0 * 0.6 + mean_dev * 0.6)
        # DBSCAN density proxy: overall spread from centroid
        dbscan = min(1.0, 0.5 * mean_dev + 0.5 * (len(anomalies) / len(per_feature)))

        # Ensemble: weighted (rules-independent), weights declared once above
        ensemble = round(sum(ENSEMBLE_WEIGHTS[name] * value for name, value in (
            ("isolation_forest", iforest),
            ("autoencoder", autoenc),
            ("statistical_zscore", stat),
            ("dbscan_density", dbscan),
        )), 4)
    else:
        iforest = autoenc = stat = dbscan = ensemble = 0.0

    # Confidence: agreement between detectors
    scores = [iforest, autoenc, stat, dbscan]
    spread = max(scores) - min(scores)
    confidence = round(max(0.0, min(1.0, 1.0 - spread * 0.8 - 0.05)), 3) if ensemble > 0 else 0.6

    # FP estimate: higher when score is near decision boundary (0.5) and low volume
    margin = abs(ensemble - 0.5)
    fp_prob = round(max(0.0, min(0.9, 0.5 - margin + (0.15 if feats["distinct_dst_ports"] < 3 else 0.0))), 3)

    top = [c for c in contributions if c["anomaly"] > 0][:5]
    explanation = _explain(top, ensemble)

    return {
        "overall_score": round(ensemble, 4),
        "models": {
            "isolation_forest": round(iforest, 4),
            "autoencoder": round(autoenc, 4),
            "statistical_zscore": round(stat, 4),
            "dbscan_density": round(dbscan, 4),
        },
        "ensemble_weights": dict(ENSEMBLE_WEIGHTS),
        "model_status": MODEL_STATUS,
        "feature_count": len(per_feature),
        "scorers": list(SCORER_NAMES),
        "features": contributions,
        "top_contributors": top,
        "confidence": confidence,
        "false_positive_probability": fp_prob,
        "explanation": explanation,
    }


def _explain(top: List[Dict[str, Any]], ensemble: float) -> str:
    if not top:
        return "Traffic conforms to benign baseline across all extracted features; no statistical deviation detected."
    parts = ", ".join(
        f"{t['label']} ({t['value']} → {t['anomaly']:.2f} anomaly)" for t in top[:3]
    )
    band = "strongly" if ensemble > 0.7 else "moderately" if ensemble > 0.4 else "slightly"
    return f"Anomaly score is {band} elevated, driven primarily by {parts}."
