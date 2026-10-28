"""Section C verification: the four statistical anomaly scorers.

The paper describes isolation-forest / autoencoder / z-score / DBSCAN detection
over 14 packet features and characterises them as *deterministic proxies, not
trained models*. These tests hold the code to that statement:

  * the feature vector is exactly the 14 declared features and nothing else;
  * exactly the 4 declared scorers contribute, with hand-declared weights that
    sum to 1.0 and an ensemble that is reproducible from the emitted numbers;
  * scores are closed-form, bounded, order-insensitive and bit-reproducible;
  * the baseline-conforming profile scores exactly 0.0 (no phantom anomaly);
  * nothing in the module fits, imports an ML library, captures traffic, or
    reports a trained-model metric (accuracy / F1 / AUC) it cannot substantiate.

Numeric expectations were calibrated against the implementation, so the
assertions below describe measured behaviour rather than aspirations.
"""
from __future__ import annotations

import inspect
import json
import math
from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest

from app.services.ids import analysis, anomaly_scorer, rules_engine
from app.services.ids.anomaly_scorer import (
    ENSEMBLE_WEIGHTS,
    MODEL_STATUS,
    SCORER_NAMES,
    _FEATURE_LABELS,
    _NORMAL,
    _explain,
    _feature_anomaly,
    _ngram_repetition,
    _shannon_entropy,
    extract_features,
    score_anomaly,
)
from app.services.ids.attack_catalog import CATALOG
from app.services.ids.packet_generator import generate_packets

T0 = 1_700_000_000.0
SRC = "192.0.2.10"
DST = "198.51.100.20"
BENIGN_PAYLOAD = "GET /index.html HTTP/1.1  Host: www.example.com"
PATHS = ["login", "cart", "item", "search", "home", "about", "docs", "api"]


def pkt(index: int, **overrides: Any) -> Dict[str, Any]:
    """One packet with every feature input present (documentation addressing)."""
    ts = T0 + index
    packet: Dict[str, Any] = {
        "index": index,
        "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
        "unix_ts": ts,
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
    if "unix_ts" in overrides and "timestamp" not in overrides:
        packet["timestamp"] = datetime.fromtimestamp(
            overrides["unix_ts"], tz=timezone.utc).isoformat()
    return packet


def conforming(count: int = 24) -> List[Dict[str, Any]]:
    """Traffic that sits inside all 14 benign baseline ranges -> score 0.0."""
    packets = []
    for i in range(count):
        ts = T0 + sum([0.4, 1.1][j % 2] for j in range(i))
        packets.append(pkt(
            i,
            unix_ts=ts,
            dst_port=[443, 80][i % 2],
            protocol=["TCP", "HTTP"][i % 2],
            ttl=[64, 63][i % 2],
            flags=["PSH-ACK", "ACK"][i % 2],
            size=[180, 420, 260, 600][i % 4],
            payload_text=f"GET /{PATHS[i % 8]}{i}?q={i * 3} r={i * 11} z={i * 7}",
        ))
    return packets


def extreme(count: int = 40, step: float = 0.002) -> List[Dict[str, Any]]:
    """Statistically deviant on many axes at once: fan-out, rate, flags, TTLs."""
    out = []
    for i in range(count):
        out.append(pkt(
            i,
            unix_ts=T0 + i * step,
            dst_port=20000 + i,
            protocol=["TCP", "UDP", "ICMP"][i % 3],
            ttl=[64, 128, 255, 1, 63][i % 5],
            flags=["SYN", "FIN", "RST", "PSH-ACK", "NONE"][i % 5],
            size=[60, 1500, 200, 900][i % 4],
            src_ip=f"192.0.2.{i % 7}",
            payload_text="cGF5bG9hZD1ZS1pY0RIQTNlOWYxand6MnE1czZ4" + str(i),
        ))
    return out


def generated(attack_id: str, count: int = 40, volume: str = "medium", seed: int = 7):
    return generate_packets(attack_id, packet_count=count, volume=volume, seed=seed)["packets"]


# ---------------------------------------------------------------------------
# 1. The declared 14-feature vector.
# ---------------------------------------------------------------------------
def test_the_feature_vector_is_exactly_the_declared_fourteen_features():
    assert len(_NORMAL) == 14
    assert set(extract_features(conforming())) == set(_NORMAL)
    assert set(_FEATURE_LABELS) == set(_NORMAL)


def test_every_feature_is_a_finite_real_number():
    for name, value in extract_features(extreme()).items():
        assert isinstance(value, (int, float)) and not isinstance(value, bool), name
        assert math.isfinite(float(value)), name


def test_baseline_ranges_are_ordered_pairs_for_every_feature():
    for name, bounds in _NORMAL.items():
        assert len(bounds) == 2, f"{name} baseline is not a (low, high) pair"
        lo, hi = bounds
        assert lo <= hi, f"{name} baseline inverted"


@pytest.mark.parametrize("name", sorted(_NORMAL))
def test_empty_stream_degenerates_every_feature_to_zero(name: str):
    assert extract_features([])[name] == 0.0


def test_hand_computed_aggregates_match_the_feature_mathematics():
    """Two packets: mean/std/inter-arrival/distinct counts derived by hand."""
    feats = extract_features([
        pkt(0, unix_ts=T0, size=100, dst_port=80, protocol="TCP", ttl=64, flags="SYN",
            payload_text="AAAA"),
        pkt(1, unix_ts=T0 + 2.0, size=300, dst_port=443, protocol="UDP", ttl=128, flags="ACK",
            payload_text="AAAA"),
    ])
    assert feats["size_mean"] == 200.0
    assert feats["size_std"] == 100.0
    assert feats["inter_arrival_mean"] == 2.0
    assert feats["inter_arrival_std"] == 0.0
    assert feats["distinct_dst_ports"] == 2
    assert feats["distinct_src"] == 1
    assert feats["protocol_diversity"] == 2
    assert feats["ttl_diversity"] == 2
    assert feats["flag_diversity"] == 2
    assert feats["packets_per_sec"] == 1.0        # 2 packets over a 2 s span
    assert feats["periodicity"] == 0.0            # zero jitter / mean
    assert feats["payload_entropy"] == 0.0        # one repeated symbol
    assert feats["ngram_repetition"] == 0.5       # 'aaaa' appears twice of 2 grams -> (2-1)/2


def test_entropy_helpers_are_the_declared_shannon_measure():
    assert _shannon_entropy(b"") == 0.0
    assert _shannon_entropy(b"AAAAAAAA") == 0.0          # single symbol
    assert _shannon_entropy(b"ABABABAB") == 1.0           # two equiprobable symbols
    assert _shannon_entropy(b"ABCD") == 2.0               # four equiprobable symbols
    assert _ngram_repetition([]) == 0.0
    assert _ngram_repetition(["aaaa", "aaaa"]) > _ngram_repetition(["abcd", "wxyz"])


def test_byte_entropy_uses_the_hex_sample_and_falls_back_on_malformed_hex():
    assert extract_features([pkt(0, payload_sample_hex="4142")])["byte_entropy"] == 1.0
    # Unparseable hex must degrade to the payload text, not raise.
    assert extract_features([pkt(0, payload_sample_hex="zz")])["byte_entropy"] == pytest.approx(
        extract_features([pkt(0)])["payload_entropy"])


def test_features_are_insensitive_to_packet_ordering_and_survive_duplicates():
    ordered = conforming()
    shuffled = list(reversed(ordered))
    assert extract_features(shuffled) == extract_features(ordered)
    # Duplicated bytes are counted as arrivals, and never crash the statistics.
    dup = extract_features(ordered + ordered)
    assert dup["distinct_dst_ports"] == extract_features(ordered)["distinct_dst_ports"]
    assert dup["size_mean"] == extract_features(ordered)["size_mean"]


def test_a_single_packet_stream_is_scored_without_error():
    result = score_anomaly([pkt(0)])
    assert 0.0 <= result["overall_score"] <= 1.0
    assert result["feature_count"] == 14


# ---------------------------------------------------------------------------
# 2. Baseline deviation mapping (the only "learning" present).
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", sorted(_NORMAL))
def test_values_inside_the_baseline_contribute_no_anomaly(name: str):
    lo, hi = _NORMAL[name]
    assert _feature_anomaly(name, lo) == 0.0        # bounds are inclusive
    assert _feature_anomaly(name, hi) == 0.0
    assert _feature_anomaly(name, (lo + hi) / 2) == 0.0


@pytest.mark.parametrize("name", sorted(_NORMAL))
def test_values_above_the_baseline_contribute_anomaly_and_saturate_below_one(name: str):
    lo, hi = _NORMAL[name]
    mild = _feature_anomaly(name, hi * 2 + 1)
    severe = _feature_anomaly(name, hi * 10 + 1)
    absurd = _feature_anomaly(name, hi * 1e6 + 1)
    assert mild > 0.0
    assert severe > mild                            # monotone in deviation
    assert 0.0 < absurd <= 1.0                      # saturating, never explosive
    assert lo <= hi


@pytest.mark.parametrize("name", [n for n in sorted(_NORMAL) if _NORMAL[n][0] > 0])
def test_values_below_a_positive_baseline_are_anomalous_too(name: str):
    lo, hi = _NORMAL[name]
    assert _feature_anomaly(name, lo / 2) > 0.0
    assert _feature_anomaly(name, -abs(lo)) < 1.0


def test_a_conforming_stream_produces_no_phantom_anomaly():
    """Every feature in range -> every detector silent. Guards against drift."""
    feats = extract_features(conforming())
    for name, value in feats.items():
        lo, hi = _NORMAL[name]
        assert lo <= value <= hi, f"{name}={value} outside baseline"
    assert all(_feature_anomaly(n, v) == 0.0 for n, v in feats.items())


# ---------------------------------------------------------------------------
# 3. The four declared scorers and the ensemble arithmetic.
# ---------------------------------------------------------------------------
def test_exactly_the_four_paper_scorers_are_present():
    assert SCORER_NAMES == ("isolation_forest", "autoencoder", "statistical_zscore",
                            "dbscan_density")
    assert set(ENSEMBLE_WEIGHTS) == set(SCORER_NAMES)
    assert all(0.0 < w < 1.0 for w in ENSEMBLE_WEIGHTS.values())
    assert math.isclose(sum(ENSEMBLE_WEIGHTS.values()), 1.0, rel_tol=1e-9)


def test_the_scorers_are_named_after_methods_not_implementations():
    """The paper models proxies *on* these techniques; nothing is imported."""
    source = inspect.getsource(anomaly_scorer)
    for library in ("sklearn", "scipy", "torch", "tensorflow", "xgboost", "numpy",
                    "keras", "onnx"):
        assert library not in source, f"anomaly scorer imports/uses {library}"


def test_every_stream_emits_all_four_scores_in_unit_range():
    for packets in (conforming(), extreme(), generated("normal_traffic"), generated("port_scan_syn")):
        models = score_anomaly(packets)["models"]
        assert set(models) == set(SCORER_NAMES)
        for name, value in models.items():
            assert 0.0 <= value <= 1.0, f"{name} escaped the unit interval"


def test_ensemble_is_reproducible_from_the_emitted_scores_and_weights():
    for packets in (extreme(), generated("ddos_syn_flood"), generated("sqli_union")):
        result = score_anomaly(packets)
        recomputed = sum(result["ensemble_weights"][k] * v for k, v in result["models"].items())
        assert result["overall_score"] == pytest.approx(recomputed, abs=1e-3)
        assert set(result["ensemble_weights"]) == set(SCORER_NAMES)


def test_the_four_proxies_do_not_all_collapse_to_the_same_number():
    """They are four distinct functions, not one score copied four ways."""
    models = score_anomaly(extreme())["models"]
    assert len(set(models.values())) == len(models)


# ---------------------------------------------------------------------------
# 4. Scored outcomes: ordering, explanation, confidence, false positives.
# ---------------------------------------------------------------------------
def test_conforming_traffic_scores_exactly_zero_and_is_explained_as_benign():
    result = score_anomaly(conforming())
    assert result["overall_score"] == 0.0
    assert all(v == 0.0 for v in result["models"].values())
    assert result["top_contributors"] == []
    assert "conforms to benign baseline" in result["explanation"]
    assert result["confidence"] == 0.6            # no anomaly -> neutral-agreement branch


def test_statistically_deviant_traffic_scores_high_and_rises_with_the_deviation():
    conforming_score = score_anomaly(conforming())["overall_score"]
    deviant = score_anomaly(extreme())["overall_score"]
    assert deviant > 0.6 > conforming_score
    # Shrinking the burst (fewer arrivals at the same spacing) lowers the score.
    scores = [score_anomaly(extreme(n))["overall_score"] for n in (5, 10, 20, 40)]
    assert scores == sorted(scores)
    assert scores[-1] > scores[0]


@pytest.mark.parametrize("step,expected_direction", [(1.0, "in-baseline"), (0.001, "beyond")])
def test_arrival_rate_beyond_the_baseline_raises_the_score(step, expected_direction):
    packets = [pkt(i, unix_ts=T0 + i * step, size=[180, 420, 260, 600][i % 4],
                   payload_text=f"GET /{i}x?q={i * 3}") for i in range(24)]
    result = score_anomaly(packets)
    pps = {f["feature"]: f for f in result["features"]}["packets_per_sec"]
    if expected_direction == "in-baseline":
        assert pps["anomaly"] == 0.0
    else:
        assert pps["anomaly"] > 0.0
        assert pps["value"] > _NORMAL["packets_per_sec"][1]


def test_heavier_generated_volume_yields_a_higher_proxy_score():
    scores = [score_anomaly(generated("port_scan_syn", volume=v))["overall_score"]
              for v in ("low", "medium", "high")]
    assert scores == sorted(scores) and scores[-1] > scores[0]


def test_a_single_extreme_feature_dominates_the_contribution_list():
    result = score_anomaly([pkt(i, size=9000) for i in range(12)])
    top = result["top_contributors"][0]
    assert top["feature"] == "size_mean" and top["anomaly"] > 0.9
    assert "Packet Size" in result["explanation"]


def test_contributions_are_ordered_labelled_and_capped():
    result = score_anomaly(extreme())
    features = result["features"]
    assert len(features) == 14
    assert [f["anomaly"] for f in features] == sorted([f["anomaly"] for f in features],
                                                     reverse=True)
    assert all(f["label"] == _FEATURE_LABELS[f["feature"]] for f in features)
    assert all(0.0 <= f["anomaly"] <= 1.0 for f in features)
    top = result["top_contributors"]
    assert 0 < len(top) <= 5
    assert all(t["anomaly"] > 0 for t in top)
    assert top == features[:len(top)]
    for t in top[:3]:
        assert t["label"] in result["explanation"]


@pytest.mark.parametrize("score,band", [(0.91, "strongly"), (0.55, "moderately"),
                                         (0.20, "slightly")])
def test_explanation_band_language_tracks_the_ensemble_score(score, band):
    contributor = {"feature": "size_mean", "label": "Packet Size (mean bytes)",
                   "value": 5000, "anomaly": 0.9}
    assert band in _explain([contributor], score)


def test_explanation_for_clean_traffic_is_not_a_threat_claim():
    assert _explain([], 0.0) == ("Traffic conforms to benign baseline across all extracted "
                                 "features; no statistical deviation detected.")


def test_confidence_reflects_detector_agreement():
    confident = score_anomaly(generated("normal_traffic"))
    divided = score_anomaly(extreme())
    spread = lambda r: max(r["models"].values()) - min(r["models"].values())  # noqa: E731
    assert spread(confident) < spread(divided)
    assert confident["confidence"] > divided["confidence"]
    for result in (confident, divided):
        assert 0.0 <= result["confidence"] <= 1.0


def test_false_positive_probability_is_highest_near_the_decision_boundary():
    near = score_anomaly([pkt(i, unix_ts=T0 + i * 0.01, size=[180, 420, 260, 600][i % 4],
                              payload_text=f"GET /{i}x?q={i * 3}") for i in range(24)])
    far = score_anomaly(extreme())
    distance = lambda s: abs(s - 0.5)  # noqa: E731
    assert distance(near["overall_score"]) < distance(far["overall_score"])
    assert near["false_positive_probability"] > far["false_positive_probability"]
    for result in (near, far):
        assert 0.0 <= result["false_positive_probability"] <= 0.9


def test_empty_input_is_answered_not_invented():
    result = score_anomaly([])
    assert result["overall_score"] == 0.0
    assert result["models"] == {}
    assert result["explanation"] == "No packets to score."
    assert result["confidence"] == 0.5
    assert result["feature_count"] == 14
    assert result["scorers"] == list(SCORER_NAMES)
    assert result["model_status"] == MODEL_STATUS


# ---------------------------------------------------------------------------
# 5. Determinism, replay and label independence.
# ---------------------------------------------------------------------------
def test_scoring_is_bit_reproducible_for_the_same_seed_and_stream():
    a = score_anomaly(generated("c2_beacon"))
    b = score_anomaly(generated("c2_beacon"))
    assert a == b
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_reordered_packets_produce_an_identical_score():
    packets = generated("ddos_http_flood")
    assert score_anomaly(packets) == score_anomaly(list(reversed(packets)))


def test_the_scorer_reads_packet_bytes_only_and_ignores_any_label_field():
    """A label smuggled into the record cannot move the score."""
    base = extreme(12)
    tagged = [dict(p, attack_id="sqli_union", scenario="Database Dump",
                   ground_truth="malicious", detection_status="detected") for p in base]
    assert score_anomaly(tagged) == score_anomaly(base)


def test_scorer_signature_accepts_packets_only():
    assert list(inspect.signature(extract_features).parameters) == ["packets"]
    assert list(inspect.signature(score_anomaly).parameters) == ["packets"]


@pytest.mark.parametrize("module", [anomaly_scorer, analysis],
                         ids=["anomaly_scorer", "analysis"])
def test_scorer_modules_never_consult_ground_truth_or_the_catalog(module):
    source = inspect.getsource(module)
    if module is analysis:      # analysis legitimately names the attack for display only
        forbidden = ("detection_status", "ground_truth", "ScenarioCategory", "import random")
    else:
        forbidden = ("attack_id", "attack_catalog", "get_attack", "scenario", "expected_attack",
                     "ground_truth", "detection_status", "import random")
    for token in forbidden:
        assert token not in source, f"{module.__name__} references {token!r}"


# ---------------------------------------------------------------------------
# 6. Honest status: proxies, no trained-model claims, no live-traffic claims.
# ---------------------------------------------------------------------------
def test_model_status_states_the_proxy_limitation_in_full():
    assert "not trained" in MODEL_STATUS
    assert "14 packet features" in MODEL_STATUS
    assert "no fitting, no learned parameters, no live-capture input" in MODEL_STATUS


def test_no_live_capture_primitive_exists_in_the_scoring_path():
    source = inspect.getsource(anomaly_scorer)
    for forbidden in ("import socket", "from scapy", "pcapy", "pydivert", "AF_PACKET",
                      "libdnet", "pcap", ".recv("):
        assert forbidden not in source


def test_the_scorer_reports_no_trained_model_metrics():
    """Accuracy/F1/AUC would be fabricated: nothing here is fitted or evaluated."""
    result = score_anomaly(extreme())
    for fabricated in ("accuracy", "precision", "recall", "f1", "auc", "confusion_matrix",
                       "training_samples", "epochs"):
        assert fabricated not in result
    source = inspect.getsource(anomaly_scorer)
    for fitted in (".fit(", "train_test_split", "cross_val", "score(", "predict("):
        assert fitted not in source


def test_every_result_carries_the_proxy_disclaimer_and_feature_count():
    for packets in ([], conforming(), extreme(), generated("arp_spoofing")):
        result = score_anomaly(packets)
        assert result["model_status"] == MODEL_STATUS
        assert result["feature_count"] == 14
        assert result["scorers"] == list(SCORER_NAMES)


@pytest.mark.parametrize("attack_id", sorted(CATALOG))
def test_all_42_catalog_streams_score_inside_the_declared_range(attack_id: str):
    result = score_anomaly(generated(attack_id))
    assert 0.0 <= result["overall_score"] <= 1.0
    assert result["features"] and len(result["features"]) == 14
    assert result["explanation"]
    json.dumps(result)


def test_proxies_are_structural_so_application_content_is_the_rules_job():
    """Known, deliberate limitation (documented, not hidden).

    These proxies see packet *statistics*, not decoded application content, so a
    SQL*Plus-style injection stream scores like benign browsing. The signature
    layer is what detects it - see ``test_ids_rules.py``. Pinning the limitation
    here prevents anyone later claiming detection power these scorers lack.
    """
    benign = score_anomaly(generated("normal_traffic"))["overall_score"]
    injection = score_anomaly(generated("sqli_union"))["overall_score"]
    assert abs(injection - benign) < 0.05
    # ...while the signature layer does catch it (see test_ids_rules.py for full coverage).
    assert "SIG-SQLI-UNION" in [h["rule_id"] for h in rules_engine.run_rules(
        generated("sqli_union"))["triggered"]]


# ---------------------------------------------------------------------------
# 7. Pipeline + HTTP surface expose the same honest numbers.
# ---------------------------------------------------------------------------
def test_analysis_exposes_the_proxy_status_and_input_scope():
    result = analysis.analyze_payload("port_scan_syn", packet_count=40, seed=7)
    ml = result["ml"]
    assert ml["model_status"] == MODEL_STATUS
    assert ml["feature_count"] == 14
    assert ml["scorers"] == list(SCORER_NAMES)
    assert math.isclose(sum(ml["ensemble_weights"].values()), 1.0)
    assert result["pipeline"]["live_traffic_capture"] is False
    assert "Not claimed" in result["pipeline"]["live_traffic_claim"]
    assert 0.0 <= result["verdict"]["ml_score"] <= 100.0


def test_analysis_is_reproducible_from_the_seed_alone():
    first = analysis.analyze_payload("c2_beacon", packet_count=30, seed=42)["ml"]
    second = analysis.analyze_payload("c2_beacon", packet_count=30, seed=42)["ml"]
    assert first == second


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)


def test_analyze_endpoint_returns_the_proxy_scores_verbatim(client):
    body = client.post("/api/ids/analyze",
                       json={"attack_id": "port_scan_syn", "seed": 7, "packet_count": 40}).json()
    ml = body["ml"]
    assert set(ml["models"]) == set(SCORER_NAMES)
    assert ml["model_status"] == MODEL_STATUS
    assert ml["feature_count"] == 14
    assert body["pipeline"]["live_traffic_capture"] is False
    # The dashboard's ML number is the same ensemble the service computed.
    assert body["verdict"]["ml_score"] == pytest.approx(round(ml["overall_score"] * 100, 1))
