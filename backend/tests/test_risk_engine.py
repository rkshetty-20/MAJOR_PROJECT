import sys
import os
import json
from datetime import datetime, timezone

# Ensure backend directory is in python sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import SessionLocal
from app.models import (
    Scenario,
    Session as SessionModel,
    SuricataEvent,
    SecurityEvent,
    Detection,
    RiskScore,
    DetectionSource,
    ScenarioCategory,
    SessionStatus,
    RiskBand,
)
from app.routers.scenarios import seed_scenarios
from app.services.risk_engine import compute_risk_score, _band_for_score, _severity_term


def test_hybrid_risk_fusion():
    db = SessionLocal()
    created_session_ids = []

    try:
        # 1. Ensure scenario exists
        seed_scenarios(db)
        scenario = (
            db.query(Scenario)
            .filter(Scenario.category == ScenarioCategory.PORT_SCAN)
            .first()
        )
        assert scenario is not None, "port_scan scenario not found"

        now = datetime.now(timezone.utc)

        # ---------------------------------------------------------
        # Case (a): Rule Detection Only
        # ---------------------------------------------------------
        sess_a = SessionModel(
            student_id="student_case_a_rule_only",
            scenario_id=scenario.id,
            status=SessionStatus.RUNNING,
            started_at=now,
        )
        db.add(sess_a)
        db.commit()
        db.refresh(sess_a)
        created_session_ids.append(sess_a.id)

        # Suricata Event: severity 2 (medium)
        ev_a = SuricataEvent(
            session_id=sess_a.id,
            raw_signature="ET SCAN Nmap",
            src_ip="192.168.56.10",
            dest_ip="192.168.56.20",
            dest_port=80,
            protocol="TCP",
            severity=2,
            timestamp=now,
        )
        # Rule detection only
        det_a = Detection(
            session_id=sess_a.id,
            source=DetectionSource.RULE,
            label="port_scan_detected",
            confidence=1.0,
            explanation="Rule triggered: distinct ports exceeded threshold",
            timestamp=now,
        )
        db.add_all([ev_a, det_a])
        db.commit()

        risk_a = compute_risk_score(sess_a.id, db)
        factors_a = json.loads(risk_a.contributing_factors)

        print("\n--- CASE (a): RULE DETECTION ONLY ---")
        print(f"  Score: {risk_a.score} ({risk_a.band.value})")
        print(f"  Contributing Factors: {factors_a}")
        assert factors_a["rule_detected"] == 40
        assert factors_a["ml_confidence_term"] == 0
        assert factors_a["agreement_bonus"] == 0

        # ---------------------------------------------------------
        # Case (b): ML Detection Only
        # ---------------------------------------------------------
        sess_b = SessionModel(
            student_id="student_case_b_ml_only",
            scenario_id=scenario.id,
            status=SessionStatus.RUNNING,
            started_at=now,
        )
        db.add(sess_b)
        db.commit()
        db.refresh(sess_b)
        created_session_ids.append(sess_b.id)

        # Suricata Event: severity 2 (medium)
        ev_b = SuricataEvent(
            session_id=sess_b.id,
            raw_signature="ET SCAN Nmap",
            src_ip="192.168.56.10",
            dest_ip="192.168.56.20",
            dest_port=80,
            protocol="TCP",
            severity=2,
            timestamp=now,
        )
        # ML detection only (confidence 0.95 -> 0.95 * 40 = 38)
        det_b = Detection(
            session_id=sess_b.id,
            source=DetectionSource.ML,
            label="port_scan_detected",
            confidence=0.95,
            explanation="ML flagged high port velocity",
            timestamp=now,
        )
        db.add_all([ev_b, det_b])
        db.commit()

        risk_b = compute_risk_score(sess_b.id, db)
        factors_b = json.loads(risk_b.contributing_factors)

        print("\n--- CASE (b): ML DETECTION ONLY ---")
        print(f"  Score: {risk_b.score} ({risk_b.band.value})")
        print(f"  Contributing Factors: {factors_b}")
        assert factors_b["rule_detected"] == 0
        assert factors_b["ml_confidence_term"] == 38
        assert factors_b["agreement_bonus"] == 0

        # ---------------------------------------------------------
        # Case (c): Both Rule and ML Agreeing (Hybrid Fusion)
        # ---------------------------------------------------------
        sess_c = SessionModel(
            student_id="student_case_c_hybrid_agreeing",
            scenario_id=scenario.id,
            status=SessionStatus.RUNNING,
            started_at=now,
        )
        db.add(sess_c)
        db.commit()
        db.refresh(sess_c)
        created_session_ids.append(sess_c.id)

        # Suricata Event: severity 2 (medium)
        ev_c = SuricataEvent(
            session_id=sess_c.id,
            raw_signature="ET SCAN Nmap",
            src_ip="192.168.56.10",
            dest_ip="192.168.56.20",
            dest_port=80,
            protocol="TCP",
            severity=2,
            timestamp=now,
        )
        # Both Rule and ML Agreeing on "port_scan_detected"
        det_c_rule = Detection(
            session_id=sess_c.id,
            source=DetectionSource.RULE,
            label="port_scan_detected",
            confidence=1.0,
            explanation="Rule triggered: port threshold exceeded",
            timestamp=now,
        )
        det_c_ml = Detection(
            session_id=sess_c.id,
            source=DetectionSource.ML,
            label="port_scan_detected",
            confidence=0.95,
            explanation="ML model flagged port scan pattern",
            timestamp=now,
        )
        db.add_all([ev_c, det_c_rule, det_c_ml])
        db.commit()

        risk_c = compute_risk_score(sess_c.id, db)
        factors_c = json.loads(risk_c.contributing_factors)

        print("\n--- CASE (c): BOTH RULE AND ML AGREEING (HYBRID) ---")
        print(f"  Score: {risk_c.score} ({risk_c.band.value})")
        print(f"  Contributing Factors: {factors_c}")
        # Paper formula: terms are summed, never suppressed.
        #   r=40, m=0 (one distinct label), c=0.95*40=38, a=10, s=(4-2)/3*10=6.667
        #   S = round(clamp(94.667, 0, 100)) = 95
        assert factors_c["rule_detected"] == 40
        assert factors_c["ml_confidence_term"] == 38, (
            "Agreement must not zero the ML term - the paper sums r + m + c + a + s"
        )
        assert factors_c["agreement_bonus"] == 10
        assert factors_c["terms"]["s"] == round(20.0 / 3.0, 4)
        assert factors_c["raw_total"] == round(40 + 38 + 10 + 20.0 / 3.0, 4)
        assert risk_c.score == 95
        assert "port_scan_detected" in factors_c["agreed_labels"]

        # ---------------------------------------------------------
        # Verification: Confirm Case (c) scores higher than (a) or (b)
        # ---------------------------------------------------------
        print("\n--- COMPARISON & HYBRID BONUS VALIDATION ---")
        print(f"  Case (a) Score: {risk_a.score}")
        print(f"  Case (b) Score: {risk_b.score}")
        print(f"  Case (c) Score: {risk_c.score}")

        assert risk_c.score > risk_a.score, (
            f"Case (c) [{risk_c.score}] should score strictly higher than Case (a) [{risk_a.score}]"
        )
        assert risk_c.score > risk_b.score, (
            f"Case (c) [{risk_c.score}] should score strictly higher than Case (b) [{risk_b.score}]"
        )
        print("  [CONFIRMED] Hybrid agreement bonus successfully elevated Case (c) over both (a) and (b)!")

        # ---------------------------------------------------------
        # Update in-place test: calling compute_risk_score again does not duplicate
        # ---------------------------------------------------------
        initial_count = db.query(RiskScore).filter(RiskScore.session_id == sess_c.id).count()
        assert initial_count == 1

        updated_risk_c = compute_risk_score(sess_c.id, db)
        after_count = db.query(RiskScore).filter(RiskScore.session_id == sess_c.id).count()
        assert after_count == 1, "compute_risk_score created a duplicate RiskScore row!"
        assert updated_risk_c.id == risk_c.id
        print("  [CONFIRMED] Updating existing RiskScore row in-place verified (no duplicate created).")

    finally:
        # Cleanup test sessions and related rows
        for sid in created_session_ids:
            db.query(RiskScore).filter(RiskScore.session_id == sid).delete()
            db.query(Detection).filter(Detection.session_id == sid).delete()
            db.query(SuricataEvent).filter(SuricataEvent.session_id == sid).delete()
            db.query(SessionModel).filter(SessionModel.id == sid).delete()
        db.commit()
        db.close()


def test_risk_boundaries_and_bonuses():
    db = SessionLocal()
    created_session_ids = []

    try:
        seed_scenarios(db)
        scenario = db.query(Scenario).first()
        now = datetime.now(timezone.utc)

        # Helper to create a session
        def create_sess(name):
            sess = SessionModel(
                student_id=name,
                scenario_id=scenario.id,
                status=SessionStatus.RUNNING,
                started_at=now,
            )
            db.add(sess)
            db.commit()
            db.refresh(sess)
            created_session_ids.append(sess.id)
            return sess

        # 1. Multiple distinct detections & duplicate detections & cap
        sess_bonus = create_sess("multi_bonus")
        dets = [
            Detection(session_id=sess_bonus.id, source=DetectionSource.RULE, label="L1", confidence=1.0, timestamp=now),
            Detection(session_id=sess_bonus.id, source=DetectionSource.RULE, label="L1", confidence=1.0, timestamp=now), # Duplicate
            Detection(session_id=sess_bonus.id, source=DetectionSource.RULE, label="L2", confidence=1.0, timestamp=now),
            Detection(session_id=sess_bonus.id, source=DetectionSource.RULE, label="L3", confidence=1.0, timestamp=now),
            Detection(session_id=sess_bonus.id, source=DetectionSource.RULE, label="L4", confidence=1.0, timestamp=now),
            Detection(session_id=sess_bonus.id, source=DetectionSource.RULE, label="L5", confidence=1.0, timestamp=now), # Exceeds 30 cap
        ]
        db.add_all(dets)
        db.commit()
        r = compute_risk_score(sess_bonus.id, db)
        factors = json.loads(r.contributing_factors)
        assert factors["rule_detected"] == 40
        assert factors["multi_signal_bonus"] == 30 # Capped at 30
        assert len(factors["triggered_rules"]) == 5 # Distinct labels

        # 2. Maximum score does not exceed 100
        sess_max = create_sess("max_score")
        dets_max = [
            Detection(session_id=sess_max.id, source=DetectionSource.RULE, label="L1", confidence=1.0, timestamp=now),
            Detection(session_id=sess_max.id, source=DetectionSource.RULE, label="L2", confidence=1.0, timestamp=now),
            Detection(session_id=sess_max.id, source=DetectionSource.RULE, label="L3", confidence=1.0, timestamp=now),
            Detection(session_id=sess_max.id, source=DetectionSource.RULE, label="L4", confidence=1.0, timestamp=now),
            Detection(session_id=sess_max.id, source=DetectionSource.ML, label="L1", confidence=1.0, timestamp=now),
        ]
        ev_max = SuricataEvent(session_id=sess_max.id, raw_signature="X", src_ip="x", dest_ip="y", protocol="TCP", severity=1, timestamp=now)
        db.add_all(dets_max + [ev_max])
        db.commit()
        r_max = compute_risk_score(sess_max.id, db)
        factors_max = json.loads(r_max.contributing_factors)
        # Paper formula saturates: r=40 + m=min(30,15*3)=30 + c=1.0*40=40 + a=10
        #   + s=(4-1)/3*10=10  =>  raw 130 => clamp => 100
        assert factors_max["raw_total"] == 130.0
        assert factors_max["clamped"] is True
        assert r_max.score == 100
        assert r_max.band == RiskBand.CRITICAL

        # 3. Minimum score does not fall below 0
        sess_min = create_sess("min_score")
        ev_min = SuricataEvent(session_id=sess_min.id, raw_signature="X", src_ip="x", dest_ip="y", protocol="TCP", severity=4, timestamp=now)
        db.add_all([ev_min])
        db.commit()
        r_min = compute_risk_score(sess_min.id, db)
        assert r_min.score == 0 # Only severity term = 0 (inverse of 4), everything else 0
        assert r_min.band == RiskBand.LOW

        # 4. Risk-band boundaries tested through the authoritative mapper
        for score, expected in [
            (0, RiskBand.LOW), (29, RiskBand.LOW),
            (30, RiskBand.MEDIUM), (59, RiskBand.MEDIUM),
            (60, RiskBand.HIGH), (84, RiskBand.HIGH),
            (85, RiskBand.CRITICAL), (100, RiskBand.CRITICAL),
        ]:
            assert _band_for_score(score) == expected, f"band mismatch at {score}"

        print("\n  [CONFIRMED] Advanced bonuses, caps, duplicates, and boundaries verified.")

    finally:
        for sid in created_session_ids:
            db.query(RiskScore).filter(RiskScore.session_id == sid).delete()
            db.query(Detection).filter(Detection.session_id == sid).delete()
            db.query(SuricataEvent).filter(SuricataEvent.session_id == sid).delete()
            db.query(SessionModel).filter(SessionModel.id == sid).delete()
        db.commit()
        db.close()


def _make_session(db, scenario, student_id, tracker):
    sess = SessionModel(
        student_id=student_id,
        scenario_id=scenario.id,
        status=SessionStatus.RUNNING,
        started_at=datetime.now(timezone.utc),
    )
    db.add(sess)
    db.commit()
    db.refresh(sess)
    tracker.append(sess.id)
    return sess


def test_pure_severity_term():
    """s is Suricata-first with the documented fallback; verified without a DB."""
    now = datetime.now(timezone.utc)

    class _E:  # minimal SuricataEvent stand-in for the pure helper
        def __init__(self, sev):
            self.severity = sev

    class _S:  # minimal SecurityEvent stand-in
        def __init__(self, level):
            self.risk_level = level

    term, avg, src = _severity_term([_E(1)], [])
    assert (term, avg, src) == (10.0, 1.0, "suricata")

    term, avg, src = _severity_term([_E(4)], [])
    assert (term, avg, src) == (0.0, 4.0, "suricata")

    term, avg, src = _severity_term([_E(2), _E(3)], [])
    assert src == "suricata" and abs(avg - 2.5) < 1e-9 and abs(term - 5.0) < 1e-9

    # Severity out of the documented 1..4 window is clamped, never negative.
    term, _, src = _severity_term([_E(0)], [])
    assert term == 10.0 and src == "suricata"
    term, _, src = _severity_term([_E(9)], [])
    assert term == 0.0 and src == "suricata"

    # Missing Suricata severities must not create a phantom average.
    term, avg, src = _severity_term([_E(None), _E(None)], [])
    assert (term, avg, src) == (0.0, None, "none")

    # Fallback path: no Suricata events at all.
    assert _severity_term([], [_S("CRITICAL")])[0] == 10.0
    assert _severity_term([], [_S("HIGH"), _S("LOW")])[0] == 7.0
    assert _severity_term([], [_S("LOW")])[0] == 4.0
    assert _severity_term([], [_S(None)])[0] == 4.0
    # Suricata takes precedence over the fallback even when SecurityEvents exist.
    assert _severity_term([_E(4)], [_S("CRITICAL")])[2] == "suricata"
    print("  [OK] Pure severity-term boundaries verified.")


def test_paper_formula_term_semantics():
    """Every term of S = round(clamp(r + m + c + a + s, 0, 100)) exercised in isolation."""
    db = SessionLocal()
    created = []
    try:
        seed_scenarios(db)
        scenario = db.query(Scenario).filter(Scenario.category == ScenarioCategory.PORT_SCAN).first()
        now = datetime.now(timezone.utc)

        # --- m grows only with DISTINCT labels and saturates at 30 ---
        for n_labels, expected_m in [(1, 0), (2, 15), (3, 30), (5, 30)]:
            sess = _make_session(db, scenario, f"m_{n_labels}", created)
            dets = [
                Detection(session_id=sess.id, source=DetectionSource.RULE,
                          label=f"L{i}", confidence=1.0, timestamp=now)
                for i in range(n_labels)
            ]
            db.add_all(dets)
            db.commit()
            factors = json.loads(compute_risk_score(sess.id, db).contributing_factors)
            assert factors["multi_signal_bonus"] == expected_m, f"m wrong for n={n_labels}"
            assert factors["distinct_rule_labels"] == n_labels

        # --- Duplicate detections of one label collapse (no double counting) ---
        sess = _make_session(db, scenario, "dup_collapse", created)
        db.add_all([
            Detection(session_id=sess.id, source=DetectionSource.RULE,
                      label="SAME", confidence=1.0, timestamp=now) for _ in range(4)
        ])
        db.commit()
        factors = json.loads(compute_risk_score(sess.id, db).contributing_factors)
        assert factors["multi_signal_bonus"] == 0
        assert factors["rule_detection_count"] == 4
        assert factors["collapsed_duplicate_rule_detections"] == 3

        # --- a = 0 when rule and ML disagree on the label ---
        sess = _make_session(db, scenario, "disagree", created)
        db.add_all([
            Detection(session_id=sess.id, source=DetectionSource.RULE,
                      label="RULE_A", confidence=1.0, timestamp=now),
            Detection(session_id=sess.id, source=DetectionSource.ML,
                      label="ML_B", confidence=0.5, timestamp=now),
        ])
        db.commit()
        risk = compute_risk_score(sess.id, db)
        factors = json.loads(risk.contributing_factors)
        assert factors["agreement_bonus"] == 0
        assert factors["terms"]["c"] == 20.0
        # r + m + c + a + s = 40 + 0 + 20 + 0 + 0
        assert risk.score == 60 and risk.band == RiskBand.HIGH

        # --- Corrupt / non-qualifying ML confidence is excluded but counted ---
        # Detection.confidence is NOT NULL (and SQLite rejects NaN), so "missing"
        # telemetry arrives as an unusable out-of-range confidence value.
        sess = _make_session(db, scenario, "bad_conf", created)
        db.add_all([
            Detection(session_id=sess.id, source=DetectionSource.ML,
                      label="X", confidence=1.5, timestamp=now),
            Detection(session_id=sess.id, source=DetectionSource.ML,
                      label="Y", confidence=-0.5, timestamp=now),
            Detection(session_id=sess.id, source=DetectionSource.ML,
                      label="Z", confidence=0.8, timestamp=now),
        ])
        db.commit()
        factors = json.loads(compute_risk_score(sess.id, db).contributing_factors)
        assert factors["terms"]["c"] == 32.0
        assert factors["ml_missing_confidence_count"] == 2
        assert factors["ml_highest_confidence"] == 0.8
        assert factors["ml_detection_count"] == 3

        # --- Agreement with ML only for a repeated label set (no suppression) ---
        sess = _make_session(db, scenario, "agree_multi", created)
        db.add_all([
            Detection(session_id=sess.id, source=DetectionSource.RULE, label="A", confidence=1.0, timestamp=now),
            Detection(session_id=sess.id, source=DetectionSource.RULE, label="B", confidence=1.0, timestamp=now),
            Detection(session_id=sess.id, source=DetectionSource.ML, label="A", confidence=0.75, timestamp=now),
            SuricataEvent(session_id=sess.id, raw_signature="ET SCAN", src_ip="198.51.100.5",
                          dest_ip="192.0.2.10", dest_port=22, protocol="TCP", severity=2, timestamp=now),
        ])
        db.commit()
        risk = compute_risk_score(sess.id, db)
        factors = json.loads(risk.contributing_factors)
        # r=40 m=15 c=30 a=10 s=6.6667 -> 101.6667 -> clamped 100
        assert factors["terms"] == {"r": 40.0, "m": 15.0, "c": 30.0, "a": 10.0,
                                   "s": round(20.0 / 3.0, 4)}
        assert factors["clamped"] is True and risk.score == 100
        assert factors["agreed_labels"] == ["A"]

        # --- Recomputation is deterministic and idempotent for identical evidence ---
        first = json.loads(compute_risk_score(sess.id, db).contributing_factors)
        second = json.loads(compute_risk_score(sess.id, db).contributing_factors)
        assert first == second, "risk fusion must be reproducible from stored evidence"
        assert db.query(RiskScore).filter(RiskScore.session_id == sess.id).count() == 1

        print("  [OK] Paper formula term semantics verified.")
    finally:
        for sid in created:
            db.query(RiskScore).filter(RiskScore.session_id == sid).delete()
            db.query(Detection).filter(Detection.session_id == sid).delete()
            db.query(SuricataEvent).filter(SuricataEvent.session_id == sid).delete()
            db.query(SecurityEvent).filter(SecurityEvent.session_id == sid).delete()
            db.query(SessionModel).filter(SessionModel.id == sid).delete()
        db.commit()
        db.close()


def test_severity_fallback_from_security_events():
    """A session with host telemetry but no Suricata rows still scores s correctly."""
    db = SessionLocal()
    created = []
    try:
        seed_scenarios(db)
        scenario = db.query(Scenario).first()
        now = datetime.now(timezone.utc)

        for level, expected_s in [("CRITICAL", 10), ("HIGH", 7), ("LOW", 4)]:
            sess = _make_session(db, scenario, f"fallback_{level}", created)
            db.add(SecurityEvent(
                session_id=sess.id, scenario="brute_force", event_type="failed_login",
                source="192.0.2.25", target="svc-account", risk_level=level,
                detection_status="Detected", timestamp=now,
            ))
            db.commit()
            factors = json.loads(compute_risk_score(sess.id, db).contributing_factors)
            assert factors["severity_source"] == "security_events"
            assert factors["terms"]["s"] == expected_s
            assert factors["rule_detected"] == 0
            # score is exactly the severity contribution when nothing detected
            assert json.loads(compute_risk_score(sess.id, db).contributing_factors)["raw_total"] == float(expected_s)
        print("  [OK] Missing-Suricata severity fallback verified.")
    finally:
        for sid in created:
            db.query(RiskScore).filter(RiskScore.session_id == sid).delete()
            db.query(Detection).filter(Detection.session_id == sid).delete()
            db.query(SuricataEvent).filter(SuricataEvent.session_id == sid).delete()
            db.query(SecurityEvent).filter(SecurityEvent.session_id == sid).delete()
            db.query(SessionModel).filter(SessionModel.id == sid).delete()
        db.commit()
        db.close()


if __name__ == "__main__":
    test_hybrid_risk_fusion()
    test_risk_boundaries_and_bonuses()
    test_pure_severity_term()
    test_paper_formula_term_semantics()
    test_severity_fallback_from_security_events()
    print("\nALL RISK FUSION ENGINE TESTS PASSED!")
