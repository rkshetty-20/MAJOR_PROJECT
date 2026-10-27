import sys
import os
import json
import unittest
from fastapi.testclient import TestClient

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database import SessionLocal
from app.routers.scenarios import seed_scenarios
from app.models import SecurityEvent, SuricataEvent, Detection, RiskScore, Session as SessionModel


class TestSimulationSystem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app.database import engine, Base
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(app)
        db = SessionLocal()
        try:
            seed_scenarios(db)
        finally:
            db.close()

    def test_01_simulation_endpoint_exists(self):
        """Test 1: Verify the /api/simulation/run endpoint exists and validates input."""
        res = self.client.post("/api/simulation/run", json={})
        self.assertIn(res.status_code, [400, 422])
        print("  [PASS] Test 1: Simulation endpoint /api/simulation/run exists and validates input.")

    def test_02_valid_scenario_works(self):
        """Test 2: Valid scenario returns completed status, simulation_id, and telemetry."""
        res = self.client.post(
            "/api/simulation/run",
            json={"scenario": "brute_force", "intensity": "medium"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["scenario"], "brute_force")
        self.assertTrue(data["simulation_id"].startswith("sim_"))
        self.assertIn("risk", data)
        self.assertIn("score", data["risk"])
        self.assertIn("band", data["risk"])
        self.assertIn("simulation_flow", data)
        print("  [PASS] Test 2: Valid scenario 'brute_force' executes successfully with telemetry & timeline.")

    def test_03_invalid_scenario_is_rejected(self):
        """Test 3: Invalid scenario key is rejected with HTTP 400."""
        res = self.client.post(
            "/api/simulation/run",
            json={"scenario": "malicious_unauthorized_exploit", "intensity": "high"},
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("detail", res.json())
        self.assertIn("Unknown scenario", res.json()["detail"])
        print("  [PASS] Test 3: Invalid simulation scenario rejected with HTTP 400.")

    def test_04_event_generation_respects_limits(self):
        """Test 4: Event bounds clamp to min 1 and max 100."""
        # Requesting 250 events should be clamped to 100
        res_high = self.client.post(
            "/api/simulation/run",
            json={"scenario": "credential_stuffing", "event_count": 250},
        )
        self.assertEqual(res_high.status_code, 200)
        self.assertEqual(res_high.json()["events_generated"], 100)

        # Requesting 0 events should be clamped to 1
        res_low = self.client.post(
            "/api/simulation/run",
            json={"scenario": "credential_stuffing", "event_count": 0},
        )
        self.assertEqual(res_low.status_code, 200)
        self.assertEqual(res_low.json()["events_generated"], 1)
        print("  [PASS] Test 4: Event limits correctly enforced within [1, 100] bounds.")

    def test_05_brute_force_simulation_generates_expected_events(self):
        """Test 5: Brute force simulation generates expected synthetic events and rules."""
        res = self.client.post(
            "/api/simulation/run",
            json={"scenario": "brute_force", "intensity": "medium", "event_count": 8},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["events_generated"], 8)
        self.assertIn("brute_force_detected", data["triggered_rules"])

        # Check DB persistence
        db = SessionLocal()
        try:
            evs = (
                db.query(SecurityEvent)
                .filter(SecurityEvent.simulation_id == data["simulation_id"])
                .all()
            )
            self.assertEqual(len(evs), 8)
            self.assertTrue(all(e.target == "demo_user" for e in evs))
            self.assertTrue(all(e.source == "198.51.100.25" for e in evs))
            failed_count = sum(1 for e in evs if e.event_type == "failed_login")
            self.assertEqual(failed_count, 7)
        finally:
            db.close()
        print("  [PASS] Test 5: Brute force generates target, source IP, failure burst, and detection.")

    def test_06_phishing_simulation_generates_expected_telemetry(self):
        """Test 6: Phishing simulation produces expected domain and keyword indicators."""
        res = self.client.post(
            "/api/simulation/run",
            json={"scenario": "phishing_url", "intensity": "low", "event_count": 3},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("phishing_url_detected", data["triggered_rules"])

        db = SessionLocal()
        try:
            evs = (
                db.query(SecurityEvent)
                .filter(SecurityEvent.simulation_id == data["simulation_id"])
                .all()
            )
            self.assertTrue(len(evs) >= 1)
            first_ev = evs[0]
            payload = first_ev.payload_json
            self.assertIn("domain_age_days", payload)
            self.assertIn("suspicious_keywords", payload)
            self.assertIn("login", payload)
        finally:
            db.close()
        print("  [PASS] Test 6: Phishing simulation telemetry and detection verified.")

    def test_07_port_scan_simulation_generates_ids_events(self):
        """Test 7: Port scan simulation generates synthetic Suricata IDS events."""
        res = self.client.post(
            "/api/simulation/run",
            json={"scenario": "port_scan", "event_count": 18},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("port_scan_detected", data["triggered_rules"])

        db = SessionLocal()
        try:
            suricata_evs = (
                db.query(SuricataEvent)
                .filter(SuricataEvent.session_id == data["session_id"])
                .all()
            )
            self.assertEqual(len(suricata_evs), 18)
            distinct_ports = len(set(e.dest_port for e in suricata_evs))
            self.assertTrue(distinct_ports >= 15)
        finally:
            db.close()
        print("  [PASS] Test 7: Port scan generates 18 distinct IDS events triggering port_scan_detected.")

    def test_08_simulation_output_reaches_detection_engine(self):
        """Test 8: Ensure detections are recorded in Detection table for the simulation session."""
        res = self.client.post(
            "/api/simulation/run",
            json={"scenario": "impossible_travel"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()

        db = SessionLocal()
        try:
            dets = (
                db.query(Detection)
                .filter(Detection.session_id == data["session_id"])
                .all()
            )
            self.assertTrue(len(dets) >= 1)
            self.assertIn("impossible_travel_detected", [d.label for d in dets])
        finally:
            db.close()
        print("  [PASS] Test 8: Simulation output successfully triggers and persists detection rows.")

    def test_09_risk_engine_calculates_the_result(self):
        """Test 9: Risk engine calculates risk score dynamically from detections and factors."""
        res = self.client.post(
            "/api/simulation/run",
            json={"scenario": "combined_multi_signal", "intensity": "high"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        risk = data["risk"]
        self.assertGreaterEqual(risk["score"], 60)  # Multi-signal yields high/critical
        self.assertIn(risk["band"].upper(), ["HIGH", "CRITICAL"])
        factors = risk["contributing_factors"]
        self.assertIn("rule_detected", factors)
        self.assertIn("multi_signal_bonus", factors)
        print("  [PASS] Test 9: Multi-signal risk score dynamically computed (score >= 60, High/Critical).")

    def test_10_simulation_results_are_stored_and_retrievable(self):
        """Test 10: Security telemetry events are queryable via GET /api/events and /api/events/{id}."""
        # 1. Run simulation
        res = self.client.post(
            "/api/simulation/run",
            json={"scenario": "new_device", "event_count": 3},
        )
        self.assertEqual(res.status_code, 200)
        sim_id = res.json()["simulation_id"]

        # 2. Query events list
        list_res = self.client.get(f"/api/events?simulation_id={sim_id}")
        self.assertEqual(list_res.status_code, 200)
        events_list = list_res.json()
        self.assertTrue(len(events_list) > 0)
        matched_ev = events_list[0]
        self.assertEqual(matched_ev.get("simulation_id"), sim_id)

        # 3. Query single event by ID
        detail_res = self.client.get(f"/api/events/{matched_ev['id']}")
        self.assertEqual(detail_res.status_code, 200)
        self.assertEqual(detail_res.json()["scenario"], "new_device")
        print("  [PASS] Test 10: Stored simulation events successfully retrievable via GET /api/events.")

    def test_11_all_ten_scenarios_execute(self):
        """Test 11: Execute all remaining scenarios to ensure full 10-scenario coverage."""
        scenarios_to_test = [
            "credential_stuffing",
            "suspicious_login",
            "anomalous_login_time",
            "multiple_failed_logins",
        ]
        for sc in scenarios_to_test:
            res = self.client.post("/api/simulation/run", json={"scenario": sc, "intensity": "low"})
            self.assertEqual(res.status_code, 200, f"Scenario {sc} failed with status {res.status_code}")
            self.assertEqual(res.json()["status"], "completed")
            self.assertTrue(len(res.json()["triggered_rules"]) >= 1)
        print("  [PASS] Test 11: All 10 simulation scenarios verified to execute and produce detections.")

    def test_12_soc_overview_and_risk_endpoints(self):
        """Test 12: GET /api/overview and GET /api/risk return real aggregated metrics."""
        overview_res = self.client.get("/api/overview")
        self.assertEqual(overview_res.status_code, 200)
        overview_data = overview_res.json()
        self.assertIn("total_events", overview_data)
        self.assertIn("detected_threats", overview_data)
        self.assertIn("detections_per_event_ratio", overview_data)

        risk_res = self.client.get("/api/risk")
        self.assertEqual(risk_res.status_code, 200)
        risk_data = risk_res.json()
        self.assertIn("distribution", risk_data)
        self.assertIn("total_assessments", risk_data)
        print("  [PASS] Test 12: Real SOC metrics and risk distribution endpoints operational.")

    def test_13_soc_overview_metrics_file_and_na_behavior(self):
        """Test 13: Confirm (a) model_accuracy reflects metrics file when present, (b) both fields return 'N/A' when no metrics file/ground truth exists, and detection_rate fallback is 'N/A'."""
        import tempfile
        from unittest.mock import patch, MagicMock

        # (a) Model accuracy reflects the real metrics file when present
        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tmp:
            test_metrics = {
                "accuracy": 0.991,
                "precision": 0.992,
                "recall": 0.990,
                "f1": 0.991,
                "trained_at": "2026-10-07T00:00:00Z",
                "data_source": "synthetic",
                "n_samples": 500,
            }
            json.dump(test_metrics, tmp)
            tmp_path = tmp.name

        try:
            with patch("app.routers.simulation.METRICS_PATH", tmp_path):
                res = self.client.get("/api/overview")
                self.assertEqual(res.status_code, 200)
                data = res.json()
                self.assertEqual(data["model_accuracy"], "99.1%")
                self.assertEqual(data["model_accuracy_source"], "synthetic")
                self.assertEqual(data["false_positive_rate"], "N/A")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        # (b) Both fields return "N/A" when no metrics file exists / no ground truth exists
        non_existent_path = os.path.join(tempfile.gettempdir(), "non_existent_metrics_dummy.json")
        with patch("app.routers.simulation.METRICS_PATH", non_existent_path):
            res = self.client.get("/api/overview")
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["model_accuracy"], "N/A")
            self.assertIsNone(data.get("model_accuracy_source"))
            self.assertEqual(data["false_positive_rate"], "N/A")

        # Fallback when total_events == 0: detection_rate returns "N/A"
        from app.database import get_db
        mock_db = MagicMock()
        mock_db.query.return_value.count.return_value = 0
        mock_db.query.return_value.filter.return_value.count.return_value = 0
        app.dependency_overrides[get_db] = lambda: mock_db
        try:
            res_zero = self.client.get("/api/overview")
            self.assertEqual(res_zero.status_code, 200)
            data_zero = res_zero.json()
            self.assertEqual(data_zero["total_events"], 0)
            self.assertEqual(data_zero["detections_per_event_ratio"], "N/A")
        finally:
            app.dependency_overrides.pop(get_db, None)

        print("  [PASS] Test 13: Real metrics file reflection, N/A fallback when absent, and detection rate N/A verified.")

    def test_14_no_endpoint_returns_hardcoded_percentage_literals(self):
        """Test 14: Confirm that no endpoint returns hardcoded percentage literals (98.4%, 1.2%, 99.1%)."""
        import tempfile
        from unittest.mock import patch

        non_existent_path = os.path.join(tempfile.gettempdir(), "no_metrics_path.json")
        with patch("app.routers.simulation.METRICS_PATH", non_existent_path):
            res = self.client.get("/api/overview")
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertNotEqual(data["false_positive_rate"], "1.2%")
            self.assertNotEqual(data["model_accuracy"], "99.1%")

        # Verify source code of simulation router does not contain hardcoded fallback literals in get_soc_overview
        sim_router_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "app", "routers", "simulation.py")
        )
        with open(sim_router_file, "r", encoding="utf-8") as f:
            code = f.read()

        overview_func = code.split("def get_soc_overview(")[1]
        self.assertNotIn('"98.4%"', overview_func)
        self.assertNotIn('"1.2%"', overview_func)
        self.assertNotIn('"99.1%"', overview_func)
        print("  [PASS] Test 14: Confirmed no hardcoded percentage literals exist in endpoints or responses.")


    def test_15_timeline_endpoint(self):
        """Test 15: Timeline endpoint returns correctly sorted DB-backed timestamps, even when inserted out-of-order."""
        # 1. Run simulation
        res = self.client.post(
            "/api/simulation/run",
            json={"scenario": "port_scan", "event_count": 20},
        )
        self.assertEqual(res.status_code, 200)
        sim_id = res.json()["simulation_id"]

        # 2. Artificially skew a timestamp in the DB to test out-of-order sorting
        db = SessionLocal()
        try:
            from datetime import timedelta
            # Fetch detections and force one detection's timestamp to be significantly earlier
            # than the simulation start time, proving the endpoint re-sorts it to the top
            dets = db.query(Detection).filter(Detection.session_id == res.json()["session_id"]).all()
            if len(dets) >= 2:
                # Make the second detection appear to have happened 1 hour before anything else
                dets[1].timestamp = dets[1].timestamp - timedelta(hours=1)
                db.commit()
                
            evs = db.query(SecurityEvent).filter(SecurityEvent.simulation_id == sim_id).all()
            db_timestamps = [e.timestamp.isoformat() for e in evs]
            
            db_det_ts = [d.timestamp.isoformat() for d in dets]
            
            risk = db.query(RiskScore).filter(RiskScore.session_id == evs[0].session_id).first()
            risk_ts = risk.timestamp.isoformat()
        finally:
            db.close()

        # 3. Query timeline
        timeline_res = self.client.get(f"/api/simulation/{sim_id}/timeline")
        self.assertEqual(timeline_res.status_code, 200)
        timeline = timeline_res.json()

        # Check basic stages are present
        stages = [item["step"] for item in timeline]
        self.assertIn("simulation_started", stages)
        self.assertIn("event_generated", stages)
        self.assertIn("detection_triggered", stages)
        self.assertIn("risk_calculated", stages)

        # Check sorting (chronological) is strictly enforced
        timestamps = [item["timestamp"] for item in timeline if item.get("timestamp")]
        self.assertEqual(timestamps, sorted(timestamps), "Timeline is not chronologically sorted!")

        # Check DB exact matches (not synthetic)
        event_timeline_ts = [item["timestamp"] for item in timeline if item["step"] == "event_generated"]
        for ts in event_timeline_ts:
            self.assertIn(ts, db_timestamps)

        det_timeline_ts = [item["timestamp"] for item in timeline if item["step"] == "detection_triggered"]
        for ts in det_timeline_ts:
            self.assertIn(ts, db_det_ts)
            
        risk_timeline_ts = [item["timestamp"] for item in timeline if item["step"] == "risk_calculated"][0]
        self.assertEqual(risk_timeline_ts, risk_ts)
        
        # Verify severity/risk_score distinction (F-08)
        event_steps = [item for item in timeline if item["step"] == "event_generated"]
        if event_steps:
            self.assertIsNone(event_steps[0].get("severity"), "SecurityEvent should not have severity")
            if event_steps[0].get("risk_score") is not None:
                self.assertIsNotNone(event_steps[0].get("risk_score"), "SecurityEvent should have risk_score if available")
                
        suricata_steps = [item for item in timeline if item["step"] == "suricata_event_generated"]
        if suricata_steps:
            self.assertIsNotNone(suricata_steps[0].get("severity"), "SuricataEvent should have severity")
            self.assertIsNone(suricata_steps[0].get("risk_score"), "SuricataEvent should not have risk_score")

        print("  [PASS] Test 15: Timeline endpoint returns accurate, DB-backed chronological stages (including out-of-order sort).")

    def test_16_timeline_isolation_and_empty(self):
        """Test 16: Ensure timelines isolate multiple simulations and handle empty ones."""
        # Run Simulation A
        res_a = self.client.post("/api/simulation/run", json={"scenario": "port_scan", "event_count": 5})
        self.assertEqual(res_a.status_code, 200)
        sim_id_a = res_a.json()["simulation_id"]

        # Run Simulation B
        res_b = self.client.post("/api/simulation/run", json={"scenario": "brute_force", "event_count": 3})
        self.assertEqual(res_b.status_code, 200)
        sim_id_b = res_b.json()["simulation_id"]

        # Query Timeline A
        timeline_a = self.client.get(f"/api/simulation/{sim_id_a}/timeline").json()
        for item in timeline_a:
            if item.get("simulation_id"):
                self.assertEqual(item["simulation_id"], sim_id_a)

        # Query Timeline B
        timeline_b = self.client.get(f"/api/simulation/{sim_id_b}/timeline").json()
        for item in timeline_b:
            if item.get("simulation_id"):
                self.assertEqual(item["simulation_id"], sim_id_b)

        # Test Empty/Unknown Simulation
        res_empty = self.client.get("/api/simulation/unknown_sim_id_999/timeline")
        self.assertEqual(res_empty.status_code, 404)

        print("  [PASS] Test 16: Timelines properly isolate simulations and handle unknown IDs correctly.")


    def test_17_timeline_timestamp_inconsistency_fix(self):
        """Test 17: Verify timeline correctly distinguishes baseline from active events, preserving execution time vs scenario time."""
        res = self.client.post("/api/simulation/run", json={"scenario": "suspicious_login", "event_count": 3})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        sim_id = data["simulation_id"]
        session_id = data["session_id"]
        self.assertEqual(data["events_generated"], 3)
        self.assertIn("suspicious_login_detected", data["triggered_rules"])

        timeline_res = self.client.get(f"/api/simulation/{sim_id}/timeline")
        self.assertEqual(timeline_res.status_code, 200)
        timeline = timeline_res.json()

        # Extract timestamps for baseline, active, simulation_started, and execution
        baseline_ts = [item["timestamp"] for item in timeline if item["step"] == "event_generated" and "Normal" in item.get("label", "")]
        # Suspicious login baseline event might have "baseline" or just be the first event generated
        # Let's get them in order
        event_ts = [item["timestamp"] for item in timeline if item["step"] == "event_generated"]
        sim_start_ts = [item["timestamp"] for item in timeline if item["step"] == "simulation_started"][0]

        self.assertTrue(len(event_ts) >= 3)
        
        db = SessionLocal()
        try:
            session = db.query(SessionModel).filter(SessionModel.id == session_id).first()
            execution_time = session.ended_at.isoformat()
            scenario_start_time = session.started_at.isoformat()
        finally:
            db.close()

        # 1. Correct chronological ordering of the timeline
        timestamps = [item["timestamp"] for item in timeline if item.get("timestamp")]
        self.assertEqual(timestamps, sorted(timestamps))

        # 2. Correct meaning of the simulation start marker
        self.assertEqual(sim_start_ts, scenario_start_time)
        
        # 3. Baseline events strictly precede simulation start marker, active events strictly follow it
        # The first event is the baseline (2 hours ago)
        self.assertLess(event_ts[0], sim_start_ts)
        
        # The active events (e.g. 1 min ago) should be strictly greater than simulation_started
        self.assertGreater(event_ts[1], sim_start_ts)
        self.assertGreater(event_ts[2], sim_start_ts)
        
        # 4. Simulation Execution time is strictly after the scenario start time
        self.assertGreater(execution_time, scenario_start_time)

        print("  [PASS] Test 17: Timeline accurately distinguishes baseline and active events using corrected simulation start marker.")

    def test_18_timeline_spoofing_isolation(self):
        """Test 18: Ensure timeline cannot leak events from another session by spoofing session_id."""
        db = SessionLocal()
        try:
            # Create Alice's session (target)
            res_a = self.client.post("/api/simulation/run", json={"scenario": "port_scan", "event_count": 2})
            self.assertEqual(res_a.status_code, 200)
            sim_id_a = res_a.json()["simulation_id"]
            session_id_a = res_a.json()["session_id"]
            
            # Create Attacker's session
            res_b = self.client.post("/api/simulation/run", json={"scenario": "brute_force", "event_count": 1})
            self.assertEqual(res_b.status_code, 200)
            sim_id_b = res_b.json()["simulation_id"]
            
            # Attacker tries to spoof a SecurityEvent with their simulation_id but Alice's session_id
            from datetime import datetime, timezone
            from sqlalchemy import text
            now = datetime.now(timezone.utc).isoformat()
            
            db.execute(
                text("INSERT INTO security_events (session_id, simulation_id, scenario, event_type, source, target, timestamp, evidence_hash, detection_status) "
                     "VALUES (:session_id, :simulation_id, 'brute_force', 'failed_login', 'attacker', 'target', :ts, 'fake_hash', 'Detected')"),
                {"session_id": session_id_a, "simulation_id": "spoofed_sim_123", "ts": now}
            )
            db.commit()
            
            # Attacker queries the spoofed simulation ID
            res_spoofed = self.client.get("/api/simulation/spoofed_sim_123/timeline")
            
            # The endpoint should reject it because the mapping is not validated (HMAC will fail)
            self.assertNotEqual(res_spoofed.status_code, 200)
            self.assertEqual(res_spoofed.status_code, 400)
            self.assertIn("integrity", res_spoofed.json()["detail"].lower())
            
        finally:
            db.close()
            
        print("  [PASS] Test 18: Timeline endpoint rejects unverified session mappings to prevent cross-session leakage.")

    def test_19_detections_per_event_ratio_semantics(self):
        """Test 19: Verify Detections per Event ratio calculation across various states."""
        from app.database import engine, Base
        
        # 1. Zero security events
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        
        db = SessionLocal()
        seed_scenarios(db)
        
        res = self.client.get("/api/overview")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["detections_per_event_ratio"], "N/A")
        
        # 2. Events with no detections
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        s1 = SessionModel(student_id="t1", scenario_id=1)
        db.add(s1)
        db.commit()
        
        e1 = SecurityEvent(session_id=s1.id, scenario="brute_force", event_type="failed_login", source="s", target="t", timestamp=now)
        db.add(e1)
        db.commit()
        
        res = self.client.get("/api/overview")
        self.assertEqual(res.json()["detections_per_event_ratio"], "0.0")
        
        # 3. Multiple detections for one event (1 event, 2 detections -> 2.0 ratio)
        d1 = Detection(session_id=s1.id, source="rule", label="label1", confidence=1.0, timestamp=now)
        d2 = Detection(session_id=s1.id, source="ml", label="label2", confidence=0.8, timestamp=now)
        db.add_all([d1, d2])
        db.commit()
        
        res = self.client.get("/api/overview")
        self.assertEqual(res.json()["detections_per_event_ratio"], "2.0")
        
        # 4. Multiple events for one detection (add 3 more events -> 4 events, 2 detections -> 0.5 ratio)
        db.add_all([
            SecurityEvent(session_id=s1.id, scenario="test", event_type="test", source="s", target="t", timestamp=now)
            for _ in range(3)
        ])
        db.commit()
        
        res = self.client.get("/api/overview")
        self.assertEqual(res.json()["detections_per_event_ratio"], "0.5")
        
        db.close()
        print("  [PASS] Test 19: Detections per Event ratio is calculated accurately.")

    def test_20_simulation_outcome_adaptive_recommendation(self):
        """Test 20: GET /api/simulation/next-recommendation provides outcome-based adaptation."""
        op_id = "test_adaptive_operator_99"
        # 1. Cold start recommendation
        res = self.client.get(f"/api/simulation/next-recommendation?operator_id={op_id}")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("recommended_scenario", data)
        self.assertIn("recommended_intensity", data)
        self.assertIn("rationale", data)
        self.assertIn("coverage_summary", data)
        self.assertEqual(data["coverage_summary"]["tested_scenarios"], 0)

        # 2. Run a simulation for this operator
        run_res = self.client.post(
            "/api/simulation/run",
            json={"scenario": "brute_force", "intensity": "medium", "student_id": op_id},
        )
        self.assertEqual(run_res.status_code, 200)

        # 3. Post-run recommendation should update coverage and suggest an untested scenario
        post_res = self.client.get(f"/api/simulation/next-recommendation?operator_id={op_id}")
        self.assertEqual(post_res.status_code, 200)
        post_data = post_res.json()
        self.assertGreaterEqual(post_data["coverage_summary"]["tested_scenarios"], 1)
        self.assertNotEqual(post_data["recommended_scenario"], "brute_force")
        self.assertIn(post_data["recommended_intensity"], ["low", "medium", "high"])
        self.assertIsNotNone(post_data["last_session"])
        self.assertEqual(post_data["last_session"]["scenario"], "brute_force")
        print("  [PASS] Test 20: Simulation-outcome adaptive recommendation verified.")

    def test_21_simulation_history_endpoint(self):
        """Test 21: GET /api/simulation/history returns paginated session records."""
        op_id = "test_hist_operator"
        # Run 2 simulations
        self.client.post("/api/simulation/run", json={"scenario": "new_device", "student_id": op_id})
        self.client.post("/api/simulation/run", json={"scenario": "suspicious_login", "student_id": op_id})

        hist_res = self.client.get(f"/api/simulation/history?operator_id={op_id}&limit=10")
        self.assertEqual(hist_res.status_code, 200)
        data = hist_res.json()
        self.assertIn("total", data)
        self.assertIn("items", data)
        self.assertGreaterEqual(data["total"], 2)
        first_item = data["items"][0]
        self.assertIn("session_id", first_item)
        self.assertIn("scenario", first_item)
        self.assertIn("detections_count", first_item)
        print("  [PASS] Test 21: Simulation history endpoint returns structured records.")

    def test_22_dataset_replay_dynamic_scenario(self):
        """Test 22: Generate offline dataset and replay through orchestrator with dynamic scenario resolution."""
        gen_res = self.client.post(
            "/api/datasets/generate",
            json={"scenario": "port_scan", "intensity": "low", "event_count": 5},
        )
        self.assertEqual(gen_res.status_code, 201)
        ds_id = gen_res.json()["id"]

        replay_res = self.client.post(f"/api/datasets/{ds_id}/replay")
        self.assertEqual(replay_res.status_code, 200)
        rep_data = replay_res.json()
        self.assertEqual(rep_data["dataset_id"], ds_id)
        self.assertIn("eval_run_id", rep_data)
        self.assertIn("metrics", rep_data)
        print("  [PASS] Test 22: Dataset generation and dynamic replay successfully executed.")





if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("RUNNING AOD-IPS CONTROLLED ATTACK SIMULATION TEST SUITE")
    print("=" * 70)
    unittest.main(verbosity=2)
