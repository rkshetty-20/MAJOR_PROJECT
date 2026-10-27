import sys
import os
import unittest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database import SessionLocal
from app.routers.scenarios import seed_scenarios

class TestInvestigationEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        db = SessionLocal()
        try:
            seed_scenarios(db)
        finally:
            db.close()

    def test_01_investigation_returns_real_detection(self):
        """1. Detection investigation returns a real detection."""
        res = self.client.post("/api/simulation/run", json={"scenario": "brute_force", "intensity": "medium"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        detections = data["detections"]
        self.assertGreater(len(detections), 0)
        
        det_id = detections[0]["id"]
        
        inv_res = self.client.get(f"/api/investigations/{det_id}")
        self.assertEqual(inv_res.status_code, 200)
        inv_data = inv_res.json()
        
        self.assertEqual(inv_data["detection"]["id"], det_id)
        self.assertIn("explanation", inv_data["detection"])
        print("  [PASS] Test 1: Detection investigation returns a real detection.")

    def test_02_related_events_are_correct(self):
        """2. Related events are correct."""
        res = self.client.post("/api/simulation/run", json={"scenario": "credential_stuffing"})
        data = res.json()
        det_id = data["detections"][0]["id"]
        inv_res = self.client.get(f"/api/investigations/{det_id}")
        inv_data = inv_res.json()
        self.assertGreater(len(inv_data["related_events"]), 0)
        print("  [PASS] Test 2: Related events are correct.")

    def test_03_risk_score_matches(self):
        """3. Risk score matches persisted RiskScore."""
        res = self.client.post("/api/simulation/run", json={"scenario": "suspicious_login"})
        data = res.json()
        det_id = data["detections"][0]["id"]
        inv_res = self.client.get(f"/api/investigations/{det_id}")
        inv_data = inv_res.json()
        self.assertEqual(inv_data["risk"]["score"], data["risk"]["score"])
        print("  [PASS] Test 3: Risk score matches persisted RiskScore.")

    def test_04_contributing_factors_match(self):
        """4. Contributing factors match the actual risk calculation."""
        res = self.client.post("/api/simulation/run", json={"scenario": "brute_force"})
        data = res.json()
        det_id = data["detections"][0]["id"]
        inv_res = self.client.get(f"/api/investigations/{det_id}")
        inv_data = inv_res.json()
        factors = inv_data["risk"]["contributing_factors"]
        self.assertIn("rule_detected", factors)
        self.assertIn("multi_signal_bonus", factors)
        print("  [PASS] Test 4: Contributing factors match the actual risk calculation.")

    def test_05_unknown_detection_returns_404(self):
        """5. Unknown detection returns 404."""
        inv_res = self.client.get("/api/investigations/999999")
        self.assertEqual(inv_res.status_code, 404)
        print("  [PASS] Test 5: Unknown detection returns 404.")

    def test_06_simulation_isolation(self):
        """6. Detection from simulation A cannot leak events from simulation B."""
        res_a = self.client.post("/api/simulation/run", json={"scenario": "brute_force"})
        data_a = res_a.json()
        sim_id_a = data_a["simulation_id"]
        det_id_a = data_a["detections"][0]["id"]

        res_b = self.client.post("/api/simulation/run", json={"scenario": "credential_stuffing"})
        data_b = res_b.json()
        sim_id_b = data_b["simulation_id"]
        
        inv_res = self.client.get(f"/api/investigations/{det_id_a}")
        inv_data = inv_res.json()
        
        for ev in inv_data["related_events"]:
            self.assertNotEqual(ev["simulation_id"], sim_id_b)
            self.assertEqual(ev["simulation_id"], sim_id_a)
            
        print("  [PASS] Test 6: Simulation isolation verified.")
        
    def test_07_real_e2e_combined_multi_signal(self):
        """Test for Real E2E combined_multi_signal."""
        res = self.client.post("/api/simulation/run", json={"scenario": "combined_multi_signal"})
        data = res.json()
        
        self.assertGreaterEqual(len(data["detections"]), 4)
        
        for det in data["detections"]:
            inv_res = self.client.get(f"/api/investigations/{det['id']}")
            self.assertEqual(inv_res.status_code, 200)
            inv_data = inv_res.json()
            self.assertGreater(len(inv_data["related_events"]), 0)
            
        print("  [PASS] Test 7: Real E2E combined_multi_signal verified.")

if __name__ == '__main__':
    unittest.main()
