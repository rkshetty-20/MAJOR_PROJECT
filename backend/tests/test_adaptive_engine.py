import sys
import os
from datetime import datetime, timezone, timedelta

# Ensure backend directory is in python sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import SessionLocal
from app.models import (
    Scenario,
    Session as SessionModel,
    PerformanceHistory,
    ScenarioCategory,
    DifficultyLevel,
    SessionStatus,
)
from app.routers.scenarios import seed_scenarios
from app.services.adaptive_engine import recommend_next_scenario


def test_adaptive_recommendation_engine():
    db = SessionLocal()
    created_student_ids = []
    created_scenario_ids = []

    try:
        # 1. Ensure standard scenario catalog is seeded
        seed_scenarios(db)

        # Retrieve scenarios
        scenarios = {s.category: s for s in db.query(Scenario).all()}
        assert ScenarioCategory.SSH_BRUTE_FORCE in scenarios
        assert ScenarioCategory.WEB_PROBING in scenarios
        assert ScenarioCategory.PHISHING in scenarios

        now = datetime.now(timezone.utc)

        # =========================================================================
        # Test Case 1: Cold Start (< 2 records)
        # =========================================================================
        student_cold = "student_cold_start"
        created_student_ids.append(student_cold)

        rec_cold = recommend_next_scenario(student_cold, db)
        print("\n--- COLD START TEST (< 2 records) ---")
        print(f"  Result: {rec_cold}")
        assert rec_cold["category"] == "port_scan"
        assert rec_cold["difficulty"] == "easy"
        assert "Not enough history yet" in rec_cold["reason"]
        print("  [PASS] Cold start defaults correctly to baseline easy port_scan.")

        # =========================================================================
        # Test Case 2: Improving Trend in Weakest Category (Raising Difficulty)
        #   - Categories: web_probing (65, 70), phishing (60, 65)
        #   - Weakest: sql_injection [20, 35, 45] (avg 33.3, improving trend)
        #   - Initial difficulty: easy -> should step up to medium
        # =========================================================================
        student_improving = "student_improving_sql"
        created_student_ids.append(student_improving)

        # Create an easy SQL injection scenario to test progression easy -> medium
        sql_easy = Scenario(
            name="SQL Injection Fundamentals",
            category=ScenarioCategory.SQL_INJECTION,
            difficulty=DifficultyLevel.EASY,
            description="Introductory SQL injection exercises",
        )
        db.add(sql_easy)
        db.commit()
        db.refresh(sql_easy)
        created_scenario_ids.append(sql_easy.id)

        # Create session linked to the easy scenario
        sess_sql_easy = SessionModel(
            student_id=student_improving,
            scenario_id=sql_easy.id,
            status=SessionStatus.COMPLETED,
            started_at=now - timedelta(hours=5),
        )
        db.add(sess_sql_easy)
        db.commit()
        db.refresh(sess_sql_easy)

        # History rows for student_improving across 3 categories
        histories_improving = [
            # web_probing (high scores: avg 67.5)
            PerformanceHistory(student_id=student_improving, session_id=sess_sql_easy.id, score_achieved=65, category=ScenarioCategory.WEB_PROBING, timestamp=now - timedelta(hours=4)),
            PerformanceHistory(student_id=student_improving, session_id=sess_sql_easy.id, score_achieved=70, category=ScenarioCategory.WEB_PROBING, timestamp=now - timedelta(hours=3)),
            # phishing (medium-high scores: avg 62.5)
            PerformanceHistory(student_id=student_improving, session_id=sess_sql_easy.id, score_achieved=60, category=ScenarioCategory.PHISHING, timestamp=now - timedelta(hours=3)),
            PerformanceHistory(student_id=student_improving, session_id=sess_sql_easy.id, score_achieved=65, category=ScenarioCategory.PHISHING, timestamp=now - timedelta(hours=2)),
            # sql_injection (lowest scores, but improving: [20, 35, 45])
            PerformanceHistory(student_id=student_improving, session_id=sess_sql_easy.id, score_achieved=20, category=ScenarioCategory.SQL_INJECTION, timestamp=now - timedelta(minutes=90)),
            PerformanceHistory(student_id=student_improving, session_id=sess_sql_easy.id, score_achieved=35, category=ScenarioCategory.SQL_INJECTION, timestamp=now - timedelta(minutes=60)),
            PerformanceHistory(student_id=student_improving, session_id=sess_sql_easy.id, score_achieved=45, category=ScenarioCategory.SQL_INJECTION, timestamp=now - timedelta(minutes=30)),
        ]
        db.add_all(histories_improving)
        db.commit()

        rec_improving = recommend_next_scenario(student_improving, db)
        print("\n--- TEST CASE: IMPROVING TREND IN WEAKEST CATEGORY ---")
        print(f"  Recommended Category:   {rec_improving['category']}")
        print(f"  Recommended Difficulty: {rec_improving['difficulty']}")
        print(f"  Scenario ID:            {rec_improving['scenario_id']}")
        print(f"  Reason:                 {rec_improving['reason']}")

        # (a) Weakest category correctly identified
        assert rec_improving["category"] == "sql_injection", (
            f"Expected weakest category 'sql_injection', got '{rec_improving['category']}'"
        )
        print("  [PASS] (a) Weakest category correctly identified as sql_injection.")

        # (b) Improving trend raises difficulty (easy -> medium)
        assert rec_improving["difficulty"] == "medium", (
            f"Expected difficulty 'medium' due to improving trend, got '{rec_improving['difficulty']}'"
        )
        print("  [PASS] (b) Improving trend successfully raised difficulty from easy to medium.")

        # (c) Reason string contains actual numbers from test data
        reason_imp = rec_improving["reason"]
        assert "sql_injection" in reason_imp
        assert "33" in reason_imp, f"Expected average '33' in reason: {reason_imp}"
        assert "65" in reason_imp, f"Expected comparison average '65' in reason: {reason_imp}"
        assert "20, 35, 45" in reason_imp, f"Expected last 3 scores '20, 35, 45' in reason: {reason_imp}"
        assert "improving" in reason_imp
        assert "raising difficulty to medium" in reason_imp
        print("  [PASS] (c) Reason string accurately cites real computed numbers (avg 33 vs 65, scores: 20, 35, 45).")

        # =========================================================================
        # Test Case 3: Declining Trend in Weakest Category (Not Raising Difficulty)
        #   - Categories: web_probing (65, 70), phishing (50, 55)
        #   - Weakest: ssh_brute_force [50, 20, 15] (avg 28.3, declining trend)
        #   - Initial difficulty: medium -> should step down to easy (not raise!)
        # =========================================================================
        student_declining = "student_declining_ssh"
        created_student_ids.append(student_declining)

        # Create session with medium ssh_brute_force
        sess_ssh_medium = SessionModel(
            student_id=student_declining,
            scenario_id=scenarios[ScenarioCategory.SSH_BRUTE_FORCE].id,
            status=SessionStatus.COMPLETED,
            started_at=now - timedelta(hours=5),
        )
        db.add(sess_ssh_medium)
        db.commit()
        db.refresh(sess_ssh_medium)

        histories_declining = [
            # web_probing (avg 67.5)
            PerformanceHistory(student_id=student_declining, session_id=sess_ssh_medium.id, score_achieved=65, category=ScenarioCategory.WEB_PROBING, timestamp=now - timedelta(hours=4)),
            PerformanceHistory(student_id=student_declining, session_id=sess_ssh_medium.id, score_achieved=70, category=ScenarioCategory.WEB_PROBING, timestamp=now - timedelta(hours=3)),
            # phishing (avg 52.5)
            PerformanceHistory(student_id=student_declining, session_id=sess_ssh_medium.id, score_achieved=50, category=ScenarioCategory.PHISHING, timestamp=now - timedelta(hours=3)),
            PerformanceHistory(student_id=student_declining, session_id=sess_ssh_medium.id, score_achieved=55, category=ScenarioCategory.PHISHING, timestamp=now - timedelta(hours=2)),
            # ssh_brute_force (declining scores: [50, 20, 15])
            PerformanceHistory(student_id=student_declining, session_id=sess_ssh_medium.id, score_achieved=50, category=ScenarioCategory.SSH_BRUTE_FORCE, timestamp=now - timedelta(minutes=90)),
            PerformanceHistory(student_id=student_declining, session_id=sess_ssh_medium.id, score_achieved=20, category=ScenarioCategory.SSH_BRUTE_FORCE, timestamp=now - timedelta(minutes=60)),
            PerformanceHistory(student_id=student_declining, session_id=sess_ssh_medium.id, score_achieved=15, category=ScenarioCategory.SSH_BRUTE_FORCE, timestamp=now - timedelta(minutes=30)),
        ]
        db.add_all(histories_declining)
        db.commit()

        rec_declining = recommend_next_scenario(student_declining, db)
        print("\n--- TEST CASE: DECLINING TREND IN WEAKEST CATEGORY ---")
        print(f"  Recommended Category:   {rec_declining['category']}")
        print(f"  Recommended Difficulty: {rec_declining['difficulty']}")
        print(f"  Scenario ID:            {rec_declining['scenario_id']}")
        print(f"  Reason:                 {rec_declining['reason']}")

        # (a) Weakest category correctly identified
        assert rec_declining["category"] == "ssh_brute_force", (
            f"Expected weakest category 'ssh_brute_force', got '{rec_declining['category']}'"
        )
        print("  [PASS] (a) Weakest category correctly identified as ssh_brute_force.")

        # (b) Declining trend does NOT raise difficulty
        assert rec_declining["difficulty"] != "hard", (
            f"Declining trend should NOT raise difficulty to hard! Got '{rec_declining['difficulty']}'"
        )
        assert rec_declining["difficulty"] == "easy", (
            f"Expected difficulty stepped down to 'easy' due to low scores, got '{rec_declining['difficulty']}'"
        )
        print("  [PASS] (b) Declining trend stepped down difficulty to easy (did not raise).")

        # (c) Reason string cites actual numbers
        reason_dec = rec_declining["reason"]
        assert "ssh_brute_force" in reason_dec
        assert "28" in reason_dec, f"Expected average '28' in reason: {reason_dec}"
        assert "50, 20, 15" in reason_dec, f"Expected scores '50, 20, 15' in reason: {reason_dec}"
        assert "declining" in reason_dec
        assert "stepping down difficulty" in reason_dec
        print("  [PASS] (c) Reason string accurately cites real computed numbers (avg 28, scores: 50, 20, 15).")

    finally:
        # Cleanup test data
        for sid in created_student_ids:
            db.query(PerformanceHistory).filter(PerformanceHistory.student_id == sid).delete()
            db.query(SessionModel).filter(SessionModel.student_id == sid).delete()
        for sc_id in created_scenario_ids:
            db.query(Scenario).filter(Scenario.id == sc_id).delete()
        db.commit()
        db.close()


if __name__ == "__main__":
    test_adaptive_recommendation_engine()
    print("\nALL ADAPTIVE ENGINE TESTS PASSED!")
