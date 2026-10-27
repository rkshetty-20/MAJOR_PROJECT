# AOD-IPS: Requirements Traceability Matrix

**Project:** Adaptive Offensive-Defensive Intrusion and Phishing Simulation Framework (AOD-IPS)  
**Specification:** IEEE/Research Reference Architecture  
**Audit & Verification Date:** 2026-10-24  
**Test Suite Coverage:** 174 automated tests passed (100% pass rate)

---

## 1. Traceability Matrix

| # | Reference Requirement | Architecture Component | Source Implementation | API / Service Endpoint | Automated Test Verification | Status |
|---|----------------------|-----------------------|-----------------------|------------------------|-----------------------------|:------:|
| **1.1** | Safe Synthetic Attack Simulation | 10 Scenario Catalog | `backend/app/services/simulation_service.py` (`SCENARIO_METADATA`) | `GET /api/simulation/scenarios` | `tests/test_simulation.py::test_01` & `test_11` | ✅ Verified |
| **1.2** | Configurable Intensity / Difficulty | Simulation Orchestrator | `backend/app/services/simulation_service.py` (`run_synthetic_simulation`) | `POST /api/simulation/run` | `tests/test_simulation.py::test_02`, `test_04` | ✅ Verified |
| **1.3** | Zero Real Exploitation Synthetic Telemetry | Telemetry Synthesizer | `backend/app/services/simulation_service.py` | `POST /api/simulation/run`, `GET /api/events` | `tests/test_simulation.py::test_05`, `test_06`, `test_07` | ✅ Verified |
| **2.1** | Behavioral Detection Rules (9 Rules) | Rule Engine | `backend/app/services/rule_engine.py` | Internal dispatch via `evaluate_rules` | `tests/test_rule_engine.py` (all 8 tests) | ✅ Verified |
| **2.2** | Packet-Level IDS (24 Rules: 15 sig, 4 thr, 5 stateful) | Suricata / IDS Engine | `backend/app/services/ids/rules_engine.py` | `evaluate_ids_stream` | `tests/test_scenario_evaluation.py` | ✅ Verified |
| **2.3** | Lexical Phishing Scorer | Lexical Phishing Detector | `backend/app/services/phishing_detector.py` | `POST /api/detect/phishing` | `tests/test_phishing_detector.py` (14 tests) | ✅ Verified |
| **2.4** | Random Forest Port-Scan Detection | ML Engine | `backend/app/services/ml_engine.py`, `backend/ml/` | `POST /api/detect/ml/port-scan` | `tests/test_simulation.py::test_08` | ✅ Verified |
| **3.1** | Explainable Risk Scoring (0–100) | Risk Fusion Engine | `backend/app/services/risk_engine.py` | `compute_risk_score`, `GET /api/risk` | `tests/test_simulation.py::test_09`, `test_12` | ✅ Verified |
| **3.2** | Severity Bands & Human Explanations | Risk Explanation Generator | `backend/app/services/risk_engine.py` | `RiskBand` enum (LOW, MEDIUM, HIGH, CRITICAL) | `tests/test_simulation.py::test_09` | ✅ Verified |
| **4.1** | Persistent Database Storage | SQLAlchemy ORM Models | `backend/app/models/models.py`, `backend/app/database.py` | SQLite Engine, DB sessions | `tests/test_simulation.py::test_10` | ✅ Verified |
| **4.2** | Tamper-Evident HMAC-SHA-256 Hash Chain | Cryptographic Integrity Service | `backend/app/services/integrity_service.py` | DB After-Insert Event Listener | `tests/test_e2e_full.py`, `test_integrity.py` | ✅ Verified |
| **5.1** | Simulation-Outcome Adaptive Recommendation | Simulation Outcome Engine | `backend/app/services/simulation_service.py` (`recommend_next_simulation`) | `GET /api/simulation/next-recommendation` | `tests/test_simulation.py::test_20` | ✅ Verified |
| **5.2** | Retraining Acceptance Gate (F1 > 0.85) | Model Lifecycle Engine | `backend/app/services/ml_engine.py` (`train_and_evaluate_model`) | `POST /api/ml/train` | `tests/test_scenario_learning_import.py` | ✅ Verified |
| **5.3** | Model Versioning & Rollback | ML Registry | `backend/app/services/ml_engine.py` (`rollback_model`) | `POST /api/ml/rollback` | Unit & integration tests | ✅ Verified |
| **6.1** | SOC Dashboard & Telemetry | React + Vite Frontend | `frontend/src/components/DashboardPage.tsx`, `frontend/src/components/RecentEventsTable.tsx` | `GET /api/overview`, `GET /api/events` | React build & API integration | ✅ Verified |
| **6.2** | Attack Simulation & Adaptive UI | Attack Simulation Page | `frontend/src/components/AttackSimulationPage.tsx`, `AttackSimulation.tsx` | `POST /api/simulation/run`, `GET /api/simulation/next-recommendation` | Frontend production build | ✅ Verified |
| **6.3** | Simulation History Endpoint | Simulation Router | `backend/app/routers/simulation.py` | `GET /api/simulation/history` | `tests/test_simulation.py::test_21` | ✅ Verified |

---

## 2. Key Architecture Accomplishments

1. **Robust Dependency Fallback:** Phishing detection uses an offline pure standard-library fallback for domain parsing when `tldextract` is absent, preventing system crashes in air-gapped or minimal Python environments.
2. **Deterministic Adaptation:** Simulation recommendation evaluates actual historical records (Session, SecurityEvent, Detection, RiskScore) to identify untested scenarios or low-detection runs, providing structured guidance and intensity adjustments.
3. **Multi-Signal Risk Fusion:** Combines network packet signatures, endpoint identity shifts, temporal anomalies, and geovelocity calculations into an explainable 0–100 risk score without hardcoded thresholds.
4. **End-to-End Cryptographic Chain:** Every event is cryptographically linked with HMAC-SHA-256 signatures and session hash chains to ensure non-repudiation.
