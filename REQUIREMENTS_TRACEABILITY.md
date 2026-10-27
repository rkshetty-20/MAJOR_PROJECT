# AOD-IPS: Requirements Traceability Matrix

**Project:** Adaptive Offensive-Defensive Intrusion and Phishing Simulation Framework (AOD-IPS)  
**Specification:** IEEE/Research Reference Architecture  
**Audit & Verification Date:** 2026-10-27 (research-aligned reconstruction, branch `reconstruction`)  
**Test Suite Coverage:** 232 automated backend tests passing (baseline before modification: 189)  

---

## 1. Traceability Matrix

| # | Reference Requirement | Architecture Component | Source Implementation | API / Service Endpoint | Automated Test Verification | Status |
|---|----------------------|-----------------------|-----------------------|------------------------|-----------------------------|:------:|
| **1.1** | Safe Synthetic Attack Simulation | 10 Scenario Catalog | `backend/app/services/simulation_service.py` (`SCENARIO_METADATA`) | `GET /api/simulation/scenarios` | `tests/test_simulation.py::test_01` & `test_11` | ✅ Verified |
| **1.2** | Configurable Intensity / Difficulty | Simulation Orchestrator | `backend/app/services/simulation_service.py` (`run_synthetic_simulation`) | `POST /api/simulation/run` | `tests/test_simulation.py::test_02`, `test_04` | ✅ Verified |
| **1.3** | Zero Real Exploitation Synthetic Telemetry | Telemetry Synthesizer | `backend/app/services/simulation_service.py` | `POST /api/simulation/run`, `GET /api/events` | `tests/test_simulation.py::test_05`, `test_06`, `test_07` | ✅ Verified |
| **2.1** | Behavioral Detection Rules (9 Rules) | Rule Engine | `backend/app/services/rule_engine.py` | Internal dispatch via `evaluate_rules` | `tests/test_rule_engine.py` (11 tests: per-rule boundaries, out-of-order timestamps, duplicate re-delivery, missing fields, conflicting signals, threshold registry) | ✅ Verified |
| **2.2** | Packet-Level IDS (24 Rules: 15 sig, 4 thr, 5 stateful) | Suricata / IDS Engine | `backend/app/services/ids/rules_engine.py` | `evaluate_ids_stream` | per-rule tests pending (stage C verification) | 🔎 Under verification |
| **2.3** | Lexical Phishing Scorer | Lexical Phishing Detector | `backend/app/services/phishing_detector.py` | `POST /api/detect/phishing` | `tests/test_phishing_detector.py` (14 tests) + `tests/test_phishing_suite.py` | 🔎 Under verification |
| **2.4** | Random Forest Port-Scan Detection | ML Engine | `backend/app/services/ml_engine.py`, `backend/ml/features.py`, `backend/ml/registry.py` | `evaluate_ml` / `evaluate_ml_detailed` (simulation pipeline), `GET /api/ml/readiness` | `tests/test_ml_model_lifecycle.py` (37 tests) | ✅ Verified |
| **3.1** | Explainable Risk Scoring (0–100) | Risk Fusion Engine | `backend/app/services/risk_engine.py` | `compute_risk_score`, `GET /api/risk` | `tests/test_simulation.py::test_09`, `test_12` | ✅ Verified |
| **3.2** | Severity Bands & Human Explanations | Risk Explanation Generator | `backend/app/services/risk_engine.py` | `RiskBand` enum (LOW, MEDIUM, HIGH, CRITICAL) | `tests/test_simulation.py::test_09` | ✅ Verified |
| **4.1** | Persistent Database Storage | SQLAlchemy ORM Models | `backend/app/models/models.py`, `backend/app/database.py` | SQLite Engine, DB sessions | `tests/test_simulation.py::test_10` | ✅ Verified |
| **4.2** | Tamper-Evident HMAC-SHA-256 Hash Chain | Cryptographic Integrity Service | `backend/app/services/integrity_service.py` | DB After-Insert Event Listener | `tests/test_e2e_full.py`, `test_integrity.py` | ✅ Verified |
| **5.1** | Simulation-Outcome Adaptive Recommendation | Simulation Outcome Engine | `backend/app/services/simulation_service.py` (`recommend_next_simulation`) | `GET /api/simulation/next-recommendation` | `tests/test_simulation.py::test_20` | ✅ Verified |
| **5.2** | Retraining Acceptance Gate (F1 > 0.85) | Model Lifecycle Engine | `backend/app/services/ml_engine.py` (`train_candidate` → `evaluate_candidate` → `acceptance_gate` → `persist_candidate` → `promote_version`) | `POST /api/ml/train` | `tests/test_ml_model_lifecycle.py::test_acceptance_gate_boundaries`, `test_rejected_candidate_is_never_written_to_disk`, `test_train_candidate_has_no_side_effects` | ✅ Verified |
| **5.3** | Model Versioning & Rollback | ML Registry | `backend/ml/registry.py`, `backend/app/services/ml_engine.py` (`rollback_model`) | `POST /api/ml/rollback` | `tests/test_ml_model_lifecycle.py::test_rollback_restores_an_accepted_version_and_refuses_fabrication`, `test_promotion_supersedes_the_previous_active_model` | ✅ Verified |
| **5.4** | Feature contract (names, order, units, ranges) | Feature Schema | `backend/ml/features.py` (`FEATURE_SPECS`, `validate_features`, `vectorize`) | enforced inside `evaluate_ml` and `_load_training_matrix` | `tests/test_ml_model_lifecycle.py::test_validate_features_accepts_only_the_declared_contract`, `test_vectorize_is_order_checked_and_lossless` | ✅ Verified |
| **5.5** | Model provenance & reproducible loading | Artifact Registry | `backend/ml/registry.py` (`save_model`, `validate_artifact`, `load_verified`), `backend/ml/attest_base_models.py`, `ModelVersion` provenance columns | `GET /api/ml/readiness`, `GET /api/ml/status` | `tests/test_ml_model_lifecycle.py::test_bundled_artifact_is_verifiable_and_reports_the_reported_config`, `test_registry_refuses_unverified_or_mismatched_artifacts`, `test_training_is_deterministic_for_identical_data` | ✅ Verified |
| **5.6** | Detectors cannot read ground truth | Anti-leakage verification | `backend/app/services/rule_engine.py`, `backend/app/services/ml_engine.py` | n/a (source-level invariant) | `tests/test_ml_model_lifecycle.py::test_detection_code_path_contains_no_ground_truth_shortcut`, `test_inference_runs_from_measured_features_under_an_unrelated_scenario` | ✅ Verified |
| **6.1** | SOC Dashboard & Telemetry | React + Vite Frontend | `frontend/src/components/DashboardPage.tsx`, `frontend/src/components/RecentEventsTable.tsx` | `GET /api/overview`, `GET /api/events` | React build & API integration | ✅ Verified |
| **6.2** | Attack Simulation & Adaptive UI | Attack Simulation Page | `frontend/src/components/AttackSimulationPage.tsx`, `AttackSimulation.tsx` | `POST /api/simulation/run`, `GET /api/simulation/next-recommendation` | Frontend production build | ✅ Verified |
| **6.3** | Simulation History Endpoint | Simulation Router | `backend/app/routers/simulation.py` | `GET /api/simulation/history` | `tests/test_simulation.py::test_21` | ✅ Verified |

---

## 2. Key Architecture Accomplishments

1. **Robust Dependency Fallback:** Phishing detection uses an offline pure standard-library fallback for domain parsing when `tldextract` is absent, preventing system crashes in air-gapped or minimal Python environments.
2. **Deterministic Adaptation:** Simulation recommendation evaluates actual historical records (Session, SecurityEvent, Detection, RiskScore) to identify untested scenarios or low-detection runs, providing structured guidance and intensity adjustments.
3. **Multi-Signal Risk Fusion:** Combines network packet signatures, endpoint identity shifts, temporal anomalies, and geovelocity calculations into an explainable 0–100 risk score without hardcoded thresholds.
4. **End-to-End Cryptographic Chain:** Every event is cryptographically linked with HMAC-SHA-256 signatures and session hash chains to ensure non-repudiation.

---

## 3. Documented limitations, conflicts and non-claims

These are recorded instead of hidden, because the review must be able to distinguish
"implemented and tested" from "claimed in a slide".

| Item | Honest state | Evidence |
|---|---|---|
| Random Forest accuracy (`1.0` on the synthetic hold-out) | Real-world generalization is **not** established: the hold-out labels are derived from the scenario generator's own signatures. The limitation text is quoted by the artifact metadata, every detection payload, `GET /api/ml/readiness`, `GET /api/ml/status` and `POST /api/ml/train`. | `backend/ml/registry.py::SYNTHETIC_LIMITATION` |
| Bundled `port_scan_rf.joblib` | **Retro-attested, not retrained.** Hyper-parameters, input count and class order are read from the artifact; the dataset digest is recomputed from the documented generator; the accuracy figures are copied from the pre-existing metrics sidecar and explicitly tagged `reported_by_existing_metrics_sidecar_not_remeasured`. | `backend/ml/models/port_scan_rf.meta.json`, `backend/ml/attest_base_models.py` |
| Authentication-attack ML (`brute_force_rf.joblib`) | **Not deployed.** The artifact does not exist and no paper-reported accuracy for it exists, so no artifact was fabricated. The auth detector reports `MODEL_UNAVAILABLE / extension_not_trained` and the readiness endpoint reports `UNAVAILABLE`. Behavioural *rules* still detect brute force and credential stuffing; only the ML leg is absent. | `tests/test_ml_model_lifecycle.py::test_evaluate_ml_detailed_never_silently_skips_an_absent_model`, `test_readiness_distinguishes_ready_and_unavailable_tasks` |
| Legacy `ml/models/v_*.joblib` artifacts | Pre-existing candidates written by the old code path, which dumped every candidate to disk *before* the acceptance gate. They have no provenance sidecar, so the registry refuses to load them and lists them as unverified. New rejected candidates are never written at all. | `ml.registry.artifact_inventory`, `test_rejected_candidate_is_never_written_to_disk` |
| Live traffic monitoring | **Not claimed.** No authorized live ingestion path is implemented or tested; the IDS pipeline operates on recorded/replayed synthetic telemetry only. |
| Lexical phishing scorer | Deterministic lexical scorer, **not** a trained classifier, and uncalibrated: legitimate login URLs can trip the suspicious-token heuristics. Submitted URLs are never fetched. | stage E verification |
| Risk fusion formula | Exactly `S = round(clamp(r + m + c + a + s, 0, 100))` from the paper. An earlier implementation had suppressed the `a` (agreement) term inconsistently; that invention was removed and the paper's form restored. | `backend/app/services/risk_engine.py`, `tests/test_risk_engine.py` |
