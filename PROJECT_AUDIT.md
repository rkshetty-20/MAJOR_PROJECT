# PROJECT_AUDIT.md — AOD-IPS Complete Codebase Audit & Implementation Report

*Generated: 2026-10-24 | Inspector & Engineer: Antigravity Full-Stack Engineering Agent*

---

## 1. COMPONENT STATUS SUMMARY (All Verified)

### Backend — FastAPI (Python)

| Component | File | Status | Verification |
|---|---|---|:---:|
| Health endpoint `/health` | `app/main.py` | ✅ Working | Verified |
| 10-scenario catalog | `app/services/simulation_service.py` | ✅ All 10 scenarios complete | `test_simulation.py::test_11` |
| Synthetic simulation engine | `app/services/simulation_service.py` | ✅ Working | `test_simulation.py::test_02-07` |
| Rule-based detection (9 behavioral rules) | `app/services/rule_engine.py` | ✅ Working | `test_rule_engine.py` (8/8 passed) |
| Phishing URL lexical scorer (10 registered indicators, per-indicator cap 0.60) | `app/services/phishing/` (façade: `app/services/phishing_detector.py`) | ✅ Declared lexicon, offline by construction, self-describing | `tests/test_phishing_lexical.py` (92), `tests/test_phishing_golden_replay.py` (19), `test_phishing_detector.py` (14), `test_phishing_suite.py` (15) |
| Packet-level IDS (24 rules: 15 sig, 4 thr, 5 stateful) | `app/services/ids/rules_engine.py` | ✅ 24 rules, each contract-validated and individually tested | `tests/test_ids_rules.py` (148), `tests/test_ids_golden_replay.py` (378 locked streams) |
| Packet anomaly proxies (4 deterministic scorers x 14 features) | `app/services/ids/anomaly_scorer.py` | ✅ Deterministic proxies, explicitly not trained models | `tests/test_ids_anomaly.py` (135) |
| Random Forest port-scan ML | `app/services/ml_engine.py`, `ml/registry.py`, `ml/features.py` | ✅ Trained, versioned, provenance-attested | `test_ml_model_lifecycle.py` (37) |
| Risk fusion engine (0-100 score) | `app/services/risk_engine.py` | ✅ Working | `test_simulation.py::test_09` |
| HMAC-SHA-256 evidence integrity | `app/services/integrity_service.py` | ✅ Working | `test_e2e_full.py` |
| Hash chain (per-session) | `app/models/models.py` | ✅ Working | After-insert listener |
| Database persistence (SQLite/SQLAlchemy) | `app/database.py` + models | ✅ Working | Full test suite |
| Simulation history endpoint `/api/simulation/history` | `app/routers/simulation.py` | ✅ Working | `test_simulation.py::test_21` |
| Dynamic scenario replay orchestrator | `app/services/simulation_service.py` | ✅ Working | `test_simulation.py::test_22` |
| Simulation-outcome adaptive recommendation | `app/routers/simulation.py` | ✅ Working | `test_simulation.py::test_20` |
| ML retraining with F1 gate (>0.85) | `app/services/ml_engine.py` | ✅ Working | Retraining pipeline |
| Model versioning + rollback | `app/services/ml_engine.py` | ✅ Working | Rollback tests |
| SOC dashboard API endpoints | `app/routers/simulation.py` | ✅ Working | `test_simulation.py::test_12-14` |

### Frontend — React + TypeScript + Vite

| Component | Status | Verification |
|---|---|:---:|
| App shell and routing | ✅ Working | `npm run build` |
| Dashboard with real API data | ✅ Working | `npm run build` |
| Attack Simulation page | ✅ Working | `npm run build` |
| Adaptive "Adaptive Rec" & "Apply Recommendation" UI | ✅ Working | `npm run build` |
| Raw Dataset Generator & Replay Studio | ✅ Working | `npm run build` |
| Phishing Detection page (renders the served indicator contract, states the uncalibrated limit) | ✅ Working | `PhishingDetectionPage.test.tsx` (5) |
| Intrusion Detection & IDS Rules | ✅ Working | `npm run build` |

---

## 2. COMPLETED FIXES & ENHANCEMENTS

1. **`tldextract` Offline Fallback:**
   Replaced unconditional top-level import with a robust stdlib URL parsing fallback. Avoids crash when `tldextract` is not installed or when running offline.
2. **Dynamic Scenario Resolution in Dataset Replay:**
   Fixed `run_dataset_replay` which previously hardcoded `scenario_id=1`, causing foreign-key or missing-record failures on clean databases. Now uses dynamic scenario resolution via `_resolve_scenario_record()`.
3. **Simulation-Outcome Adaptive Recommendation:**
   Implemented `recommend_next_simulation()` in `simulation_service.py` and exposed endpoint `GET /api/simulation/next-recommendation`. Evaluates actual historical session records, security events, detections, and risk scores to systematically expand attack scenario coverage and modulate intensity.
4. **Simulation History Endpoint:**
   Implemented `GET /api/simulation/history` returning paginated simulation runs with status, event counts, detections, and risk scores.
5. **Behavioral Rule Enhancements:**
   - General anomalous login time evaluation: off-hours baseline check (outside 07:00–22:00) with per-user profile overrides.
   - Distinct `multiple_failed_logins_detected` rule for the dedicated `multiple_failed_logins` attack scenario.
6. **Frontend Integration:**
   - Added `AdaptiveRecommendation` and `SimulationHistoryResponse` interfaces and API methods in `frontend/src/api.ts`.
   - Added `Adaptive Rec` refresh button and adaptive next recommendation banner in `AttackSimulation.tsx` with one-click `Apply Recommendation` control.
   - Clean production build with Vite (`dist/` generated, 0 TypeScript errors).
7. **Traceability Matrix:**
   Generated comprehensive `REQUIREMENTS_TRACEABILITY.md` cross-referencing all 6 reference requirements with active code files and automated test verifications.

---

## 3. TEST SUITE RESULTS

- **Backend Pytest:** **691 passed**, 0 failures across 29 test modules (measured 2026-10-27 on branch `reconstruction`).
  History: 189 at the pre-reconstruction baseline (`ebaac9f`) -> 232 after stages B/D/F -> 521 after stage C -> 632 after stage E (`test_phishing_lexical.py` 92, `test_phishing_golden_replay.py` 19) -> 691 after stage A (`test_scenario_telemetry_contract.py` 59).
- **Frontend Vitest:** **70 passed**, 0 failures across 18 test files; `tsc --noEmit` clean (`strict`, `noUnusedLocals`).
- **Frontend Vite Build:** **1692 modules transformed**, 0 TypeScript errors, bundle generated in 36s.

---

## 4. STAGE C CORRECTIONS - PACKET-LEVEL IDS (2026-10-27)

Section 1 of this file previously asserted *"24 rules complete"* and cited
`test_scenario_evaluation.py`. That citation was wrong: no test module in the
repository imported the IDS engine - searching `backend/tests` for `run_rules`,
`RULE_REGISTRY` or `anomaly_scorer` returned zero hits - so the count of 24 was a
display value, not a verified property. The registry really did contain 24 entries,
but six defects made them weaker than advertised. Each was fixed, and detection
behaviour was proved unchanged before the tests were added.

| # | Finding in the committed code | Correction |
|---|---|---|
| 1 | No per-rule `version`, `category`, `inputs`, `matching` or `weight` contract; fields existed only where a renderer happened to read them. | Every rule declares the full contract and `_register()` raises at import time if any field is missing or empty; `registry_summary()` derives counts from the registry itself. |
| 2 | `THR-PORT-SCAN.window_seconds` (and the other window fields) were declared but never read - matching used whole-stream statistics. | Real sliding-window helpers (`_window_max_distinct`, `_window_peak_count`, `_window_max_count`, `_window_peak_bytes_per_sec`) honour each rule's `window_seconds`, with a documented whole-stream fallback for captures shorter than the window. |
| 3 | `ST-LATERAL` compared against the *registry default* bandwidth ceiling, so an operator override of `THR-BANDWIDTH` could not influence it. | `StreamContext.thresholds()` resolves effective overrides, and dependent rules read the effective value; a regression test pins the coupling. |
| 4 | Packets were indexed with raw `p["..."]`, so one malformed record raised `KeyError` and aborted the whole analysis. | `PACKET_REQUIRED_FIELDS` + `_packet_problem()`: unusable records are skipped and reported (`skipped`, `accepted_count`) while the rest of the stream still evaluates. |
| 5 | Threshold and stateful hits carried `matched_packets=[]` - a detection with no evidence. | `_evidence()` / `_make_hit()` attach packet indices and rendered evidence records (bounded by `_EVIDENCE_LIMIT`), plus `explanation`, `inputs_used` and `category`/`version` on every hit. |
| 6 | Nothing proved the 15/4/5 split, and a rule could be registered without a matcher. | `_MATCHERS` dispatch table with an import-time guard, `RULE_POSITIVES` coverage table asserted equal to `KNOWN_RULE_IDS`, and one parametrized positive + benign-negative + boundary case per rule id. |

**Non-regression proof.** Before and after the rewrite, the same 378 generated
streams (42 catalog attacks x {10, 20, 60} packets x {low, medium, high} volume) were
compared: **0 differing detections, 0 differing rule scores**. The comparison ran the
previously committed engine loaded from git (`git show 591e147:backend/app/services/ids/rules_engine.py`)
against the rebuilt one. The outcome is now *retained* as a lock file
(`backend/tests/data/ids_detection_golden.json`) enforced by
`backend/tests/test_ids_golden_replay.py`, regenerable only deliberately via
`python tests/regenerate_ids_golden.py`.

**Claims kept honest (see `REQUIREMENTS_TRACEABILITY.md` section 3):** the four anomaly
scorers are declared deterministic proxies over exactly 14 packet features - the module
contains no fitting, no ML library and no trained-model metric; `pipeline.live_traffic_capture`
is `False` in every analysis response because no authorized live ingestion path exists; and
benign high-volume traffic is recorded as tripping `THR-CONN-RATE` rather than being reported
as a clean-benign case.

---

## 5. STAGE E CORRECTIONS - LEXICAL PHISHING (2026-10-27)

Section 1 of this file described the phishing scorer as a *"pure stdlib offline fallback"*
verified by `test_phishing_detector.py` (14 tests). The fallback existed, but the module was a
958-line monolith whose behaviour did not match the label: a per-match keyword weight could
push confidence to **2.0** on a 0-1 scale, malformed hosts crashed with interpreter text, a
single bad link inside an email body produced **HTTP 500**, and the UI advertised a
"URL Reputation (VirusTotal)" card and an "ML Classification" block for a project that has
**no** reputation client, API key or phishing model. Each item was measured before it was
changed.

| # | Finding in the committed code | Correction |
|---|---|---|
| 1 | Weights existed only as inline literals inside the scoring function; nothing could enumerate or validate them. | `app/services/phishing/contract.py` holds a declarative registry (`id`, `category`, `version`, `weight`, `weight_kind`, `inputs`, `matching`, `severity`, `predicate`, `mitre`) validated at import time: 10 core indicators plus 2 extended (redirection, suspicious TLD), with `provenance()`/`UNCALIBRATED_NOTE` served by `GET /api/detect/phishing/indicators`. |
| 2 | `rule_suspicious_keywords` added its weight once **per matched token** - measured maximum contribution 2.0. | Every indicator is capped at `MAX_SINGLE_INDICATOR_CONTRIBUTION = 0.60` before summing, the total is capped at 0.99 and quantised to 4 decimals; measured post-change maximum contribution is exactly 0.60. |
| 3 | `int(port)` and `urlsplit` raised raw `ValueError`/`Invalid IPv6 URL`; whitespace, NUL, NBSP, bidi overrides and bad host labels were parsed into a meaningless host and **scored anyway**. | A single `MalformedURLError` (a `ValueError` subclass, so old callers still work) with a declared `reason` from a closed set; 19 hostile inputs are rejected, 11 of which were previously scored, and the routers turn the reason into a stable HTTP 400 `detail` string. |
| 4 | Embedded-link analysis in email/spear scorers let `ValueError` escape the endpoint. | Per-link guard: rejected links are returned in `links_analysis.skipped_links` / `link_analysis.skipped` with their reason, so one bad link degrades the result instead of killing the request. |
| 5 | A dead reputation cache, unused `httpx`/`os`/`base64`/`time`/`unquote` imports and a default `tldextract` constructor that downloads publicsuffix.org. | Package split into `contract.py`, `url_features.py`, `scorer.py`, `email_scorer.py`, `spear_scorer.py` behind a compatibility façade; `TLDExtract(suffix_list_urls=())` pins the bundled snapshot; the suite scores the corpus with sockets disabled and a source scan asserts no HTTP/DNS client is imported. |
| 6 | No record of what the rewrite changed. | 66 URLs / 6 emails / 2 spear messages are scored before and after: the immutable pre-change record (`phishing_lexical_baseline_pre_stage_e.json`, including its crashes) and the current lock (`phishing_lexical_golden.json`) are replayed by `test_phishing_golden_replay.py`. |

**Measured non-regression proof.** Over the common corpus: **5** URLs flipped to detection
(decimal/octal/overflowing-dotted IPv4, trailing-dot IP, IDN homograph), **0** pre-existing
detections were lost, and the 4 real legitimate URLs the scorer gets wrong (0.95/0.75 phishing,
0.60/0.40 suspicious) are pinned rather than tuned away. The regeneration tool is deliberately
named `regenerate_phishing_golden.py` - **no** `test_` prefix, so pytest can never rewrite a lock.

**Claims kept honest:** there is no reputation provider and no phishing ML model in this
project; the page now says "Not implemented - no lookup was performed" and "No machine-learning
model is used here", renders every weight, cap and threshold from the served registry, and
prints a plain error if that registry cannot be read instead of inventing fallback numbers.

---

## 6. STAGE A CORRECTIONS - CONTROLLED SYNTHETIC TELEMETRY (2026-10-27)

Section 1 listed the Attack Scenario Studio compiler as working. The schema, the validators
and the compiler were real, but three of the six properties Section A requires (deterministic
seeds, independent ground truth, schema validation, provenance, replay, documentation-only
identifiers) were asserted in prose while the code quietly undermined them.

| # | Finding in the committed code | Correction |
|---|---|---|
| 1 | `compiler._build_auth_event` derived the **observable** `event_type` from `ground_truth_label` (`failed_authentication` if label 1 else `baseline_login`, and `status` followed it), under a comment claiming it did not leak the label. It did: the label and a detector-visible field were the same fact, so any model trained on the compiled dataset could recover ground truth from one column. | The author must declare `features.event_type`; the compiler raises `CompilationError` rather than guessing, and `validate_scenario_feasibility` reports a repairable `missing_observable_event_type` violation first. Proved by a label-flip test: changing only the label leaves the payload byte-identical. |
| 2 | The `label_leakage` validator compared `ground_truth_source.value` against `rule_output`/`ml_prediction`/`detection_score` - values the closed `GroundTruthSource` enum can never hold - so the guard could never fire. | Replaced with reachable checks: feature keys that name the label (`ground_truth_label`, `is_attack`, ...) and auth templates missing an observable event type. The closed enum itself is now the tested protection against a detector-derived label source. |
| 3 | Every network event without an explicit `raw_signature` was stamped `ET SCAN Possible Nmap User-Agent Observed`, i.e. a vendor scan signature on *any* undeclared event, benign baseline included. | Undeclared events carry the explicit `SYNTHETIC no-signature-declared` marker, and the validator warns (`no_declared_signature`, `no_declared_dest_port`) instead of filling the gap. |
| 4 | `evaluator._parse_ts` fell back to `datetime.now()` for a missing or unparsable timestamp, so a corrupted dataset silently replayed as "traffic that happened just now". | Raises `ReplayError` naming the event index; a replay never invents time. |
| 5 | Determinism, replay and identifier safety had no tests: only a single two-call equality check existed for one category. | `tests/test_scenario_telemetry_contract.py` (59 tests) and a 9-case lock (`tests/data/scenario_telemetry_golden.json`) generated by `tests/regenerate_scenario_telemetry_golden.py` - deliberately not named `test_*`, so a suite run cannot rewrite the lock. |
| 6 | The `seed` field's real scope was unstated, so "deterministic seeded telemetry" could be read as "different seeds give different data". | Measured and locked: for a fully declared spec two different seeds compile byte-identically (deliberate - nothing is random); the seed only reaches telemetry through undeclared-identifier fallbacks, where seed 101 and seed 7 do produce different destinations. Both halves are asserted. |

**Measured properties.** Recompilation is byte-identical in-process and in two fresh interpreters
with different `PYTHONHASHSEED`; every timestamp derives from the fixed 2024-01-01T00:00Z epoch;
flipping `ground_truth_label` changes zero bytes; every emitted IP/host/URL across the corpus is
RFC5737, RFC1918 or a reserved TLD; and the dataset row carries generator version, dataset role,
the preserved plan (with its labels) and a SHA-256 of the prompt - never the prompt itself.

**Claims kept honest:** (a) the seed's scope is narrow, as above; (b) the Studio's precision/
recall/F1 are label-set intersection figures, not per-event classification, and are documented as
such rather than reported as accuracy; (c) provenance that a proposal could otherwise claim for
itself (source, generator version) is overwritten authoritatively by the pipeline.


