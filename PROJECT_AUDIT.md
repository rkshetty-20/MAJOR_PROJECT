# PROJECT_AUDIT.md — AOD-IPS Complete Codebase Audit & Implementation Report

*Generated: 2026-10-24 | Inspector & Engineer: Antigravity Full-Stack Engineering Agent*

*Stage F (2026-10-27): the audit sources `AOD-IPS_Research_Paper.pdf` and `Phase2_Review_Presentation.pptx` were located outside the workspace, extracted and read, and the implementation was re-checked against them. Section 7 records what that changed.*

---

## 1. COMPONENT STATUS SUMMARY (All Verified)

### Backend — FastAPI (Python)

| Component | File | Status | Verification |
|---|---|---|:---:|
| Health endpoint `/health` | `app/main.py` | ✅ Working | Verified |
| 10-scenario catalog | `app/services/simulation_service.py` | ✅ All 10 scenarios complete | `test_simulation.py::test_11` |
| Synthetic simulation engine | `app/services/simulation_service.py` | ✅ Working | `test_simulation.py::test_02-07` |
| Rule-based detection (9 behavioral rules) | `app/services/rule_engine.py` | ✅ Working; the nine paper confidences are declared once in `RULE_CONFIDENCES` (plus one documented extension rule) | `test_rule_engine.py` (12 tests, incl. `test_rule_engine_confidences_match_paper_table`) |
| Phishing URL lexical scorer (10 registered indicators, per-indicator cap 0.80) | `app/services/phishing/` (façade: `app/services/phishing_detector.py`) | ✅ Declared lexicon, offline by construction, self-describing | `tests/test_phishing_lexical.py` (93), `tests/test_phishing_golden_replay.py` (19), `test_phishing_detector.py` (14), `test_phishing_suite.py` (15) |
| Packet-level IDS (24 rules: 15 sig, 4 thr, 5 stateful) | `app/services/ids/rules_engine.py` | ✅ 24 rules, each contract-validated and individually tested | `tests/test_ids_rules.py` (148), `tests/test_ids_golden_replay.py` (378 locked streams) |
| Packet anomaly proxies (4 deterministic scorers x 14 features) | `app/services/ids/anomaly_scorer.py` | ✅ Deterministic proxies, explicitly not trained models | `tests/test_ids_anomaly.py` (135) |
| Random Forest port-scan ML | `app/services/ml_engine.py`, `ml/registry.py`, `ml/features.py` | ✅ Trained, versioned, provenance-attested | `test_ml_model_lifecycle.py` (37) |
| Risk fusion engine (0-100 score) | `app/services/risk_engine.py` | ✅ Implements eq. (1)-(3) incl. the Section IV-E `max(r, c)` de-duplication | `test_risk_engine.py` (6), `test_simulation.py::test_09` |
| HMAC-SHA-256 evidence integrity | `app/services/integrity_service.py` | ✅ Working | `test_integrity_service.py` (11) |
| Hash chain (per-session) | `app/models/models.py` | ✅ Working | After-insert listener |
| Database persistence (SQLite/SQLAlchemy) | `app/database.py` + models | ✅ Working | Full test suite |
| Simulation history endpoint `/api/simulation/history` | `app/routers/simulation.py` | ✅ Working | `test_simulation.py::test_21_simulation_history_endpoint` |
| Dynamic scenario replay orchestrator | `app/services/simulation_service.py` | ✅ Working | `test_simulation.py::test_22_dataset_replay_dynamic_scenario` |
| Simulation-outcome adaptive recommendation | `app/routers/simulation.py` | ✅ Working | `test_simulation.py::test_20_simulation_outcome_adaptive_recommendation` |
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

- **Backend Pytest:** **694 passed**, 0 failures across 29 test modules (measured 2026-10-27 on branch `reconstruction`, after stage F).
  History: 189 at the pre-reconstruction baseline (`ebaac9f`) -> 232 after stages B/D/F -> 521 after stage C -> 632 after stage E (`test_phishing_lexical.py` 92, `test_phishing_golden_replay.py` 19) -> 691 after stage A (`test_scenario_telemetry_contract.py` 59) -> 694 after stage F (`+2` risk/phishing paper-bound tests, `+1` rule-confidence table test; `test_phishing_lexical.py` is now 93 and `test_rule_engine.py` 12).
- **Frontend Vitest:** **72 passed**, 0 failures across 18 test files; `tsc --noEmit` clean (`strict`, `noUnusedLocals`).
- **Frontend Vite Build:** **0 TypeScript errors**, exit code 0, built in 9.7s on the stage-F tree (an earlier stage-E measurement of the same command produced 1692 modules in 24.9s). Vite reports one chunk above its 500 kB advisory limit (`assets/index-*.js`, 609 kB / 155 kB gzipped) - an advisory warning, not an error.

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
detections were lost, and the 4 real legitimate URLs the scorer gets wrong (0.99/0.75 phishing,
0.60/0.40 suspicious - re-measured in stage F after the cap correction) are pinned rather than
tuned away. The regeneration tool is deliberately named `regenerate_phishing_golden.py` - **no**
`test_` prefix, so pytest can never rewrite a lock.

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

---

## 7. STAGE F CORRECTIONS - CHECKED AGAINST THE PAPER AND THE REVIEW DECK (2026-10-27)

Earlier stages could only audit against a directive, because both authoritative documents were
absent from the workspace. They are not absent: `C:\Users\Roshan Kumar Shetty\Downloads\`
contains `AOD-IPS_Research_Paper.pdf` (6 pages) and `Phase2_Review_Presentation.pptx`
(18 slides), plus the original `final-year-2.zip`. Both documents were extracted to text and read
in full, so this stage is the first one in which requirements can be classified as
*paper-verified* rather than *directive-derived*. The full classification is in
`REQUIREMENTS_TRACEABILITY.md` section 4.

Every numeric claim in the paper was then checked against the code: the ten scenarios and their
trigger conditions (Table I), the nine rule confidences (Table I), the 15/4/5 packet-rule split
(Table II), the four anomaly scorers over 14 features, the Random Forest's 100 trees / depth 6 /
five features, the ten phishing weights with cap 0.99 and threshold 0.65, equations (1)-(3), the
HMAC chain, the trainee-engine thresholds, the F1 > 0.85 gate with ≥10 examples, ≥2 per class and
a stratified 75/25 split, "more than 50 endpoints in 12 routers" (measured 70 declared route handlers in
12 routers; `/openapi.json` documents 68 of them because `chat.py` hides two legacy `/chat`
aliases with `include_in_schema=False`) and "16 tables" (measured 16). All of those held. Four
things did not.

| # | Finding | Correction |
|---|---|---|
| 1 | **Risk fusion double-counted.** `compute_risk_score` summed `r` and `c` even when the rule engine and the ML model agreed on the same label, and its own comment claimed "the paper sums all five terms directly". The paper says the opposite: "When rule and ML agree, only the larger of r and c is kept to avoid double counting" (§IV-E). Consequences: an agreeing port scan scored **100/CRITICAL** where the paper states that "an agreeing port-scan detection with the maximum severity term would reach **60**, the lowest HIGH score" (§V-A), and the paper's "rule-only sessions cannot exceed 80" cap was meaningless. Three tests had been written to enforce the invented behaviour ("terms are never suppressed"). | `r` and `c` are now replaced by `max(r, c)` whenever `agreed_labels` is non-empty; the agreement bonus `a` is still added. Both raw values are persisted in `terms_pre_suppression` and the decision in `double_counting_suppression`, and the legacy integer keys carry the *effective* values so a UI that adds the cards up reaches the persisted score. Three tests corrected, and `test_paper_double_counting_boundaries` now asserts the paper's 60/HIGH and 80/HIGH bounds directly. |
| 2 | **The phishing per-indicator cap contradicted Fig. 7.** The cap was 0.60, so a keyword-only URL contributed at most 0.60 and could never cross the 0.65 threshold: measured, 3, 4 and 6 credential tokens all scored exactly 0.60 ("suspicious"). The paper (§IV-D + Fig. 7) says four tokens (4 x 0.20 = 0.80) are enough to flag a short HTTPS URL. | Cap raised to **0.80** - the smallest guard that reproduces the published arithmetic while still stopping one count-based indicator from reaching the 0.99 ceiling alone. `test_paper_fig7_four_suspicious_tokens_are_flagged` asserts 3 tokens => 0.60/suspicious and 4 => 0.80/phishing on the real scorer. Re-measured false positives: both affected legitimate URLs move 0.95 -> 0.99 with **unchanged verdicts** (they were already in the phishing tier); the other two are unchanged. The 74-case lock was regenerated and reported `changed cases: 0`, i.e. the locked corpus never exercised a four-token URL - which is why the defect survived stage E. |
| 3 | **The risk waterfall was blank in live mode.** `PortScanRisk` did `JSON.parse(liveData.risk.contributing_factors)`, but the investigation endpoint serialises that field as an object, so the parse threw into a `catch` and the component drew zero rows; the unit test passed only because it mocked a JSON *string*. `AttackAnatomy` rendered every key of the same object, so it would have printed `+[object Object]`, the formula text and the label array as if they were score contributions. | New `readRiskTerms()` accepts object or string, restricts the waterfall to the five formula terms in equation order, and drops zero values; both components use it. Two new vitest cases cover the real API shape and the metadata-exclusion rule. |
| 4 | **The rule count was off by one against the paper.** Table I lists nine rules; the engine emits ten labels, because `multiple_failed_logins_detected` (≥5 failures per source/account in 300 s, confidence 0.88) duplicates the paper's `sustained_attack_no_compromise` (≥4, no later success, 0.85) at a different threshold. The 0.88 confidence exists nowhere in the paper, and the extra label raises the multi-signal term `m` by 15 whenever both fire. | Not removed - deleting a tested detection rule is the author's call, not a silent cleanup - but made explicit: the nine paper confidences now live in `RULE_CONFIDENCES` with `PAPER_RULE_LABELS` naming them, the extension carries a comment saying it is not a reported result, and `test_rule_engine_confidences_match_paper_table` pins the split between the two sets. |

**Deck claims that the code cannot support (documentation correction, nothing to implement).**
`Phase2_Review_Presentation.pptx` presents XGBoost as a deployed model (slides 2, 9, 13), quotes
"XGBoost 94.6% / 93.8% / 94.1%" and "Random Forest 91.8% / 90.4% / 89.7%" (slide 14), and says
datasets were collected from Kaggle (slide 13). The repository contains **no XGBoost** (a test
asserts the string is absent from the ML engine), **no public dataset** (everything is synthetic),
and **no such metrics** - the only measured figures are `accuracy/precision/recall/f1 = 1.0` on a
synthetic hold-out with 500 samples, stored with `data_source: synthetic` in
`ml/models/port_scan_rf_metrics.json`. The deck's clone/smishing modules likewise do not exist;
URL, email and spear-phishing scorers do. The paper supersedes the deck, and these numbers must
not be presented as measured results in the review.

**Verification on the stage-F tree.** Backend `694 passed` (from 691); frontend `18 files /
72 tests passed` (from 70); `tsc --noEmit` exit 0; `vite build` exit 0 with the pre-existing
500 kB chunk advisory. No test was deleted or skipped to reach those numbers: the three risk
assertions that encoded the old behaviour were corrected, and five tests were added. Committed
as `e28c1be` on `reconstruction`, working tree clean.

**The application was also started, not just tested.** `uvicorn app.main:app --host 127.0.0.1
--port 8011` came up without an import error, `GET /api/system/config` returned `200` with
`{"health": {"database": "connected", "api": "online"}}`, `integrity.hmac_configured: true`
and `detection.phishing_threshold: 0.65` straight from the live process, and `GET /openapi.json`
served 68 operations over 68 paths. The process was then stopped.

**Still open, deliberately.** (a) The paper's figures 1-8 are raster images, so their numbers were
verified through the prose and tables that describe them, not by reading the images. (b) The
tenth rule, the presentation's unsupported metrics and the uncalibrated phishing threshold are all
author decisions and are documented rather than silently changed. (c) Persisted `RiskScore` rows
in the shipped `aod_ips.db` were computed under the old formula; they are refreshed the next time
a session is scored, and no bulk rewrite of the demo database was performed.



