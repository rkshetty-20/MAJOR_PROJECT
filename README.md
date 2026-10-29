# AOD-IPS: Adaptive Offensive–Defensive Intrusion and Phishing Simulation Framework

AOD-IPS is an academic and operational cybersecurity simulation framework designed to generate controlled synthetic attack telemetry and process it through multi-tiered detection, machine learning anomaly classification, explainable risk fusion, cryptographic evidence integrity, and interactive investigation.

---

## 2. Problem Statement

Modern authentication and enterprise perimeters face diverse, blended threats:
- brute-force and credential stuffing attacks
- suspicious and impossible-travel logins
- new device anomalies and off-hours access
- URL phishing campaigns (open redirects, lookalike domains, obfuscation)
- deceptive email phishing (brand spoofing, urgency cues, weaponized links)
- targeted spear phishing (executive impersonation, BEC wire fraud, payroll diversion)
- network reconnaissance and port scans
- multi-signal composite intrusion behavior

Individual signals may be insufficient to determine if an attack is underway. AOD-IPS addresses this by fusing telemetry, deterministic rules, lexical heuristics, and Random Forest classification to support grounded security investigations.

---

## 3. Objectives

- Generate controlled synthetic security telemetry.
- Detect suspicious behavioral patterns.
- Combine multiple security signals.
- Calculate a unified risk score.
- Persist investigation evidence.
- Visualize attack progression.
- Provide event-level investigation.
- Provide grounded AI-assisted security analysis.

---

## 4. Key Features

### Controlled Attack Simulation
The system includes 10 synthetic scenarios:
1. Brute Force
2. Credential Stuffing
3. Suspicious Login
4. Impossible Travel
5. New Device
6. Phishing URL
7. Port Scan
8. Anomalous Login Time
9. Multiple Failed Logins
10. Combined Multi-Signal

*Note: Simulations generate safe synthetic telemetry data only and do not perform real network attacks or real-world exploitation.*

### Behavioral Detection
Detection decisions are based strictly on telemetry analysis rather than trusting simulation scenario labels. Detection rules analyze the raw event data to trigger alerts for behavior such as:
- brute-force behavior
- credential stuffing
- suspicious login
- impossible travel
- new device
- anomalous login time
- phishing URL telemetry

### Comprehensive Phishing Detection Suite
The platform integrates three complementary, explainable phishing detection modules operating in offline mode:

1. **URL Phishing Detection (`POST /api/detect/url` & `POST /api/detect/phishing`)**:
   - Analyzes lexical and structural URL attributes: HTTPS protocol usage, IP-based hostnames, URL length, path depth, character entropy, and suspicious symbol counts (`@`, `-`, `//`, `%`).
   - Detects homograph / Punycode attacks (`xn--`) and misleading subdomains (e.g., `login.paypal.com.scammer.com`).
   - Identifies high-risk TLDs and open-redirect parameters (`url=`, `redirect=`, `next=`, `return_to=`).
   - Classifies URLs into multi-tier ratings: **Legitimate** (< 0.35), **Suspicious** (0.35–0.64), and **Phishing** (≥ 0.65).

2. **Email Phishing Detection (`POST /api/detect/email`)**:
   - **Sender Spoofing & Discrepancies**: Flags brand display-name impersonation (e.g. PayPal, Microsoft, Apple, Google, Banks) originating from unauthorized domains, public free webmail (`@gmail.com`, `@yahoo.com`) used for corporate alerts, and `Reply-To` vs `From` mismatches.
   - **Content & Psychological Coercion**: Detects artificial urgency / fear pressure ("account suspended within 24 hours", "immediate action required"), generic greetings ("Dear Customer"), and credential-harvesting calls to action.
   - **Embedded Link & Attachment Analysis**: Extracts all URLs from email content, evaluates threat levels across each hyperlink, detects anchor-text destination deception, and flags executable / dual-extension attachment indicators (`.pdf.exe`, `.scr`, `.vbs`).

3. **Spear Phishing Detection (`POST /api/detect/spear-phishing`)**:
   - **Reconnaissance & Personalization**: Evaluates target tailoring by cross-referencing recipient name, organizational role, and corporate department.
   - **Executive / Leadership Impersonation**: Detects CEO/CFO/President impersonation from unverified external addresses, coercive authority pressure, and out-of-band communication suppression ("in an all-day meeting, do not call, handle via email").
   - **High-Risk Request Vectors**: Pinpoints Business Email Compromise (BEC) wire transfers, payroll / direct deposit redirection, employee W-2 / PII data exfiltration, gift card purchase scams, and approval process circumvention.
   - Generates actionable, role-tailored defensive countermeasures.

### Risk Fusion
Risk is dynamically calculated server-side based on the aggregated detection context.

**Formula:**
```text
rule_term          = 40 if the rule engine fired any label, else 0
multi_signal_bonus = min(30, 15 × (distinct_rule_labels − 1))
ml_confidence_term = 40 × top ML confidence
agreement_bonus    = 10 if a rule label and an ML label coincide, else 0
severity_term      = clamp(10 × (4 − average_severity) / 3, 0, 10)

raw_total  = rule_term + multi_signal_bonus + ml_confidence_term
             + agreement_bonus + severity_term
final_score = int(round(clamp(raw_total, 0, 100)))
```

**Double-counting rule (paper Section IV-E):** "When rule and ML agree, only the larger of r and
c is kept to avoid double counting." So whenever at least one label is produced by *both* the
rule engine and the ML model, `rule_term` and `ml_confidence_term` are replaced by `max(r, c)`
before the sum; the agreement bonus `a` is still added. Both raw values remain visible under
`terms_pre_suppression` in the API payload. Two consequences, both asserted by
`tests/test_risk_engine.py`: an agreeing port scan at maximum severity scores exactly **60
(HIGH)**, and a rule-only session cannot exceed **80**, so CRITICAL requires rule-ML agreement.

**Multi-signal bonus:**
```text
(distinct_rule_labels - 1) × 15  (maximum of 30)
```

**Risk bands:**
- **LOW:** <30
- **MEDIUM:** 30–59
- **HIGH:** 60–84
- **CRITICAL:** 85–100

### SOC Dashboard
A complete UI for security monitoring:
- Security Overview
- Detection Pipeline
- Risk Distribution
- Attack Timeline
- Recent Security Events
- Event Details

### Attack Progression Timeline
The timeline is generated exclusively from persisted database records and uses actual timestamps. Fabricated alert stages are not generated when there is no underlying database record.

**Current persisted timeline stages:**
- `simulation_started`
- `event_generated`
- `suricata_event_generated`
- `detection_triggered`
- `risk_calculated`

### Security Assistant
An integrated AI chat interface for SOC investigation:
- Operates via a backend-only OpenRouter API key.
- The frontend communicates through `/api/chat`.
- Security context can be supplied from actual event telemetry.
- The assistant is explicitly instructed not to fabricate unavailable security information. Missing telemetry should be acknowledged rather than invented.

---

## 5. Adaptive ML Engine (Port Scan)

The framework implements an adaptive machine-learning subsystem strictly for **port-scan detection**, while other detection mechanisms currently use deterministic rules.

### Adaptive Engine Architecture
The subsystem dynamically learns from persisted synthetic network telemetry. Future port-scan inference uses the accepted active model, forming a complete observe-and-adapt feedback loop.

```text
Observe (Collect synthetic IDS telemetry)
        ↓
Learn (Extract features & independent labels)
        ↓
Evaluate (Train candidate on holdout set)
        ↓
Decide (Gate vs active model threshold)
        ↓
Activate (Version model & deploy to inference)
        ↓
Detect (Future port-scan inference)
        ↓
Feedback (New telemetry data)
```

### Lifecycle & Mechanics
- **LearningExample Pipeline**: The system tracks Suricata `eve.json` alerts.
- **Data Quality Controls**: The system validates class distribution and strictly enforces minimum sample counts before training.
- **Feature Extraction**: Five behavioural features, declared once in `ml/features.py::FEATURE_NAMES` and validated for name, order, unit and range before they reach the estimator: `distinct_dest_ports`, `events_per_second`, `distinct_dest_ips`, `avg_severity`, `protocol_diversity`. Ground truth is labeled independently via IDS signatures to eliminate feature/label leakage.
- **Candidate Model Training**: When sufficient new data is gathered, a candidate Random Forest model is trained.
- **Evaluation & Acceptance Gate**: Candidate models are evaluated on held-out data before activation. Model promotion is controlled by an explicit F1-based acceptance gate (`candidate_f1 > 0.85` and `candidate_f1 >= previous_active_f1`).
- **Model Versioning & History**: Accepted models are persisted (e.g. `v_20261007_xyz.joblib`) with their adaptation decisions recorded. A rejected candidate never replaces the active model, and since the reconstruction it is not written to disk at all - the old code path dumped every candidate before the gate, leaving ~100 untraceable `v_*.joblib` files that the registry now refuses to load because they carry no provenance sidecar.
- **Model Rollback**: Operators can roll back inference to any previously accepted model version.
- **Active Model Management**: Future port-scan inference dynamically queries the active model database and uses the accepted version.

### Limitations & Interpretation (F1 = 1.0)
The evaluation uses controlled synthetic data and therefore does not establish real-world generalization. The adaptive port-scan model frequently achieves an F1 = 1.0 on the evaluation dataset used by the prototype. Because the synthetic dataset is deterministic and designed around clear port-scan behaviors, this result is expected within the simulation bounds and should not be interpreted as evidence of a production-ready, flawless classifier.

---

## 6. Architecture

**Frontend:** React + TypeScript + Vite + Tailwind  
**Backend:** FastAPI  
**Database:** SQLAlchemy-backed database (SQLite/PostgreSQL)  
**ML:** Random Forest-based detection where implemented  
**AI:** OpenRouter-compatible LLM API through backend  

**Data Flow:**
```text
Simulation
  → SecurityEvent
      → Rule Engine / ML
          → Detection
              → Risk Engine
                  → RiskScore
                      → REST APIs
                          → SOC Dashboard
                              → Security Assistant
```

---

## 6. Detection Integrity

The detection engine maintains strict data integrity and does not simply trust incoming simulation scenario labels.

For example:
- **Credential stuffing** is detected by observing one source IP making authentication attempts across multiple distinct target accounts within a rapid time window.
- **Suspicious login** is evaluated by comparing the current authentication context against prior authentication behavior, taking into account known devices and known locations.

This ensures a clear distinction between attack profiles, such as differentiating **Brute Force** (one source → repeated attempts against one account) from **Credential Stuffing** (one source → multiple accounts).

---

## 7. Risk Example

**Scenario:** `combined_multi_signal`

**Detections Triggered:**
- `anomalous_login_time_detected`
- `new_device_detected`
- `suspicious_login_detected`
- `brute_force_detected`

**Risk calculation:**
- Rule term = 40
- Multi-signal bonus = 30
- ML contribution = 0
- Agreement bonus = 0
- Severity fallback = 4

**Final score:** 74  
**Risk band:** HIGH

*(This is an example calculation from a tested synthetic simulation run.)*

---

## 8. API Endpoints

### Simulation
- `POST /api/simulation/run`
- `GET /api/simulation/scenarios`
- `GET /api/simulation/{simulation_id}/timeline`

### SOC
- `GET /api/overview`
- `GET /api/events`
- `GET /api/events/{id}`
- `GET /api/detections`
- `GET /api/risk`

### AI
- `POST /api/chat`

---

## 9. Technology Stack

- **Frontend:** React, TypeScript, Vite, Tailwind CSS, Lucide React
- **Backend:** Python, FastAPI, Uvicorn, Pydantic
- **Database:** SQLAlchemy, SQLite
- **Machine Learning:** scikit-learn (Random Forest)
- **AI:** OpenRouter LLM API integration
- **Development Tools:** npm, pip, pytest/unittest

---

## 10. Project Structure

```text
backend/
  app/
    models/
    routers/
    services/
    ml/
    main.py
  tests/

frontend/
  src/
    components/
    api.ts
```

---

## 11. Setup

### Backend

1. Create a virtual environment and activate it:
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Configure the environment variables in `backend/.env`:
   ```env
   OPENROUTER_API_KEY=your_openrouter_api_key_here
   ```
4. Start the FastAPI server:
   ```bash
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

### Frontend

1. Install npm dependencies:
   ```bash
   cd frontend
   npm install
   ```
2. Start the Vite development server:
   ```bash
   npm run dev
   ```

---

## 12. Testing

The project has undergone rigorous automated testing to ensure architectural integrity:

- **Backend:** 694 tests passing across 29 modules (`pytest -q`, 26.8 s).
- **Frontend:** 72 tests passing across 18 files (`vitest run`, 12.9 s).
- **TypeScript:** `tsc --noEmit` exits 0 under `strict` with `noUnusedLocals`.
- **Production build:** `vite build` exits 0, with one large-chunk advisory.

Reproduce them with:

```powershell
cd backend; .\venv\Scripts\python.exe -m pytest -q
cd ..\frontend; npm run test; npm run build   # build runs `tsc && vite build`
```

Testing covers:
- Simulation constraints
- Rule engine logic
- Risk fusion calculation
- Adaptive engine workflows
- Chatbot API grounding and safety
- Timeline stage generation
- Simulation isolation

---

## 13. Security Considerations

- The platform generates synthetic, non-invasive simulations.
- API secrets (like `OPENROUTER_API_KEY`) are backend-only and never leaked to the client.
- Local-development CORS policies are restricted.
- All database access is parameterized via the SQLAlchemy ORM.
- Input bounds are enforced on all simulation generation endpoints.
- Simulation runs are strictly isolated by session/simulation UUIDs.
- API errors are sanitized to prevent internal trace leakage.

**Disclaimer:** The current system is designed as a local academic/demo SOC prototype. Public production deployment would require authentication and authorization (IAM), multi-tenant isolation, stronger operational security, rate limiting, monitoring, and other production controls.

---

## 14. Limitations

- Generates and relies on synthetic attack telemetry.
- Machine Learning accuracy metrics are based entirely on synthetic/test data.
- The system lacks real-world production traffic validation.
- Operates under a local/demo authentication model.
- AI functionality has a strict upstream dependency on the OpenRouter API.
- Production deployment requires IAM and additional security controls.

---

## 15. Future Scope

Potential future work includes:
- Real SIEM/log ingestion from live network interfaces.
- Authenticated multi-user deployment.
- Role-based access control (RBAC).
- Production telemetry connectors (e.g., Elasticsearch, Splunk).
- Richer ML models for anomaly detection.
- Model evaluation using real security datasets.
- Alert management queues.
- Automated response and incident playbooks.
- Production-grade observability and monitoring.

---

## 16. Screenshots

*(Screenshots placeholder - To be added based on deployed UI assets)*

---

## 17. License / Academic Notice

This simulator generates synthetic telemetry primarily for educational and security research purposes.


