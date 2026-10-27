# AOD-IPS Backend

FastAPI backend service for **AOD-IPS**, powered by Python 3.11+, SQLAlchemy 2.x, Uvicorn, and the **FraudGuard Security Assistant** (OpenRouter AI).

---

## Features
- **FastAPI** with CORS preconfigured for the Vite frontend (`http://localhost:5173`).
- **Controlled Attack Simulation Subsystem (`POST /api/simulation/run`)**: 10 safe, synthetic scenarios for demonstrating intrusion detection, anomaly hunting, and threat response without attacking real systems.
- **AI Cybersecurity Chatbot (`POST /api/chat`)**: Integrated with OpenRouter, providing defensive guidance, intrusion analysis, and explainable risk scores without data fabrication.
- **SQLAlchemy 2.x** database engine supporting both SQLite and PostgreSQL.
- **Suricata IDS Ingestion**: Ingests `eve.json` alerts scoped to student learning sessions.
- **Detection Pipeline**: Behavioral sliding-window rule matching and offline-trained Random Forest ML detector.
- **Explainable Risk Fusion**: Combines rule, ML, agreement bonus, and event severity into a transparent 0-100 risk score.
- **Adaptive Engine**: Tracks historical performance and recommends weakest scenario categories with dynamic difficulty adjustment.
- **pydantic-settings** managing environment configuration cleanly.

---

## Directory Structure

```text
backend/
├── app/
│   ├── __init__.py
│   ├── config.py         # Settings & environment variables (pydantic-settings)
│   ├── database.py       # SQLAlchemy engine, SessionLocal, get_db dependency
│   ├── main.py           # FastAPI application entrypoint & CORS middleware
│   ├── models/           # SQLAlchemy ORM models (Scenario, Session, SecurityEvent, Detection, etc.)
│   │   ├── __init__.py
│   │   └── models.py
│   ├── routers/          # API route definitions
│   │   ├── __init__.py
│   │   ├── chat.py       # OpenRouter AI Chatbot route (/api/chat)
│   │   ├── simulation.py # Controlled Attack Simulation & SOC Event routes
│   │   ├── scenarios.py  # Scenario catalog and seeding
│   │   ├── sessions.py   # Simulation lifecycle and detections
│   │   ├── responses.py  # Student mitigations & scoring
│   │   ├── students.py   # Adaptive learning recommendations
│   │   └── db_init.py    # Database initialization trigger
│   └── services/         # Detection, risk, adaptive, simulation, and AI services
│       ├── simulation_service.py # Synthetic attack simulation engine (10 scenarios)
│       ├── chatbot_service.py    # OpenRouter integration & prompt engineering
│       ├── adaptive_engine.py    # Trend-based difficulty and scenario selector
│       ├── risk_engine.py        # Multi-signal risk fusion
│       ├── ml_engine.py          # Random Forest ML detector
│       ├── rule_engine.py        # Behavioral rule detector
│       └── suricata_ingest.py    # eve.json parser
├── ml/                   # Offline ML training scripts and serialized models
├── tests/                # Test suites
│   ├── test_simulation.py
│   ├── test_chatbot.py
│   ├── test_adaptive_engine.py
│   ├── test_risk_engine.py
│   └── test_rule_engine.py
├── .env.example          # Template for environment variables
├── .env                  # Local environment file
├── aod_ips.db            # SQLite database file (generated at runtime)
├── requirements.txt      # Python dependencies
└── README.md             # Backend setup & execution guide
```

---

## Setup & Running

### 1. Prerequisites
- Python 3.11 or higher installed on your system.

### 2. Navigate to the backend directory
```bash
cd backend
```

### 3. Activate the Virtual Environment
- **Windows PowerShell:**
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
- **macOS / Linux:**
  ```bash
  source venv/bin/activate
  ```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 5. Configure Environment
In `backend/.env`:
```env
DATABASE_URL=sqlite:///./aod_ips.db
SURICATA_EVE_PATH=/var/log/suricata/eve.json
OPENROUTER_API_KEY=your_openrouter_api_key_here
OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct:free
```

### 6. Run the Server
```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The API will now be accessible at:
- **Health Check:** [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
- **Chatbot API:** [http://127.0.0.1:8000/api/chat](http://127.0.0.1:8000/api/chat)
- **Interactive Swagger Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## AI Cybersecurity Chatbot API

The chatbot endpoint accepts:
```json
POST /api/chat
{
  "message": "Why was this login flagged?",
  "conversation_history": [
    {"role": "user", "content": "What is brute force?"},
    {"role": "assistant", "content": "Brute force is..."}
  ],
  "security_context": {
    "failed_attempts": 7,
    "risk_score": 87,
    "risk_level": "HIGH",
    "ip_address": "198.51.100.42"
  }
}
```

Or pass `session_id` to automatically extract the live database telemetry from an active or completed simulation session:
```json
POST /api/chat
{
  "message": "Explain what triggered the detections in this session and what I should do.",
  "session_id": 1
}
```

---

## Controlled Attack Simulation Endpoints

- `POST /api/simulation/run` — Run a synthetic attack simulation
  ```json
  {
    "scenario": "brute_force",
    "intensity": "high",
    "num_events": 8,
    "delay_ms": 10
  }
  ```
  Returns simulation summary with events generated, detections triggered, risk score, and attack progression timeline.

- `GET /api/simulation/scenarios` — Catalog of all 10 simulation scenarios.
- `GET /api/overview` — SOC dashboard aggregated metrics.
- `GET /api/events` — Security event log (with query params: `session_id`, `simulation_id`, `risk_level`, `event_type`).
- `GET /api/events/{id}` — Single event telemetry with mitigation advice.
- `GET /api/detections` — Engine detections breakdown.
- `GET /api/risk` — Risk levels distribution.

---

## Running Test Suites

Execute all backend test suites:
```bash
python tests/test_simulation.py
python tests/test_chatbot.py
python tests/test_adaptive_engine.py
python tests/test_risk_engine.py
python tests/test_rule_engine.py
```
