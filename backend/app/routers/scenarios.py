import json
from typing import List, Optional
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scenario, ScenarioCategory, DifficultyLevel

router = APIRouter(prefix="/scenarios", tags=["Scenarios"])


# ==========================================
# Pydantic Schemas
# ==========================================

class ScenarioResponse(BaseModel):
    id: int
    name: str
    category: ScenarioCategory
    description: Optional[str] = None
    difficulty: DifficultyLevel
    config_json: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class SeedResponse(BaseModel):
    message: str
    seeded_count: int
    scenarios: List[ScenarioResponse]


# ==========================================
# Endpoints
# ==========================================

@router.get("", response_model=List[ScenarioResponse], summary="List all scenarios")
@router.get("/", response_model=List[ScenarioResponse], include_in_schema=False)
def list_scenarios(db: Session = Depends(get_db)) -> List[Scenario]:
    """Retrieve all attack scenarios from the database."""
    scenarios = db.query(Scenario).all()
    return scenarios


@router.post("/seed", response_model=SeedResponse, status_code=status.HTTP_201_CREATED, summary="Seed standard scenarios")
def seed_scenarios(db: Session = Depends(get_db)) -> SeedResponse:
    """
    Inserts or updates the 5 standard attack scenarios with realistic configurations:
    - port_scan (with structured target/attacker, behavioral rules, correct actions & scoring)
    - ssh_brute_force
    - web_probing
    - sql_injection
    - phishing
    """
    seed_data = [
        {
            "name": "Port Scan Attack",
            "category": ScenarioCategory.PORT_SCAN,
            "description": "Simulates reconnaissance port scanning with high port diversity across internal subnets.",
            "difficulty": DifficultyLevel.EASY,
            "config_json": json.dumps({
                "target_ip": "192.168.56.20",
                "attacker_ip": "192.168.56.10",
                "expected_suricata_signatures": [
                    "ET SCAN Nmap Scripting Engine User-Agent Detected",
                    "ET SCAN Possible Nmap User-Agent Observed",
                ],
                "behavioral_rule": {
                    "name": "high_port_diversity",
                    "description": "More than 15 distinct destination ports from one source IP within 10 seconds",
                    "threshold_ports": 15,
                    "window_seconds": 10,
                },
                "correct_responses": ["isolate_host", "block_source_ip"],
                "incorrect_responses": ["ignore", "restart_service"],
                "scoring": {
                    "correct_response_points": 50,
                    "fast_response_bonus_seconds": 30,
                    "fast_response_bonus_points": 20,
                },
            }),
        },
        {
            "name": "SSH Brute Force Attack",
            "category": ScenarioCategory.SSH_BRUTE_FORCE,
            "description": "Simulates high-velocity dictionary password spraying and authentication attempts against an internal SSH daemon.",
            "difficulty": DifficultyLevel.MEDIUM,
            "config_json": json.dumps({
                "target_ip": "192.168.56.20",
                "attacker_ip": "192.168.56.15",
                "service": "ssh",
                "port": 22,
                "rate_per_sec": 10,
                "threshold_attempts": 50,
                "correct_responses": ["block_source_ip", "disable_password_auth"],
                "incorrect_responses": ["ignore", "restart_ssh"],
                "scoring": {
                    "correct_response_points": 50,
                    "fast_response_bonus_seconds": 30,
                    "fast_response_bonus_points": 20,
                },
            }),
        },
        {
            "name": "Web Application Directory Probing",
            "category": ScenarioCategory.WEB_PROBING,
            "description": "Simulates automated URI fuzzing, sensitive path enumeration (e.g. .env, /admin), and API endpoint discovery.",
            "difficulty": DifficultyLevel.EASY,
            "config_json": json.dumps({
                "target_ip": "192.168.56.20",
                "attacker_ip": "192.168.56.30",
                "targets": ["/admin", "/.env", "/backup.tar.gz", "/api/v1/metrics"],
                "user_agent": "gobuster/3.1",
                "correct_responses": ["rate_limit_ip", "block_source_ip"],
                "incorrect_responses": ["ignore", "reboot_server"],
                "scoring": {
                    "correct_response_points": 50,
                    "fast_response_bonus_seconds": 30,
                    "fast_response_bonus_points": 20,
                },
            }),
        },
        {
            "name": "SQL Injection Exploit",
            "category": ScenarioCategory.SQL_INJECTION,
            "description": "Simulates structured SQL injection exploitation attempting union-based data extraction and database authentication bypass.",
            "difficulty": DifficultyLevel.HARD,
            "config_json": json.dumps({
                "target_ip": "192.168.56.20",
                "attacker_ip": "192.168.56.40",
                "injection_type": "UNION_BASED",
                "payload": "' UNION SELECT null, username, password_hash FROM admin_users --",
                "target_param": "id",
                "correct_responses": ["enable_waf_rule", "sanitize_input_params"],
                "incorrect_responses": ["ignore", "drop_table"],
                "scoring": {
                    "correct_response_points": 50,
                    "fast_response_bonus_seconds": 30,
                    "fast_response_bonus_points": 20,
                },
            }),
        },
        {
            "name": "Targeted Spear Phishing Campaign",
            "category": ScenarioCategory.PHISHING,
            "description": "Simulates a deceptive email dispatch containing credential harvesting links and weaponized document attachments.",
            "difficulty": DifficultyLevel.MEDIUM,
            "config_json": json.dumps({
                "target_ip": "192.168.56.20",
                "attacker_ip": "192.168.56.50",
                "template": "HR_payroll_update",
                "harvesting_url": "https://portal-auth-check.internal.net/login",
                "correct_responses": ["quarantine_email", "revoke_user_tokens"],
                "incorrect_responses": ["ignore", "forward_all"],
                "scoring": {
                    "correct_response_points": 50,
                    "fast_response_bonus_seconds": 30,
                    "fast_response_bonus_points": 20,
                },
            }),
        },
        {
            "name": "Sustained Failed Logins",
            "category": ScenarioCategory.MULTIPLE_FAILED_LOGINS,
            "description": "Simulates a burst of consecutive invalid credentials exceeding velocity thresholds, ending without a successful login.",
            "difficulty": DifficultyLevel.EASY,
            "config_json": json.dumps({
                "target_ip": "192.168.56.20",
                "attacker_ip": "198.51.100.12",
                "service": "web",
                "threshold_attempts": 20,
                "correct_responses": ["block_source_ip", "monitor", "rate_limit_ip"],
                "incorrect_responses": ["force_password_reset", "isolate_host", "notify_user"],
                "scoring": {
                    "correct_response_points": 30,
                    "fast_response_bonus_seconds": 30,
                    "fast_response_bonus_points": 10,
                },
            }),
        },
    ]

    existing_scenarios = {s.category: s for s in db.query(Scenario).all()}
    new_items: List[Scenario] = []
    updated_items: List[Scenario] = []

    for item in seed_data:
        if item["category"] not in existing_scenarios:
            scenario = Scenario(
                name=item["name"],
                category=item["category"],
                description=item["description"],
                difficulty=item["difficulty"],
                config_json=item["config_json"],
            )
            db.add(scenario)
            new_items.append(scenario)
        else:
            scenario = existing_scenarios[item["category"]]
            scenario.name = item["name"]
            scenario.description = item["description"]
            scenario.difficulty = item["difficulty"]
            scenario.config_json = item["config_json"]
            updated_items.append(scenario)

    db.commit()
    for item in new_items:
        db.refresh(item)
    for item in updated_items:
        db.refresh(item)

    all_scenarios = db.query(Scenario).all()
    message = (
        f"Seeded {len(new_items)} new scenario(s) and synchronized {len(updated_items)} existing scenario(s)."
    )

    return SeedResponse(
        message=message,
        seeded_count=len(new_items) + len(updated_items),
        scenarios=[ScenarioResponse.model_validate(s) for s in all_scenarios],
    )
