"""Safety and feasibility validation for scenario proposals (Milestone 2).

Separate from the structural schema validation in ``spec.py``. The schema proves
the proposal is *well-formed*; this module proves it is *safe and executable as a
defensive synthetic simulation*.

Two surfaces:
    * ``validate_analyst_request`` — screens the natural-language request before
      we spend any tokens, so we never feed an obviously malicious instruction
      to the LLM or treat it as a real action.
    * ``validate_scenario_safety`` / ``validate_scenario_feasibility`` — audit the
      returned ``ScenarioSpec``: all entities must be clearly synthetic, no
      executable payloads, and feature/timing configs must be internally
      plausible for the category.

Every validator returns a list of ``ValidationViolation`` and never raises for
expected rejections, so callers can present honest, itemized feedback and offer
a supported alternative.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional

from app.services.scenario_simulator.spec import (
    AttackCategory,
    ScenarioSpec,
)


@dataclass
class ValidationViolation:
    code: str
    message: str
    # Where the violation came from, so the UI can point at it.
    location: Optional[str] = None


@dataclass
class ValidationReport:
    violations: List[ValidationViolation] = field(default_factory=list)
    warnings: List[ValidationViolation] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return len(self.violations) == 0

    def to_serializable(self) -> dict:
        return {
            "ok": self.ok,
            "violations": [v.__dict__ for v in self.violations],
            "warnings": [w.__dict__ for w in self.warnings],
        }


# ==========================================
# Analyst-request screening (pre-token safety gate)
# ==========================================

# Phrases that indicate a request to actually attack/execute rather than to
# simulate. Kept intentionally narrow to avoid blocking legitimate defensive or
# educational phrasing.
_UNSAFE_REQUEST_PATTERNS: List[tuple] = [
    (r"\b(exploit kit|deliver malware|execute malware|drop a? ?trojan|ransomware payload)\b", "malware_execution"),
    (r"\b(shell|reverse shell|remote code execution|arbitrary code)\b", "code_execution"),
    (r"\b(rm -rf|del /s|format c:|shutdown -r)\b", "destructive_command"),
    (r"\b(modify|change|add|disable)\b.{0,20}\b(firewall rule|security group|production (control|rule))\b", "production_control_change"),
    (r"\b(send(ing)? (a )?(phishing )?(email|e-mail|sms)|blast(ing)? (out )?emails?)\b", "real_message_delivery"),
    (r"\b(credential[- ]harvest(ing)? page|fake login (page|site)|host a? ?phishing (site|page))\b", "phishing_infrastructure"),
    (r"\b(real credentials|live credentials|production credentials)\b", "real_credentials"),
    (r"\b(scan(ner)? (the |our |my )?(external|public|internet|production) (host|network|ip|subnet|domain))\b", "live_network_scan"),
    (r"\b(nmap|masscan)\b.{0,30}\b(\d{1,3}(\.\d{1,3}){3}|[a-z0-9-]+\.(com|net|org|io))\b", "live_network_scan"),
    (r"\b(ddos|denial of service|flood (the )?(real |production )?(host|site|server))\b", "destructive_action"),
]

# Domains that are unambiguously real/public brand targets in a request.
_REAL_TARGET_HINT = re.compile(
    r"\b(attack|breach|compromise|target|scan)\b.{0,30}\b([a-z0-9-]+\.(com|net|org|gov|edu|io)\b)",
    re.IGNORECASE,
)


def validate_analyst_request(prompt: str) -> ValidationReport:
    """Screen the raw analyst request before generation."""
    report = ValidationReport()
    text = (prompt or "").lower()

    for pattern, code in _UNSAFE_REQUEST_PATTERNS:
        if re.search(pattern, text):
            report.violations.append(
                ValidationViolation(
                    code=code,
                    message=(
                        "The request appears to ask for a real or destructive action. "
                        "FraudGuard only generates safe, synthetic, offline telemetry. "
                        "Rephrase as a simulation of observable behavior."
                    ),
                    location="analyst_request",
                )
            )

    m = _REAL_TARGET_HINT.search(prompt or "")
    if m:
        report.violations.append(
            ValidationViolation(
                code="external_target",
                message=(
                    f"Request references what looks like a real external target '{m.group(2)}'. "
                    "Use clearly synthetic identifiers instead (RFC5737 example IPs or .invalid domains)."
                ),
                location="analyst_request",
            )
        )

    return report


# ==========================================
# Synthetic-entity checks
# ==========================================

# Reserved/synthetic ranges that are safe to emit as fake telemetry.
_SYNTHETIC_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),      # RFC5737 TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # RFC5737 TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # RFC5737 TEST-NET-3
    ipaddress.ip_network("10.0.0.0/8"),        # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),     # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),    # RFC1918
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
]

# Reserved TLDs safe for synthetic URLs/domains.
_SYNTHETIC_TLDS = (".invalid", ".example", ".test", ".localhost")


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _ip_is_synthetic(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(addr in net for net in _SYNTHETIC_NETS)


def _domain_is_synthetic(value: str) -> bool:
    # Extract host from a URL or bare domain and require a reserved TLD.
    host = value
    if "://" in value:
        host = value.split("://", 1)[1]
    host = host.split("/", 1)[0].split(":", 1)[0]
    return host.endswith(_SYNTHETIC_TLDS) or host == "localhost"


# entity kinds whose "value" must be a synthetic IP
_IP_ENTITY_KINDS = {"source_ip", "dest_ip", "src_ip", "ip"}
# entity kinds whose "value" must be a synthetic host/domain/URL
_URL_ENTITY_KINDS = {"url", "domain", "host"}


def validate_scenario_safety(spec: ScenarioSpec) -> ValidationReport:
    """Audit the returned spec for unsafe or non-synthetic content."""
    report = ValidationReport()

    for ent in spec.entity_templates:
        kind = (ent.kind or "").lower()
        value = ent.value or ""

        if kind in _IP_ENTITY_KINDS:
            if not _looks_like_ip(value):
                report.violations.append(
                    ValidationViolation(
                        code="non_synthetic_ip",
                        message=f"Entity '{ent.entity_id}' value '{value}' is not an IP address.",
                        location=f"entity:{ent.entity_id}",
                    )
                )
            elif not _ip_is_synthetic(value):
                report.violations.append(
                    ValidationViolation(
                        code="external_target",
                        message=(
                            f"Entity '{ent.entity_id}' uses IP '{value}' which is not a reserved "
                            "synthetic range (RFC5737/RFC1918). Use clearly fake telemetry values."
                        ),
                        location=f"entity:{ent.entity_id}",
                    )
                )

        if kind in _URL_ENTITY_KINDS:
            if not _domain_is_synthetic(value):
                report.violations.append(
                    ValidationViolation(
                        code="external_target",
                        message=(
                            f"Entity '{ent.entity_id}' URL/host '{value}' is not a reserved synthetic "
                            "domain (use .invalid/.example/.test)."
                        ),
                        location=f"entity:{ent.entity_id}",
                    )
                )

    # Ground-truth integrity: detector output must never be the label source.
    for t in spec.event_templates:
        if t.ground_truth_source.value in ("rule_output", "ml_prediction", "detection_score"):
            report.violations.append(
                ValidationViolation(
                    code="label_leakage",
                    message=(
                        f"Event template '{t.template_id}' derives ground truth from the detector "
                        "being evaluated. Labels must come from IDS signature, scenario design, "
                        "or heuristic policy."
                    ),
                    location=f"event_template:{t.template_id}",
                )
            )

    return report


def validate_scenario_feasibility(spec: ScenarioSpec) -> ValidationReport:
    """Audit whether the scenario is internally plausible/executable."""
    report = ValidationReport()

    # Event rate sanity: a scenario claiming a huge event count over a 1s window
    # is not a realistic simulation.
    if spec.duration_seconds and spec.event_count:
        rate = spec.event_count / max(spec.duration_seconds, 1)
        if rate > 1000:
            report.warnings.append(
                ValidationViolation(
                    code="implausible_rate",
                    message=f"Implied event rate {rate:.0f}/s is unusually high; timestamps may collide.",
                    location="timing",
                )
            )

    # Category-specific observable-feature sanity.
    if spec.attack_category == AttackCategory.PORT_SCAN:
        _check_port_scan_feasibility(spec, report)
    elif spec.attack_category in (AttackCategory.BRUTE_FORCE, AttackCategory.CREDENTIAL_STUFFING):
        _check_auth_feasibility(spec, report)

    # If nothing is expected to be detected and it is benign, warn (not error).
    any_attack = any(o.is_malicious for o in spec.expected_outcomes)
    if not any_attack and not spec.expected_outcomes[0].expected_detection_labels:
        report.warnings.append(
            ValidationViolation(
                code="benign_only",
                message="Scenario is entirely benign; useful as a false-positive baseline.",
                location="expected_outcomes",
            )
        )

    return report


def _check_port_scan_feasibility(spec: ScenarioSpec, report: ValidationReport) -> None:
    # At least one network template should carry a distinct_dest_ports feature.
    has_port_feature = any(
        "distinct_dest_ports" in t.features or "dest_port" in t.features
        for t in spec.event_templates
    )
    if not has_port_feature:
        report.violations.append(
            ValidationViolation(
                code="missing_category_features",
                message="Port-scan scenarios must include port-observable features (distinct_dest_ports or dest_port).",
                location="event_templates",
            )
        )


def _check_auth_feasibility(spec: ScenarioSpec, report: ValidationReport) -> None:
    has_auth_target = any(t.event_category.value == "auth" for t in spec.event_templates)
    if not has_auth_target:
        report.violations.append(
            ValidationViolation(
                code="missing_category_features",
                message="Authentication scenarios must include at least one auth event template.",
                location="event_templates",
            )
        )


def run_full_validation(spec: ScenarioSpec) -> ValidationReport:
    """Aggregate safety + feasibility into one report."""
    combined = ValidationReport()
    safety = validate_scenario_safety(spec)
    feas = validate_scenario_feasibility(spec)
    combined.violations.extend(safety.violations)
    combined.violations.extend(feas.violations)
    combined.warnings.extend(safety.warnings)
    combined.warnings.extend(feas.warnings)
    return combined
