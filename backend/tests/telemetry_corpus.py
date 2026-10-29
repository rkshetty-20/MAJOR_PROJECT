"""Fixed scenario corpus for the synthetic-telemetry contract (Section A).

This module is deliberately **not** named ``test_*``: it is imported by both
``test_scenario_telemetry_contract.py`` and
``regenerate_scenario_telemetry_golden.py`` so the lock can never be produced from
a different corpus than the one the tests replay.

Every spec here is authored the way the schema requires a real proposal to be:

* observables are declared on the template (``features.event_type`` for auth,
  ``features.dest_port`` / ``features.raw_signature`` for network) and are never
  left for the compiler to infer from ``ground_truth_label``;
* ground truth lives only in ``ground_truth_label`` / ``ground_truth_source`` /
  ``expected_outcomes``;
* every identifier is documentation-only (RFC5737 / RFC1918 / reserved TLDs).
"""

from __future__ import annotations

from typing import Any, Dict

from app.services.scenario_simulator.spec import (
    SCENARIO_SPEC_SCHEMA_VERSION,
    ScenarioSpec,
)

#: Reserved TLDs accepted as synthetic hostnames by ``validators``.
RESERVED_TLDS = (".invalid", ".example", ".test", ".localhost")


def provenance(**overrides: Any) -> Dict[str, Any]:
    prov: Dict[str, Any] = {
        "generator_version": "scenario-studio-1.0",
        "source": "deterministic",
        "request_correlation_id": "corr_telemetry_contract",
        "llm_input_sha256": "0" * 64,
    }
    prov.update(overrides)
    return prov


def _base(scenario_id: str, category: str, seed: int, event_count: int,
          stages: list, entities: list, templates: list,
          outcomes: list, **overrides: Any) -> Dict[str, Any]:
    spec: Dict[str, Any] = {
        "schema_version": SCENARIO_SPEC_SCHEMA_VERSION,
        "scenario_id": scenario_id,
        "title": f"{category} telemetry contract case",
        "description": f"Deterministic synthetic {category} telemetry for the contract tests.",
        "attack_category": category,
        "intensity": "high",
        "duration_seconds": 60,
        "event_count": event_count,
        "seed": seed,
        "stages": stages,
        "entity_templates": entities,
        "event_templates": templates,
        "expected_outcomes": outcomes,
        "evaluation_objective": f"Confirm {category} detection on controlled telemetry.",
        "generation_provenance": provenance(),
    }
    spec.update(overrides)
    return spec


def port_scan_spec(seed: int = 101, declare_signature: bool = False) -> ScenarioSpec:
    """Network fan-out. ``declare_signature=False`` exercises the neutral marker."""
    features: Dict[str, Any] = {"distinct_dest_ports": 18, "severity": 2}
    if declare_signature:
        features["raw_signature"] = "ET SCAN Possible Nmap User-Agent Observed"
    return ScenarioSpec(**_base(
        "scn_tc_port", "port_scan", seed, 20,
        stages=[{"stage_id": "s1", "stage_type": "recon", "description": "Recon sweep",
                 "expected_observable_behavior": "many distinct destination ports"}],
        entities=[
            {"entity_id": "src1", "kind": "source_ip", "value": "10.0.0.50"},
            {"entity_id": "dst1", "kind": "dest_ip", "value": "192.0.2.10"},
        ],
        templates=[{"template_id": "et_scan", "stage_id": "s1", "event_category": "network",
                    "time_offset_seconds": 5, "source_ref": "src1", "target_ref": "dst1",
                    "features": features, "ground_truth_label": 1,
                    "ground_truth_source": "ids_signature", "repetition": 18}],
        outcomes=[{"expected_detection_labels": ["port_scan_detected"], "is_malicious": True,
                   "rationale": "Eighteen distinct ports inside the scan window."}],
    ))


def credential_stuffing_spec(seed: int = 202) -> ScenarioSpec:
    return ScenarioSpec(**_base(
        "scn_tc_stuff", "credential_stuffing", seed, 8,
        stages=[{"stage_id": "s1", "stage_type": "initial_access", "description": "Spray",
                 "expected_observable_behavior": "one source against many accounts"}],
        entities=[{"entity_id": "src1", "kind": "source_ip", "value": "203.0.113.88"}],
        templates=[{"template_id": "et_spray", "stage_id": "s1", "event_category": "auth",
                    "time_offset_seconds": 10, "source_ref": "src1",
                    "features": {"event_type": "failed_authentication", "distinct_targets": 6},
                    "ground_truth_label": 1, "ground_truth_source": "scenario_design",
                    "repetition": 6}],
        outcomes=[{"expected_detection_labels": ["credential_stuffing_detected"],
                   "is_malicious": True, "rationale": "Many distinct accounts from one source."}],
    ))


def brute_force_spec(seed: int = 303, ground_truth_label: int = 1) -> ScenarioSpec:
    """Auth failure burst followed by success.

    ``ground_truth_label`` is a parameter on purpose: the label-independence test
    compiles this spec twice, changing only the label, and requires the emitted
    telemetry to be byte-identical.
    """
    return ScenarioSpec(**_base(
        "scn_tc_brute", "brute_force", seed, 8,
        stages=[{"stage_id": "s1", "stage_type": "initial_access", "description": "Guess",
                 "expected_observable_behavior": "failure burst then one success"}],
        entities=[
            {"entity_id": "src1", "kind": "source_ip", "value": "198.51.100.25"},
            {"entity_id": "acct", "kind": "target_account", "value": "svc_account"},
        ],
        templates=[
            {"template_id": "et_fail", "stage_id": "s1", "event_category": "auth",
             "time_offset_seconds": 0, "source_ref": "src1", "target_ref": "acct",
             "features": {"event_type": "failed_login"}, "ground_truth_label": ground_truth_label,
             "ground_truth_source": "scenario_design", "repetition": 6},
            {"template_id": "et_ok", "stage_id": "s1", "event_category": "auth",
             "time_offset_seconds": 12, "source_ref": "src1", "target_ref": "acct",
             "features": {"event_type": "successful_login"}, "ground_truth_label": ground_truth_label,
             "ground_truth_source": "scenario_design", "repetition": 1},
        ],
        outcomes=[{"expected_detection_labels": ["brute_force_detected"], "is_malicious": True,
                   "rationale": "Repeated failures against one account."}],
    ))


def phishing_spec(seed: int = 505) -> ScenarioSpec:
    return ScenarioSpec(**_base(
        "scn_tc_phish", "phishing_url", seed, 2,
        stages=[{"stage_id": "s1", "stage_type": "initial_access", "description": "Click",
                 "expected_observable_behavior": "lookalike domain with a verification path"}],
        entities=[{"entity_id": "u1", "kind": "url",
                   "value": "http://portal-verify.internal-update.invalid/auth/login"}],
        templates=[{"template_id": "et_phish", "stage_id": "s1", "event_category": "phishing",
                    "time_offset_seconds": 1, "target_ref": "u1",
                    "features": {"https": False, "suspicious_keywords": ["verify"],
                                 "domain_age_days": 1},
                    "ground_truth_label": 1, "ground_truth_source": "heuristic_policy",
                    "repetition": 2}],
        outcomes=[{"expected_detection_labels": ["phishing_url_detected"], "is_malicious": True,
                   "rationale": "Reserved-TLD lookalike with a verification path."}],
    ))


def port_scan_fallback_ids_spec(seed: int = 101) -> ScenarioSpec:
    """Port scan whose templates reference no entities.

    This is the only path on which the spec's ``seed`` actually reaches the
    telemetry: undeclared identifiers are drawn from a seed-derived RNG
    (``compiler._default_for_category``). It exists so the suite can prove the seed
    is live instead of decorative - and, conversely, that a fully declared spec is
    seed-invariant on purpose.
    """
    return ScenarioSpec(**_base(
        "scn_tc_port_fallback", "port_scan", seed, 20,
        stages=[{"stage_id": "s1", "stage_type": "recon", "description": "Recon sweep",
                 "expected_observable_behavior": "many distinct destination ports"}],
        entities=[],
        templates=[{"template_id": "et_scan", "stage_id": "s1", "event_category": "network",
                    "time_offset_seconds": 5,
                    "features": {"distinct_dest_ports": 18, "severity": 2},
                    "ground_truth_label": 1, "ground_truth_source": "ids_signature",
                    "repetition": 18}],
        outcomes=[{"expected_detection_labels": ["port_scan_detected"], "is_malicious": True,
                   "rationale": "Eighteen distinct ports inside the scan window."}],
    ))


#: The replay corpus: name -> spec. Ordered so the lock file is stable.
def build_corpus() -> Dict[str, ScenarioSpec]:
    return {
        "port_scan|seed101": port_scan_spec(101),
        "port_scan|seed7": port_scan_spec(7),
        "port_scan|seed101|declared_signature": port_scan_spec(101, declare_signature=True),
        "port_scan|fallback_ids|seed101": port_scan_fallback_ids_spec(101),
        "port_scan|fallback_ids|seed7": port_scan_fallback_ids_spec(7),
        "credential_stuffing|seed202": credential_stuffing_spec(202),
        "brute_force|seed303": brute_force_spec(303),
        "brute_force|seed303|label0": brute_force_spec(303, ground_truth_label=0),
        "phishing_url|seed505": phishing_spec(505),
    }
