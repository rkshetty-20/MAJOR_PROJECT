"""LLM-powered Attack Scenario Simulator.

Modular pipeline implementing the FraudGuard scenario generation and evaluation
workflow. Responsibilities are separated so that the LLM only *proposes* a
structured, validated scenario specification, while deterministic services
compile telemetry, run detection replay, evaluate results, and expose learning
eligibility.

Modules:
    - ``spec``: versioned scenario specification schema (Pydantic) and the
      supported attack-category registry. The single source of truth for what a
      valid scenario proposal looks like.
"""
