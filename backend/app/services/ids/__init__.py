"""Intrusion Detection System (IDS) analysis subsystem.

A self-contained, DB-free detection pipeline that:
  1. Generates realistic synthetic network packets per attack type (packet_generator)
  2. Runs a multi-layer rules engine: signature / threshold / stateful (rules_engine)
  3. Scores anomalies with an ensemble of simulated ML detectors (anomaly_scorer)
  4. Fuses everything into an explainable analysis result (analysis)

It is intentionally decoupled from the legacy simulation/rule/ML engines so that
the expanded IDS payload-submission experience can evolve without destabilising
the existing (test-covered) telemetry flow.
"""
