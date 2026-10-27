"""LLM-Assisted Adaptive Learning (Milestone 1).

Evidence-backed LLM analysis of persisted ``EvaluationRun`` records. The LLM is
an analyst only: it proposes structured, evidence-linked recommendations and has
no database-write, feature-schema, rule-edit or model-activation authority. Every
reference produced by the model is validated against the database and the
registered feature schemas before it is persisted.
"""
