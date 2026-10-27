from fastapi import APIRouter
from sqlalchemy import inspect, text
from typing import Dict
from app.database import engine, Base
# Importing app.models ensures all models are registered on Base.metadata
import app.models  # noqa: F401

router = APIRouter(prefix="/db", tags=["Database"])


# Columns added to `datasets` by the Attack Scenario Studio (Milestone 3).
# create_all() only creates missing *tables*, never new *columns*, so we add
# them idempotently for pre-existing databases.
_DATASET_STUDIO_COLUMNS = {
    "scenario_id": "VARCHAR(128)",
    "generator_version": "VARCHAR(32)",
    "dataset_role": "VARCHAR(16)",
    "llm_input_sha256": "VARCHAR(64)",
    "scenario_spec_json": "TEXT",
}

# Columns added to `evaluation_runs` by the Studio lifecycle explorer (Milestone 5).
_EVALUATION_RUN_STUDIO_COLUMNS = {
    "session_id": "INTEGER",
    "comparison_json": "TEXT",
}


def _add_missing_columns(table: str, columns: Dict[str, str]) -> None:
    inspector = inspect(engine)
    if table not in inspector.get_table_names():
        return
    existing = {col["name"] for col in inspector.get_columns(table)}
    missing = {name: ddl for name, ddl in columns.items() if name not in existing}
    if not missing:
        return
    # Safe: identifiers are static, values are fixed DDL fragments (no user input).
    with engine.begin() as conn:
        for name, ddl in missing.items():
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


def _ensure_dataset_provenance_columns() -> None:
    """Additively migrate the datasets table for existing databases."""
    _add_missing_columns("datasets", _DATASET_STUDIO_COLUMNS)


def init_db() -> None:
    """
    Creates all database tables defined in the SQLAlchemy models.
    Called on application startup.
    """
    Base.metadata.create_all(bind=engine)
    _add_missing_columns("datasets", _DATASET_STUDIO_COLUMNS)
    _add_missing_columns("evaluation_runs", _EVALUATION_RUN_STUDIO_COLUMNS)


@router.post("/init", summary="Initialize database tables")
def init_db_endpoint() -> dict[str, str]:
    """Manually trigger table creation."""
    init_db()
    return {"status": "ok", "message": "Database tables created successfully"}
