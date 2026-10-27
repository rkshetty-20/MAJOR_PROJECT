import os
import sys
import pytest

# Ensure backend root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Ensure tests use an isolated database and do NOT modify the production database
TEST_DB_PATH = "./test_aod_ips.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH}"
os.environ["EVIDENCE_HMAC_KEY"] = "test_mock_key_for_hmac_123"

@pytest.fixture(scope="session", autouse=True)
def isolated_test_db():
    # Clean up any previous test db
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except Exception:
            pass

    # Create the schema explicitly so every test module is runnable on its own.
    # Previously tables only appeared as a side effect of a TestClient starting
    # the app lifespan, which made single-file runs fail with "no such table".
    from app.database import Base, engine
    import app.models  # noqa: F401  (registers all mappers on Base.metadata)
    Base.metadata.create_all(bind=engine)

    yield

    # Cleanup after tests
    try:
        from app.database import engine
        engine.dispose()
        if os.path.exists(TEST_DB_PATH):
            os.remove(TEST_DB_PATH)
    except Exception:
        pass


@pytest.fixture(scope="session", autouse=True)
def isolated_model_store():
    """Keep every test-run ML artifact out of the repository's model store.

    The adaptive lifecycle is exercised end to end by the suite. Without this,
    each run would drop new ``v_*.joblib`` files into ``backend/ml/models`` and
    make the registry inventory - and therefore the readiness diagnostics that
    report how many verified/unverified artifacts exist - depend on how often
    the tests had previously been executed.

    Only the bundled baseline artifacts are copied into the temporary store, so
    tests still exercise a realistic "base model present, adaptive versions
    absent" starting state.
    """
    import shutil
    import tempfile

    from ml import registry

    real_dir = registry.MODELS_DIR
    store = tempfile.mkdtemp(prefix="aod_ips_models_")
    for filename in sorted(os.listdir(real_dir)):
        if filename.startswith(("port_scan_rf.", "brute_force_rf.")):
            shutil.copy(os.path.join(real_dir, filename), store)

    registry.MODELS_DIR = store
    try:
        yield store
    finally:
        registry.MODELS_DIR = real_dir
        shutil.rmtree(store, ignore_errors=True)
