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
