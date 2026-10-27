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
        
    yield
    
    # Cleanup after tests
    try:
        from app.database import engine
        engine.dispose()
        if os.path.exists(TEST_DB_PATH):
            os.remove(TEST_DB_PATH)
    except Exception:
        pass
