from pydantic_settings import BaseSettings, SettingsConfigDict


import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(BASE_DIR, ".env")
DB_FILE = os.path.join(BASE_DIR, "aod_ips.db")

class Settings(BaseSettings):
    DATABASE_URL: str = f"sqlite:///{DB_FILE}"
    SURICATA_EVE_PATH: str = "/var/log/suricata/eve.json"
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_MODEL: str = "meta-llama/llama-3.3-70b-instruct"
    EVIDENCE_HMAC_KEY: str = ""

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
