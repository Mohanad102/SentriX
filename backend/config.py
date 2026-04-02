from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # App
    APP_NAME: str = "SentriX"
    SECRET_KEY: str = "sentrix-super-secret-key-change-in-production-2025"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours

    # Database
    DATABASE_URL: str = "sqlite:///./sentrix.db"

    # Wazuh SIEM
    WAZUH_URL: str = "https://localhost:55000"
    WAZUH_USER: str = "wazuh"
    WAZUH_PASSWORD: str = "wazuh"
    WAZUH_ENABLED: bool = False  # Set True when Wazuh is running

    # TheHive SOAR
    THEHIVE_URL: str = "http://localhost:9000"
    THEHIVE_API_KEY: str = ""
    THEHIVE_ENABLED: bool = False  # Set True when TheHive is running

    # Cortex
    CORTEX_URL: str = "http://localhost:9001"
    CORTEX_API_KEY: str = ""
    CORTEX_ENABLED: bool = False

    # VirusTotal
    VIRUSTOTAL_API_KEY: str = ""
    VIRUSTOTAL_ENABLED: bool = False  # Set True when API key is provided

    # OpenAI / AI Engine
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    AI_ENABLED: bool = False  # Set True when OpenAI key is provided

    # ChromaDB
    CHROMA_PERSIST_DIR: str = "./chroma_db"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
