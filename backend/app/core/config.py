from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

# Dynamically find the root directory
# __file__ is backend/app/core/config.py
# .parent goes up one level: core -> app -> backend -> root
ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
ENV_FILE_PATH = ROOT_DIR / ".env"

class Settings(BaseSettings):
    # App Settings
    PROJECT_NAME: str = "AI Vulnerability Analysis Agent"
    VERSION: str = "0.1.0"
    
    # API Keys
    MISTRAL_API_KEY: str
    GITHUB_TOKEN: Optional[str] = None
    
    # Database
    DATABASE_URL: str
    
    # Safely point directly to the absolute path of the .env file
    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE_PATH), 
        env_file_encoding="utf-8", 
        extra="ignore"
    )

# Instantiate the settings
settings = Settings()