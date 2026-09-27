from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://prahari:prahari@localhost:5432/prahari"
    redis_url: str = "redis://localhost:6379/0"

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    geoip_db_path: str = "/app/data/GeoLite2-City.mmdb"

    secret_key: str = "change-me-in-production"
    allowed_origins: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:8443",
        "http://127.0.0.1:8443",
        "https://praharii-ai.vercel.app"
    ]

    max_upload_size_mb: int = 10
    ai_models_enabled: bool = True
    ai_bert_model_id: str = "ealvaradob/bert-finetuned-phishing"
    ai_roberta_model_id: str = "eduardocastellon/roberta-phishing-email-detector"
    ai_bert_label_map: dict[str, str] = {"benign": "benign", "phishing": "phishing"}
    ai_roberta_label_map: dict[str, str] = {"LABEL_0": "benign", "LABEL_1": "phishing"}
    ai_device: str = "auto"
    ai_max_sequence_length: int = 512
    ai_batch_size: int = 8
    ai_max_input_characters: int = 50000
    ai_risk_weight: int = 8
    ai_phishing_threshold: float = 0.5

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
