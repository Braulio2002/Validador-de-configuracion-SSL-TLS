import os
from pathlib import Path
from typing import Dict


class Settings:
    # Directories and paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    INPUT_DIR: Path = BASE_DIR / os.getenv("INPUT_DIR", "datos_entrada")
    OUTPUT_DIR: Path = BASE_DIR / os.getenv("OUTPUT_DIR", "datos_salida")
    DOMAINS_FILE: Path = INPUT_DIR / \
        os.getenv("DOMAINS_FILE_NAME", "domains.txt")

    # Connection Parameters
    DEFAULT_PORT: int = int(os.getenv("DEFAULT_PORT", "443"))
    TIMEOUT_SECONDS: float = float(os.getenv("TIMEOUT_SECONDS", "5.0"))

    # SSL/TLS Analysis Settings
    VERIFY_CERTIFICATES: bool = os.getenv(
        "VERIFY_CERTIFICATES", "True").lower() == "true"
    NEAR_EXPIRATION_DAYS: int = int(os.getenv("NEAR_EXPIRATION_DAYS", "30"))

    # Reports Naming
    EXCEL_REPORT_NAME: str = os.getenv("EXCEL_REPORT_NAME", "ssl_tls_report")
    JSON_REPORT_NAME: str = os.getenv("JSON_REPORT_NAME", "ssl_tls_report")

    # Scoring weights (MUST be easy to configure and adjust)
    # Default scoring weights summing up to 100 points
    SCORE_WEIGHTS: Dict[str, float] = {
        "https_available": 15.0,
        "certificate_valid": 25.0,
        "matches_domain": 15.0,
        "not_near_expiration": 10.0,
        "tls_1_2_supported": 10.0,
        "tls_1_3_supported": 10.0,
        "tls_1_0_disabled": 5.0,
        "tls_1_1_disabled": 5.0,
        "ssl_v2_v3_disabled": 5.0,
    }


# Instancia global configurable
settings = Settings()
