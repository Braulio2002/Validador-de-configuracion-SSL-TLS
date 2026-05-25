from enum import Enum


class RiskLevel(str, Enum):
    LOW = "BAJO"
    MEDIUM = "MEDIO"
    HIGH = "ALTO"
    CRITICAL = "CRÍTICO"
