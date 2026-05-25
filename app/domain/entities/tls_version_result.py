from dataclasses import dataclass
from typing import Optional

from app.domain.value_objects.check_status import CheckStatus
from app.domain.value_objects.risk_level import RiskLevel
from app.domain.value_objects.tls_version import TlsVersion


@dataclass
class TlsVersionResult:
    version: TlsVersion
    supported: bool
    status: CheckStatus
    risk_level: Optional[RiskLevel] = None
    recommendation: Optional[str] = None
