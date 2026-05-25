from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from app.domain.entities.certificate_info import CertificateInfo
from app.domain.entities.tls_version_result import TlsVersionResult
from app.domain.value_objects.risk_level import RiskLevel


@dataclass
class SslTlsReport:
    domain: str
    https_available: bool
    certificate_info: Optional[CertificateInfo] = None
    tls_versions: List[TlsVersionResult] = field(default_factory=list)
    weak_configurations: List[Dict[str, str]] = field(default_factory=list)
    recommendations: List[Dict[str, str]] = field(default_factory=list)
    score: float = 0.0
    risk_level: Optional[RiskLevel] = None
    error: Optional[str] = None
    scan_date: datetime = field(default_factory=datetime.now)
