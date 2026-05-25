from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class CertificateInfo:
    subject: str = ""
    issuer: str = ""
    common_name: str = ""
    san_domains: List[str] = field(default_factory=list)
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    days_to_expire: int = 0
    is_expired: bool = False
    is_near_expiration: bool = False
    matches_domain: bool = False
    is_trusted: bool = False
    error: Optional[str] = None
