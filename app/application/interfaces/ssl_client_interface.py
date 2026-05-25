from abc import ABC, abstractmethod

from app.domain.entities.certificate_info import CertificateInfo
from app.domain.value_objects.tls_version import TlsVersion


class ISslClient(ABC):
    @abstractmethod
    def check_https_available(self, domain: str, port: int, timeout: float) -> bool:
        """Verifica si el puerto HTTPS está disponible y responde."""
        pass

    @abstractmethod
    def get_certificate_info(self, domain: str, port: int, timeout: float) -> CertificateInfo:
        """Obtiene y parsea la información del certificado SSL/TLS."""
        pass

    @abstractmethod
    def check_tls_version_supported(
        self, domain: str, port: int, version: TlsVersion, timeout: float
    ) -> bool:
        """Verifica si el host remoto soporta una versión particular de TLS/SSL."""
        pass
