from datetime import datetime, timezone
from typing import List

from app.domain.entities.certificate_info import CertificateInfo


class CertificateAnalyzerService:
    def analyze_certificate(
        self, cert_info: CertificateInfo, domain_to_check: str, near_expiration_threshold_days: int
    ) -> CertificateInfo:
        """
        Analiza un certificado SSL/TLS y actualiza sus estados:
        - Expiración
        - Vencimiento próximo
        - Coincidencia con el dominio (incluyendo comodines/SANs)
        """
        if cert_info.error:
            # Si ya hay un error de infraestructura, no procedemos con el análisis de fechas
            return cert_info

        if not cert_info.valid_until:
            cert_info.error = "Fechas del certificado no disponibles."
            return cert_info

        # Fechas y cálculo de días restantes
        now = datetime.now(timezone.utc)

        # Asegurarse de que valid_until y valid_from tengan timezone utc para comparar
        valid_until_utc = cert_info.valid_until
        if valid_until_utc.tzinfo is None:
            valid_until_utc = valid_until_utc.replace(tzinfo=timezone.utc)

        valid_from_utc = cert_info.valid_from
        if valid_from_utc and valid_from_utc.tzinfo is None:
            valid_from_utc = valid_from_utc.replace(tzinfo=timezone.utc)

        # Si aún no es válido o ya expiró
        if (valid_from_utc and now < valid_from_utc) or (now > valid_until_utc):
            cert_info.is_expired = True
            cert_info.days_to_expire = 0
            cert_info.is_near_expiration = True
        else:
            delta = valid_until_utc - now
            cert_info.days_to_expire = max(0, delta.days)
            cert_info.is_expired = False
            cert_info.is_near_expiration = (
                cert_info.days_to_expire <= near_expiration_threshold_days
            )

        # Verificar si el certificado coincide con el dominio
        cert_info.matches_domain = self.match_hostname(
            domain_to_check, cert_info.common_name, cert_info.san_domains
        )

        return cert_info

    def match_hostname(self, hostname: str, common_name: str, san_domains: List[str]) -> bool:
        """
        Verifica si un hostname coincide con el Common Name o los Subject Alternative Names,
        soportando comodines básicos (e.g. *.google.com).
        """
        hostname_lower = hostname.lower()
        candidates = []

        if common_name:
            candidates.append(common_name.lower())
        for san in san_domains:
            candidates.append(san.lower())

        for pattern in candidates:
            if self._match_pattern(hostname_lower, pattern):
                return True
        return False

    def _match_pattern(self, hostname: str, pattern: str) -> bool:
        """Soporte para coincidencias de comodines de un solo nivel (e.g. *.domain.com)"""
        if pattern == hostname:
            return True

        if pattern.startswith("*."):
            # *.example.com coincide con sub.example.com pero no con example.com ni con deep.sub.example.com
            suffix = pattern[2:]
            parts = hostname.split(".")
            if len(parts) >= 2:
                # Comprobar si el hostname termina con el sufijo y solo tiene una parte antes del sufijo
                parent_domain = ".".join(parts[1:])
                if parent_domain == suffix and not hostname.startswith("."):
                    return True
        return False
