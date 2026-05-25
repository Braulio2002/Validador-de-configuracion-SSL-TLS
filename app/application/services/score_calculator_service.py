from typing import Dict, List

from app.config.settings import settings
from app.domain.entities.certificate_info import CertificateInfo
from app.domain.entities.tls_version_result import TlsVersionResult
from app.domain.value_objects.risk_level import RiskLevel
from app.domain.value_objects.tls_version import TlsVersion


class ScoreCalculatorService:
    def calculate_score(
        self,
        https_available: bool,
        cert_info: CertificateInfo,
        tls_results: List[TlsVersionResult],
        weights: Dict[str, float] = settings.SCORE_WEIGHTS,
    ) -> float:
        """
        Calcula un score de 0 a 100 para un dominio basándose en pesos configurables.
        """
        if not https_available:
            return 0.0

        score = weights.get("https_available", 15.0)

        # 1. Sumar score del certificado
        if cert_info:
            score += self._calculate_certificate_score(cert_info, weights)

        # 2. Sumar score de versiones TLS
        score += self._calculate_tls_score(tls_results, weights)

        # Limitar a rango [0.0, 100.0]
        return float(max(0.0, min(100.0, score)))

    def _calculate_certificate_score(
        self, cert_info: CertificateInfo, weights: Dict[str, float]
    ) -> float:
        score = 0.0

        # Certificado válido (+25 pts por defecto)
        # Se considera válido si no hay error de fecha, no ha expirado y es de confianza
        if not cert_info.is_expired and cert_info.is_trusted and not cert_info.error:
            score += weights.get("certificate_valid", 25.0)

        # Certificado coincide con el dominio (+15 pts por defecto)
        if cert_info.matches_domain:
            score += weights.get("matches_domain", 15.0)

        # Certificado no próximo a vencer (+10 pts por defecto)
        if not cert_info.is_near_expiration and not cert_info.is_expired:
            score += weights.get("not_near_expiration", 10.0)

        return score

    def _calculate_tls_score(
        self, tls_results: List[TlsVersionResult], weights: Dict[str, float]
    ) -> float:
        score = 0.0
        tls_map = {r.version: r for r in tls_results}

        # TLS 1.2 soportado (+10 pts por defecto)
        t12 = tls_map.get(TlsVersion.TLS_1_2)
        if t12 and t12.supported:
            score += weights.get("tls_1_2_supported", 10.0)

        # TLS 1.3 soportado (+10 pts por defecto)
        t13 = tls_map.get(TlsVersion.TLS_1_3)
        if t13 and t13.supported:
            score += weights.get("tls_1_3_supported", 10.0)

        # TLS 1.0 deshabilitado (+5 pts por defecto)
        t10 = tls_map.get(TlsVersion.TLS_1_0)
        if t10 and not t10.supported:
            score += weights.get("tls_1_0_disabled", 5.0)

        # TLS 1.1 deshabilitado (+5 pts por defecto)
        t11 = tls_map.get(TlsVersion.TLS_1_1)
        if t11 and not t11.supported:
            score += weights.get("tls_1_1_disabled", 5.0)

        # SSLv2/SSLv3 deshabilitados (+5 pts por defecto)
        sslv2 = tls_map.get(TlsVersion.SSLV2)
        sslv3 = tls_map.get(TlsVersion.SSLV3)

        # Si ambos están inactivos, sumamos los puntos
        v2_disabled = (not sslv2.supported) if sslv2 else True
        v3_disabled = (not sslv3.supported) if sslv3 else True

        if v2_disabled and v3_disabled:
            score += weights.get("ssl_v2_v3_disabled", 5.0)

        return score

    def determine_risk_level(self, score: float) -> RiskLevel:
        """
        Asigna el nivel de riesgo según la clasificación definida.
        - 90 a 100: Excelente -> RiskLevel.LOW
        - 75 a 89: Bueno -> RiskLevel.LOW
        - 50 a 74: Regular -> RiskLevel.MEDIUM
        - 25 a 49: Riesgoso -> RiskLevel.HIGH
        - 0 a 24: Crítico -> RiskLevel.CRITICAL
        """
        if score >= 75:
            return RiskLevel.LOW
        elif score >= 50:
            return RiskLevel.MEDIUM
        elif score >= 25:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    def determine_classification_name(self, score: float) -> str:
        """Retorna el nombre en texto de la clasificación de seguridad."""
        if score >= 90:
            return "Excelente"
        elif score >= 75:
            return "Bueno"
        elif score >= 50:
            return "Regular"
        elif score >= 25:
            return "Riesgoso"
        else:
            return "Crítico"
