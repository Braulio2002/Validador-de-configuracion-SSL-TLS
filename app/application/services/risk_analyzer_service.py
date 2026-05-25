from typing import Dict, List

from app.domain.entities.certificate_info import CertificateInfo
from app.domain.entities.tls_version_result import TlsVersionResult
from app.domain.value_objects.risk_level import RiskLevel
from app.domain.value_objects.tls_version import TlsVersion
from app.shared.constants import RECOMMENDATIONS


class RiskAnalyzerService:
    def analyze_risks(
        self, https_available: bool, cert_info: CertificateInfo, tls_results: List[TlsVersionResult]
    ) -> List[Dict[str, str]]:
        """
        Analiza las debilidades en la configuración SSL/TLS y genera una lista de hallazgos estructurados.
        """
        findings = []

        # 1. HTTPS no disponible (caso de corte rápido)
        if not https_available:
            rec = RECOMMENDATIONS["HTTPS_UNAVAILABLE"]
            findings.append(
                {
                    "problema": "HTTPS_UNAVAILABLE",
                    "severidad": RiskLevel.CRITICAL.value,
                    "descripcion": "El servidor no responde en el puerto 443 por protocolo HTTPS.",
                    "recomendacion": rec["recomendacion"],
                }
            )
            return findings

        # 2. Analizar riesgos del certificado
        if cert_info:
            self._analyze_certificate_risks(cert_info, findings)

        # 3. Analizar riesgos de versiones de TLS
        self._analyze_tls_version_risks(tls_results, findings)

        return findings

    def _analyze_certificate_risks(
        self, cert_info: CertificateInfo, findings: List[Dict[str, str]]
    ) -> None:
        # Certificado expirado
        if cert_info.is_expired:
            rec = RECOMMENDATIONS["CERT_EXPIRED"]
            findings.append(
                {
                    "problema": "CERT_EXPIRED",
                    "severidad": RiskLevel.CRITICAL.value,
                    "descripcion": f"El certificado SSL/TLS ha vencido o aún no entra en validez. Fecha de expiración: {cert_info.valid_until}.",
                    "recomendacion": rec["recomendacion"],
                }
            )
        # Certificado próximo a vencer
        elif cert_info.is_near_expiration:
            rec = RECOMMENDATIONS["CERT_NEAR_EXPIRATION"]
            findings.append(
                {
                    "problema": "CERT_NEAR_EXPIRATION",
                    "severidad": RiskLevel.HIGH.value,
                    "descripcion": f"El certificado SSL/TLS vencerá pronto en {cert_info.days_to_expire} días.",
                    "recomendacion": rec["recomendacion"],
                }
            )

        # Dominio no coincide
        if not cert_info.matches_domain:
            rec = RECOMMENDATIONS["CERT_DOMAIN_MISMATCH"]
            findings.append(
                {
                    "problema": "CERT_DOMAIN_MISMATCH",
                    "severidad": RiskLevel.HIGH.value,
                    "descripcion": f"El dominio no coincide con el CN ('{cert_info.common_name}') ni con los SANs {cert_info.san_domains}.",
                    "recomendacion": rec["recomendacion"],
                }
            )

        # Certificado no confiable o autofirmado
        if not cert_info.is_trusted:
            rec = RECOMMENDATIONS["CERT_UNTRUSTED"]
            desc = "El emisor del certificado no es de confianza o la cadena está rota."
            if cert_info.error and "self-signed" in cert_info.error.lower():
                desc = "El certificado es autofirmado (Self-Signed Certificate), lo cual no garantiza autenticidad."
            elif cert_info.error:
                desc = f"Error en la cadena de confianza: {cert_info.error}"

            findings.append(
                {
                    "problema": "CERT_UNTRUSTED",
                    "severidad": RiskLevel.HIGH.value,
                    "descripcion": desc,
                    "recomendacion": rec["recomendacion"],
                }
            )

    def _analyze_tls_version_risks(
        self, tls_results: List[TlsVersionResult], findings: List[Dict[str, str]]
    ) -> None:
        for r in tls_results:
            if r.supported:
                self._check_supported_tls_version(r, findings)
            else:
                self._check_unsupported_tls_version(r, findings)

    def _check_supported_tls_version(
        self, r: TlsVersionResult, findings: List[Dict[str, str]]
    ) -> None:
        if r.version == TlsVersion.SSLV2:
            rec = RECOMMENDATIONS["SSLV2_ENABLED"]
            findings.append(
                {
                    "problema": "SSLV2_ENABLED",
                    "severidad": RiskLevel.CRITICAL.value,
                    "descripcion": "El servidor tiene habilitado el protocolo obsoleto e inseguro SSLv2.",
                    "recomendacion": rec["recomendacion"],
                }
            )
        elif r.version == TlsVersion.SSLV3:
            rec = RECOMMENDATIONS["SSLV3_ENABLED"]
            findings.append(
                {
                    "problema": "SSLV3_ENABLED",
                    "severidad": RiskLevel.CRITICAL.value,
                    "descripcion": "El servidor tiene habilitado el protocolo SSLv3, vulnerable a ataques como POODLE.",
                    "recomendacion": rec["recomendacion"],
                }
            )
        elif r.version == TlsVersion.TLS_1_0:
            rec = RECOMMENDATIONS["TLS10_ENABLED"]
            findings.append(
                {
                    "problema": "TLS10_ENABLED",
                    "severidad": RiskLevel.HIGH.value,
                    "descripcion": "El servidor soporta TLS 1.0, el cual cuenta con debilidades criptográficas severas.",
                    "recomendacion": rec["recomendacion"],
                }
            )
        elif r.version == TlsVersion.TLS_1_1:
            rec = RECOMMENDATIONS["TLS11_ENABLED"]
            findings.append(
                {
                    "problema": "TLS11_ENABLED",
                    "severidad": RiskLevel.MEDIUM.value,
                    "descripcion": "El servidor soporta TLS 1.1, considerado obsoleto por el IETF.",
                    "recomendacion": rec["recomendacion"],
                }
            )

    def _check_unsupported_tls_version(
        self, r: TlsVersionResult, findings: List[Dict[str, str]]
    ) -> None:
        if r.version == TlsVersion.TLS_1_2:
            rec = RECOMMENDATIONS["TLS12_DISABLED"]
            findings.append(
                {
                    "problema": "TLS12_DISABLED",
                    "severidad": RiskLevel.MEDIUM.value,
                    "descripcion": "El servidor no soporta TLS 1.2, lo cual limita la interoperabilidad con clientes estándar seguros.",
                    "recomendacion": rec["recomendacion"],
                }
            )
        elif r.version == TlsVersion.TLS_1_3:
            rec = RECOMMENDATIONS["TLS13_DISABLED"]
            findings.append(
                {
                    "problema": "TLS13_DISABLED",
                    "severidad": RiskLevel.LOW.value,
                    "descripcion": "El servidor no soporta TLS 1.3, perdiendo mejoras de rendimiento y máxima seguridad.",
                    "recomendacion": rec["recomendacion"],
                }
            )
