from app.domain.entities.tls_version_result import TlsVersionResult
from app.domain.value_objects.check_status import CheckStatus
from app.domain.value_objects.risk_level import RiskLevel
from app.domain.value_objects.tls_version import TlsVersion
from app.shared.constants import RECOMMENDATIONS


class TlsVersionCheckerService:
    def check_version_status(self, version: TlsVersion, supported: bool) -> TlsVersionResult:
        """
        Analiza el estado de una versión SSL/TLS según si está soportada o no.
        Asigna el CheckStatus, RiskLevel y Recomendación correspondientes.
        """
        if supported:
            return self._check_supported_version(version)
        else:
            return self._check_unsupported_version(version)

    def _check_supported_version(self, version: TlsVersion) -> TlsVersionResult:
        if version == TlsVersion.SSLV2:
            rec = RECOMMENDATIONS["SSLV2_ENABLED"]
            return TlsVersionResult(
                version=version,
                supported=True,
                status=CheckStatus.FAILED,
                risk_level=RiskLevel.CRITICAL,
                recommendation=rec["recomendacion"],
            )
        elif version == TlsVersion.SSLV3:
            rec = RECOMMENDATIONS["SSLV3_ENABLED"]
            return TlsVersionResult(
                version=version,
                supported=True,
                status=CheckStatus.FAILED,
                risk_level=RiskLevel.CRITICAL,
                recommendation=rec["recomendacion"],
            )
        elif version == TlsVersion.TLS_1_0:
            rec = RECOMMENDATIONS["TLS10_ENABLED"]
            return TlsVersionResult(
                version=version,
                supported=True,
                status=CheckStatus.WARNING,
                risk_level=RiskLevel.HIGH,
                recommendation=rec["recomendacion"],
            )
        elif version == TlsVersion.TLS_1_1:
            rec = RECOMMENDATIONS["TLS11_ENABLED"]
            return TlsVersionResult(
                version=version,
                supported=True,
                status=CheckStatus.WARNING,
                risk_level=RiskLevel.MEDIUM,
                recommendation=rec["recomendacion"],
            )
        elif version in [TlsVersion.TLS_1_2, TlsVersion.TLS_1_3]:
            return TlsVersionResult(version=version, supported=True, status=CheckStatus.OK)

        return TlsVersionResult(
            version=version, supported=True, status=CheckStatus.NOT_SUPPORTED
        )

    def _check_unsupported_version(self, version: TlsVersion) -> TlsVersionResult:
        if version in [TlsVersion.SSLV2, TlsVersion.SSLV3, TlsVersion.TLS_1_0, TlsVersion.TLS_1_1]:
            return TlsVersionResult(version=version, supported=False, status=CheckStatus.OK)

        elif version == TlsVersion.TLS_1_2:
            rec = RECOMMENDATIONS["TLS12_DISABLED"]
            return TlsVersionResult(
                version=version,
                supported=False,
                status=CheckStatus.FAILED,
                risk_level=RiskLevel.MEDIUM,
                recommendation=rec["recomendacion"],
            )
        elif version == TlsVersion.TLS_1_3:
            rec = RECOMMENDATIONS["TLS13_DISABLED"]
            return TlsVersionResult(
                version=version,
                supported=False,
                status=CheckStatus.WARNING,
                risk_level=RiskLevel.LOW,
                recommendation=rec["recomendacion"],
            )

        return TlsVersionResult(
            version=version, supported=False, status=CheckStatus.NOT_SUPPORTED
        )
