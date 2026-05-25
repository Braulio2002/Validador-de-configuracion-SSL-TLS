from app.application.services.score_calculator_service import ScoreCalculatorService
from app.domain.entities.certificate_info import CertificateInfo
from app.domain.entities.tls_version_result import TlsVersionResult
from app.domain.value_objects.check_status import CheckStatus
from app.domain.value_objects.risk_level import RiskLevel
from app.domain.value_objects.tls_version import TlsVersion


def test_perfect_score():
    calculator = ScoreCalculatorService()

    # Certificado ideal y de confianza
    cert = CertificateInfo(
        is_expired=False, is_trusted=True, is_near_expiration=False, matches_domain=True, error=None
    )

    # Todas las versiones obsoletas deshabilitadas, y seguras habilitadas
    tls_results = [
        TlsVersionResult(TlsVersion.SSLV2, supported=False, status=CheckStatus.OK),
        TlsVersionResult(TlsVersion.SSLV3, supported=False, status=CheckStatus.OK),
        TlsVersionResult(TlsVersion.TLS_1_0, supported=False, status=CheckStatus.OK),
        TlsVersionResult(TlsVersion.TLS_1_1, supported=False, status=CheckStatus.OK),
        TlsVersionResult(TlsVersion.TLS_1_2, supported=True, status=CheckStatus.OK),
        TlsVersionResult(TlsVersion.TLS_1_3, supported=True, status=CheckStatus.OK),
    ]

    score = calculator.calculate_score(
        https_available=True, cert_info=cert, tls_results=tls_results
    )
    assert score == 100.0
    assert calculator.determine_risk_level(score) == RiskLevel.LOW
    assert calculator.determine_classification_name(score) == "Excelente"


def test_https_unavailable_score():
    calculator = ScoreCalculatorService()

    # Si HTTPS no responde, el score es 0
    score = calculator.calculate_score(https_available=False, cert_info=None, tls_results=[])
    assert score == 0.0
    assert calculator.determine_risk_level(score) == RiskLevel.CRITICAL
    assert calculator.determine_classification_name(score) == "Crítico"


def test_weak_config_score():
    calculator = ScoreCalculatorService()

    # Certificado válido y coincide con dominio, pero próximo a vencer
    cert = CertificateInfo(
        is_expired=False,
        is_trusted=True,
        is_near_expiration=True,  # Pierde 10 puntos
        matches_domain=True,
        error=None,
    )

    # TLS 1.0 y 1.1 están habilitados (Pierde 5 + 5 = 10 puntos)
    # TLS 1.3 no está habilitado (Pierde 10 puntos)
    tls_results = [
        TlsVersionResult(TlsVersion.SSLV2, supported=False, status=CheckStatus.OK),
        TlsVersionResult(TlsVersion.SSLV3, supported=False, status=CheckStatus.OK),
        TlsVersionResult(TlsVersion.TLS_1_0, supported=True, status=CheckStatus.WARNING),
        TlsVersionResult(TlsVersion.TLS_1_1, supported=True, status=CheckStatus.WARNING),
        TlsVersionResult(TlsVersion.TLS_1_2, supported=True, status=CheckStatus.OK),
        TlsVersionResult(TlsVersion.TLS_1_3, supported=False, status=CheckStatus.WARNING),
    ]

    score = calculator.calculate_score(
        https_available=True, cert_info=cert, tls_results=tls_results
    )
    # Score esperado:
    # HTTPS disponible: 15
    # Certificado válido: 25
    # Certificado coincide: 15
    # Certificado no venciendo pronto: 0 (porque es True)
    # TLS 1.2 soportado: 10
    # TLS 1.3 soportado: 0 (no soportado)
    # TLS 1.0 deshabilitado: 0 (porque está soportado)
    # TLS 1.1 deshabilitado: 0 (porque está soportado)
    # SSLv2/SSLv3 deshabilitado: 5
    # Total: 15 + 25 + 15 + 10 + 5 = 70.0
    assert score == 70.0
    assert calculator.determine_risk_level(score) == RiskLevel.MEDIUM
    assert calculator.determine_classification_name(score) == "Regular"
