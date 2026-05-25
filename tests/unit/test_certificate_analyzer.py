from datetime import datetime, timedelta, timezone

from app.application.services.certificate_analyzer_service import CertificateAnalyzerService
from app.domain.entities.certificate_info import CertificateInfo


def test_expired_certificate():
    service = CertificateAnalyzerService()
    now = datetime.now(timezone.utc)

    # Certificado que venció ayer
    cert = CertificateInfo(
        valid_from=now - timedelta(days=10),
        valid_until=now - timedelta(days=1),
        common_name="google.com",
    )

    analyzed = service.analyze_certificate(cert, "google.com", 30)
    assert analyzed.is_expired is True
    assert analyzed.days_to_expire == 0
    assert analyzed.is_near_expiration is True


def test_near_expiration_certificate():
    service = CertificateAnalyzerService()
    now = datetime.now(timezone.utc)

    # Certificado que vence en 15 días (umbral de advertencia es 30 días)
    cert = CertificateInfo(
        valid_from=now - timedelta(days=10),
        valid_until=now + timedelta(days=15, minutes=5),
        common_name="google.com",
    )

    analyzed = service.analyze_certificate(cert, "google.com", 30)
    assert analyzed.is_expired is False
    assert analyzed.days_to_expire == 15
    assert analyzed.is_near_expiration is True


def test_healthy_certificate():
    service = CertificateAnalyzerService()
    now = datetime.now(timezone.utc)

    # Certificado que vence en 90 días
    cert = CertificateInfo(
        valid_from=now - timedelta(days=10),
        valid_until=now + timedelta(days=90, minutes=5),
        common_name="google.com",
    )

    analyzed = service.analyze_certificate(cert, "google.com", 30)
    assert analyzed.is_expired is False
    assert analyzed.days_to_expire == 90
    assert analyzed.is_near_expiration is False


def test_hostname_matching():
    service = CertificateAnalyzerService()

    # Exact matches
    assert service.match_hostname("google.com", "google.com", []) is True
    assert service.match_hostname("api.google.com", "google.com", ["api.google.com"]) is True

    # Wildcard matches
    assert service.match_hostname("sub.google.com", "*.google.com", []) is True
    assert service.match_hostname("google.com", "*.google.com", []) is False
    assert service.match_hostname("deep.sub.google.com", "*.google.com", []) is False

    # Case insensitivity
    assert service.match_hostname("GOOGLE.COM", "google.com", []) is True
