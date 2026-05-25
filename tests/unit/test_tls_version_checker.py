from app.application.services.tls_version_checker_service import TlsVersionCheckerService
from app.domain.value_objects.check_status import CheckStatus
from app.domain.value_objects.risk_level import RiskLevel
from app.domain.value_objects.tls_version import TlsVersion


def test_legacy_versions_status():
    service = TlsVersionCheckerService()

    # SSLv3 habilitado es crítico
    res_v3_enabled = service.check_version_status(TlsVersion.SSLV3, supported=True)
    assert res_v3_enabled.supported is True
    assert res_v3_enabled.status == CheckStatus.FAILED
    assert res_v3_enabled.risk_level == RiskLevel.CRITICAL

    # SSLv3 deshabilitado está bien (OK)
    res_v3_disabled = service.check_version_status(TlsVersion.SSLV3, supported=False)
    assert res_v3_disabled.supported is False
    assert res_v3_disabled.status == CheckStatus.OK
    assert res_v3_disabled.risk_level is None


def test_weak_versions_status():
    service = TlsVersionCheckerService()

    # TLS 1.0 habilitado es alto
    res_t10 = service.check_version_status(TlsVersion.TLS_1_0, supported=True)
    assert res_t10.status == CheckStatus.WARNING
    assert res_t10.risk_level == RiskLevel.HIGH

    # TLS 1.1 habilitado es medio
    res_t11 = service.check_version_status(TlsVersion.TLS_1_1, supported=True)
    assert res_t11.status == CheckStatus.WARNING
    assert res_t11.risk_level == RiskLevel.MEDIUM


def test_secure_versions_status():
    service = TlsVersionCheckerService()

    # TLS 1.2 soportado está bien (OK)
    res_t12_ok = service.check_version_status(TlsVersion.TLS_1_2, supported=True)
    assert res_t12_ok.status == CheckStatus.OK

    # TLS 1.2 no soportado es error/alerta medio
    res_t12_fail = service.check_version_status(TlsVersion.TLS_1_2, supported=False)
    assert res_t12_fail.status == CheckStatus.FAILED
    assert res_t12_fail.risk_level == RiskLevel.MEDIUM

    # TLS 1.3 soportado está bien (OK)
    res_t13_ok = service.check_version_status(TlsVersion.TLS_1_3, supported=True)
    assert res_t13_ok.status == CheckStatus.OK

    # TLS 1.3 no soportado es una advertencia baja
    res_t13_warn = service.check_version_status(TlsVersion.TLS_1_3, supported=False)
    assert res_t13_warn.status == CheckStatus.WARNING
    assert res_t13_warn.risk_level == RiskLevel.LOW
