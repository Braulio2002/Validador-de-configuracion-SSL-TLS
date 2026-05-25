from datetime import datetime, timezone
from unittest.mock import MagicMock

from app.application.interfaces.domain_reader_interface import IDomainReader
from app.application.interfaces.ssl_client_interface import ISslClient
from app.application.services.certificate_analyzer_service import CertificateAnalyzerService
from app.application.services.domain_validator_service import DomainValidatorService
from app.application.services.recommendation_service import RecommendationService
from app.application.services.risk_analyzer_service import RiskAnalyzerService
from app.application.services.score_calculator_service import ScoreCalculatorService
from app.application.services.tls_version_checker_service import TlsVersionCheckerService
from app.application.use_cases.validate_ssl_tls_use_case import ValidateSslTlsUseCase
from app.config.settings import settings
from app.domain.entities.certificate_info import CertificateInfo
from app.domain.value_objects.risk_level import RiskLevel
from app.domain.value_objects.tls_version import TlsVersion
from app.infrastructure.exporters.excel_report_exporter import ExcelReportExporter
from app.infrastructure.exporters.json_report_exporter import JsonReportExporter


def test_full_ssl_tls_validation_flow(tmp_path):
    # 1. Configurar directorios temporales para evitar ensuciar el workspace
    settings.INPUT_DIR = tmp_path / "datos_entrada"
    settings.OUTPUT_DIR = tmp_path / "datos_salida"
    settings.DOMAINS_FILE = settings.INPUT_DIR / "domains.txt"

    # 2. Mocks de infraestructura
    mock_dir_manager = MagicMock()

    # Lector de dominios mockeado
    mock_reader = MagicMock(spec=IDomainReader)
    mock_reader.read_domains.return_value = [
        "google.com",
        "https://expired.example.com",
        "invalid-domain",
    ]

    # Cliente SSL mockeado
    mock_ssl_client = MagicMock(spec=ISslClient)

    # Comportamiento para check_https_available
    def side_check_https(domain, port, timeout):
        if domain == "invalid-domain":
            return False
        return True

    mock_ssl_client.check_https_available.side_effect = side_check_https

    # Comportamiento para get_certificate_info
    def side_get_cert(domain, port, timeout):
        now = datetime.now(timezone.utc)
        if domain == "google.com":
            return CertificateInfo(
                subject="CN=google.com",
                issuer="CN=Google Trust Services",
                common_name="google.com",
                san_domains=["google.com", "*.google.com"],
                valid_from=now - timedelta_safe(10),
                valid_until=now + timedelta_safe(90),
                is_trusted=True,
            )
        elif domain == "expired.example.com":
            return CertificateInfo(
                subject="CN=expired.example.com",
                issuer="CN=Let's Encrypt",
                common_name="expired.example.com",
                san_domains=["expired.example.com"],
                valid_from=now - timedelta_safe(60),
                valid_until=now - timedelta_safe(5),
                is_trusted=True,
            )
        return CertificateInfo(error="No se pudo obtener certificado")

    mock_ssl_client.get_certificate_info.side_effect = side_get_cert

    # Comportamiento para check_tls_version_supported
    def side_check_tls(domain, port, version, timeout):
        # google.com soporta TLS 1.2 y 1.3
        if domain == "google.com":
            return version in [TlsVersion.TLS_1_2, TlsVersion.TLS_1_3]
        # expired.example.com soporta TLS 1.0, 1.1 y 1.2
        elif domain == "expired.example.com":
            return version in [TlsVersion.TLS_1_0, TlsVersion.TLS_1_1, TlsVersion.TLS_1_2]
        return False

    mock_ssl_client.check_tls_version_supported.side_effect = side_check_tls

    # 3. Servicios reales
    validator = DomainValidatorService()
    cert_analyzer = CertificateAnalyzerService()
    tls_checker = TlsVersionCheckerService()
    risk_analyzer = RiskAnalyzerService()
    score_calculator = ScoreCalculatorService()
    rec_service = RecommendationService()

    excel_exporter = ExcelReportExporter()
    json_exporter = JsonReportExporter()

    # 4. Caso de uso
    use_case = ValidateSslTlsUseCase(
        directory_manager=mock_dir_manager,
        domain_reader=mock_reader,
        ssl_client=mock_ssl_client,
        excel_exporter=excel_exporter,
        json_exporter=json_exporter,
        domain_validator=validator,
        cert_analyzer=cert_analyzer,
        tls_checker=tls_checker,
        risk_analyzer=risk_analyzer,
        score_calculator=score_calculator,
        recommendation_service=rec_service,
    )

    # Crear carpeta de salida simulada
    settings.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 5. Ejecutar caso de uso
    reports, errors = use_case.execute()

    # 6. Validaciones
    assert (
        len(reports) == 2
    )  # google.com, expired.example.com (invalid-domain es omitido por el validador)

    # Validar google.com
    r_google = next(r for r in reports if r.domain == "google.com")
    assert r_google.https_available is True
    assert r_google.score == 100.0  # Configuración ideal
    assert r_google.risk_level == RiskLevel.LOW

    # Validar expired.example.com
    r_expired = next(r for r in reports if r.domain == "expired.example.com")
    assert r_expired.https_available is True
    assert r_expired.certificate_info.is_expired is True
    assert r_expired.score < 100.0

    # Verificar que los archivos se crearon
    excel_files = list(settings.OUTPUT_DIR.glob("*.xlsx"))
    json_files = list(settings.OUTPUT_DIR.glob("*.json"))

    assert len(excel_files) == 1
    assert len(json_files) == 1


def timedelta_safe(days):
    from datetime import timedelta

    return timedelta(days=days)
