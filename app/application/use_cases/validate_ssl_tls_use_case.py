from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from app.application.interfaces.domain_reader_interface import IDomainReader
from app.application.interfaces.report_exporter_interface import IReportExporter
from app.application.interfaces.ssl_client_interface import ISslClient
from app.application.services.certificate_analyzer_service import CertificateAnalyzerService
from app.application.services.domain_validator_service import DomainValidatorService
from app.application.services.recommendation_service import RecommendationService
from app.application.services.risk_analyzer_service import RiskAnalyzerService
from app.application.services.score_calculator_service import ScoreCalculatorService
from app.application.services.tls_version_checker_service import TlsVersionCheckerService
from app.config.settings import settings
from app.domain.entities.ssl_tls_report import SslTlsReport
from app.domain.entities.tls_version_result import TlsVersionResult
from app.domain.value_objects.tls_version import TlsVersion
from app.shared.filename_utils import get_unique_filename
from app.shared.logger import logger


class ValidateSslTlsUseCase:
    def __init__(
        self,
        directory_manager: Any,  # Interface not strictly required, dynamic type is ok
        domain_reader: IDomainReader,
        ssl_client: ISslClient,
        excel_exporter: IReportExporter,
        json_exporter: IReportExporter,
        domain_validator: DomainValidatorService,
        cert_analyzer: CertificateAnalyzerService,
        tls_checker: TlsVersionCheckerService,
        risk_analyzer: RiskAnalyzerService,
        score_calculator: ScoreCalculatorService,
        recommendation_service: RecommendationService,
    ):
        self.directory_manager = directory_manager
        self.domain_reader = domain_reader
        self.ssl_client = ssl_client
        self.excel_exporter = excel_exporter
        self.json_exporter = json_exporter
        self.domain_validator = domain_validator
        self.cert_analyzer = cert_analyzer
        self.tls_checker = tls_checker
        self.risk_analyzer = risk_analyzer
        self.score_calculator = score_calculator
        self.recommendation_service = recommendation_service

    def execute(self) -> Tuple[List[SslTlsReport], List[Dict[str, Any]]]:
        """
        Ejecuta el flujo completo de validación y exportación de reportes.
        Retorna una tupla con (lista_de_reportes, lista_de_errores_globales).
        """
        logger.info("Iniciando proceso de auditoría SSL/TLS...")

        # 1. Asegurar la existencia de directorios
        logger.info("Creando carpetas si no existen...")
        self.directory_manager.ensure_directories()

        # 2. Leer archivo de dominios
        domains_path = settings.DOMAINS_FILE
        logger.info(f"Leyendo dominios desde {domains_path}...")
        try:
            raw_domains = self.domain_reader.read_domains(domains_path)
        except Exception as e:
            logger.error(f"Error al leer archivo de dominios: {str(e)}")
            return [], [
                {
                    "dominio": "Global",
                    "tipo_error": "Lectura Archivo",
                    "mensaje_error": str(e),
                    "fecha_analisis": datetime.now(),
                }
            ]

        logger.info(f"Dominios encontrados: {len(raw_domains)}")
        if not raw_domains:
            logger.warning(
                "No se encontraron dominios para analizar en domains.txt. Finalizando."
            )
            return [], []

        # 3. Validar y normalizar dominios
        logger.info("Validando dominios...")
        targets: List[Tuple[str, str, int]] = []
        errors_list: List[Dict[str, Any]] = []

        for raw in raw_domains:
            normalized = self.domain_validator.validate_and_normalize(raw)
            if normalized:
                domain_clean, port = normalized
                targets.append((raw, domain_clean, port))
            else:
                msg = f"El dominio '{raw}' tiene un formato inválido y será omitido."
                logger.warning(msg)
                errors_list.append(
                    {
                        "dominio": raw,
                        "tipo_error": "Formato de Dominio",
                        "mensaje_error": "Formato de dominio inválido o no soportado.",
                        "fecha_analisis": datetime.now(),
                    }
                )

        if not targets:
            logger.warning(
                "No hay dominios con formato válido para auditar. Finalizando."
            )
            return [], errors_list

        reports: List[SslTlsReport] = []

        # 4. Escanear secuencialmente
        for _, clean, port in targets:
            logger.info(f"Analizando SSL/TLS de: {clean} (puerto {port})...")
            scan_date = datetime.now(timezone.utc)
            self._process_target(clean, port, scan_date, reports, errors_list)

        # 5. Exportar reportes
        if reports:
            self._export_reports(reports, errors_list)

        logger.info("Proceso finalizado")
        return reports, errors_list

    def _process_target(
        self,
        clean: str,
        port: int,
        scan_date: datetime,
        reports: List[SslTlsReport],
        errors_list: List[Dict[str, Any]],
    ) -> None:
        try:
            # 4.1. Verificar si responde por HTTPS
            https_available = self.ssl_client.check_https_available(
                clean, port, settings.TIMEOUT_SECONDS
            )

            if not https_available:
                self._handle_https_unavailable(clean, scan_date, reports, errors_list)
                return

            # 4.2. Obtener información de certificado
            logger.info(f"Obteniendo información del certificado para: {clean}")
            cert_info = self.ssl_client.get_certificate_info(
                clean, port, settings.TIMEOUT_SECONDS
            )

            if cert_info.error:
                logger.warning(f"Error de certificado en {clean}: {cert_info.error}")
                errors_list.append(
                    {
                        "dominio": clean,
                        "tipo_error": "Obtención Certificado",
                        "mensaje_error": cert_info.error,
                        "fecha_analisis": scan_date,
                    }
                )

            # 4.3. Analizar certificado (expiación, CN, etc.)
            cert_info = self.cert_analyzer.analyze_certificate(
                cert_info, clean, settings.NEAR_EXPIRATION_DAYS
            )

            # 4.4. Validar versiones TLS soportadas
            tls_results = self._scan_tls_versions(clean, port)

            # 4.5. Analizar configuración débil
            logger.info(f"Analizando configuración débil para: {clean}...")
            weak_configs = self.risk_analyzer.analyze_risks(True, cert_info, tls_results)

            # 4.6. Generar recomendaciones
            recommendations = self.recommendation_service.generate_recommendations(
                clean, weak_configs
            )

            # 4.7. Calcular score de seguridad
            score = self.score_calculator.calculate_score(True, cert_info, tls_results)
            risk_level = self.score_calculator.determine_risk_level(score)

            # Compilar reporte
            report = SslTlsReport(
                domain=clean,
                https_available=True,
                certificate_info=cert_info,
                tls_versions=tls_results,
                weak_configurations=weak_configs,
                recommendations=recommendations,
                score=score,
                risk_level=risk_level,
                scan_date=scan_date,
            )
            reports.append(report)
            logger.info(
                f"Certificado obtenido y analizado correctamente para: {clean}. Score: {score} ({risk_level.value})"
            )

        except Exception as e:
            logger.error(f"Error inesperado procesando {clean}: {str(e)}")
            errors_list.append(
                {
                    "dominio": clean,
                    "tipo_error": "Error Inesperado",
                    "mensaje_error": str(e),
                    "fecha_analisis": scan_date,
                }
            )
            # Crear reporte fallido mínimo
            reports.append(
                SslTlsReport(
                    domain=clean,
                    https_available=False,
                    error=f"Error al analizar el dominio: {str(e)}",
                    scan_date=scan_date,
                )
            )

    def _handle_https_unavailable(
        self,
        clean: str,
        scan_date: datetime,
        reports: List[SslTlsReport],
        errors_list: List[Dict[str, Any]],
    ) -> None:
        logger.warning(f"HTTPS no disponible en: {clean}")
        report = SslTlsReport(
            domain=clean,
            https_available=False,
            error="El host no responde en puerto HTTPS (443 o puerto alternativo).",
            scan_date=scan_date,
        )
        # Llenar score y riesgo
        report.score = self.score_calculator.calculate_score(False, None, [])
        report.risk_level = self.score_calculator.determine_risk_level(report.score)
        report.weak_configurations = self.risk_analyzer.analyze_risks(False, None, [])
        report.recommendations = self.recommendation_service.generate_recommendations(
            clean, report.weak_configurations
        )

        reports.append(report)
        errors_list.append(
            {
                "dominio": clean,
                "tipo_error": "Conexión HTTPS",
                "mensaje_error": "HTTPS no disponible o puerto cerrado.",
                "fecha_analisis": scan_date,
            }
        )

    def _scan_tls_versions(self, clean: str, port: int) -> List[TlsVersionResult]:
        logger.info(f"Validando versiones TLS de: {clean}...")
        tls_results: List[TlsVersionResult] = []
        for ver in TlsVersion:
            supported = self.ssl_client.check_tls_version_supported(
                clean, port, ver, settings.TIMEOUT_SECONDS
            )
            res = self.tls_checker.check_version_status(ver, supported)
            tls_results.append(res)
        return tls_results

    def _export_reports(self, reports: List[SslTlsReport], errors_list: List[Dict[str, Any]]) -> None:
        # Generar nombres únicos
        excel_path = get_unique_filename(
            settings.OUTPUT_DIR, settings.EXCEL_REPORT_NAME, "xlsx"
        )
        json_path = get_unique_filename(
            settings.OUTPUT_DIR, settings.JSON_REPORT_NAME, "json"
        )

        logger.info("Generando reporte Excel...")
        # Pasar lista de errores para incluir en Hoja 6
        self.excel_exporter.export_with_errors(reports, excel_path, errors_list)

        logger.info("Generando reporte JSON...")
        self.json_exporter.export(reports, json_path)

        logger.info("Reportes generados correctamente en datos_salida/")
