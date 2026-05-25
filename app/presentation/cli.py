import sys
from typing import Any, Dict, List

from app.application.services.certificate_analyzer_service import CertificateAnalyzerService
from app.application.services.domain_validator_service import DomainValidatorService
from app.application.services.recommendation_service import RecommendationService
from app.application.services.risk_analyzer_service import RiskAnalyzerService
from app.application.services.score_calculator_service import ScoreCalculatorService
from app.application.services.tls_version_checker_service import TlsVersionCheckerService
from app.application.use_cases.validate_ssl_tls_use_case import ValidateSslTlsUseCase
from app.infrastructure.exporters.excel_report_exporter import ExcelReportExporter
from app.infrastructure.exporters.json_report_exporter import JsonReportExporter
from app.infrastructure.filesystem.directory_manager import DirectoryManager
from app.infrastructure.readers.txt_domain_reader import TxtDomainReader
from app.infrastructure.ssl.python_ssl_client import PythonSslClient
from app.shared.logger import logger


class Cli:
    def run(self) -> None:
        """
        Inicializa las dependencias e invoca el caso de uso principal,
        mostrando finalmente un resumen visual detallado y premium en la consola.
        """
        # Inicialización de la cadena de Clean Architecture (Inversión de dependencias)
        dir_manager = DirectoryManager()
        reader = TxtDomainReader()
        ssl_client = PythonSslClient()
        excel_exporter = ExcelReportExporter()
        json_exporter = JsonReportExporter()

        validator = DomainValidatorService()
        cert_analyzer = CertificateAnalyzerService()
        tls_checker = TlsVersionCheckerService()
        risk_analyzer = RiskAnalyzerService()
        score_calculator = ScoreCalculatorService()
        rec_service = RecommendationService()

        # Instanciar el caso de uso
        use_case = ValidateSslTlsUseCase(
            directory_manager=dir_manager,
            domain_reader=reader,
            ssl_client=ssl_client,
            excel_exporter=excel_exporter,
            json_exporter=json_exporter,
            domain_validator=validator,
            cert_analyzer=cert_analyzer,
            tls_checker=tls_checker,
            risk_analyzer=risk_analyzer,
            score_calculator=score_calculator,
            recommendation_service=rec_service,
        )

        try:
            # Ejecutar el flujo de negocio coordinado
            reports, global_errors = use_case.execute()

            # Presentar el resumen en la consola
            self._render_summary(reports, global_errors)

        except Exception as e:
            logger.critical(f"Proceso detenido debido a un error crítico global: {str(e)}")
            sys.exit(1)

    def _render_summary(
        self, reports: List[Any], errors: List[Dict[str, Any]]
    ) -> None:
        """
        Dibuja un resumen en consola con diseño estilizado y alineado,
        adecuado para una entrega profesional de auditorías de ciberseguridad.
        """
        print("\n" + "=" * 80)
        print(" " * 25 + "AUDITORÍA DE CONFIGURACIÓN SSL/TLS Completada")
        print("=" * 80)

        if not reports:
            print(
                " [!] No se analizaron dominios. Verifique el archivo 'datos_entrada/domains.txt'."
            )
            print("=" * 80 + "\n")
            return

        total_scanned = len(reports)
        https_ok = sum(1 for r in reports if r.https_available)
        total_weak = sum(len(r.weak_configurations) for r in reports)
        avg_score = sum(r.score for r in reports) / total_scanned if total_scanned > 0 else 0
        total_errors = len(errors)

        print(f" [*] Dominios Escaneados: {total_scanned}")
        print(f" [*] HTTPS Disponibles : {https_ok} / {total_scanned}")
        print(f" [*] Hallazgos de Riesgo: {total_weak}")
        print(f" [*] Score Promedio     : {avg_score:.2f} / 100")
        print(f" [*] Total de Errores   : {total_errors}")
        print("-" * 80)

        # Imprimir tabla resumida de resultados
        print(
            f"{'DOMINIO':<25} | {'HTTPS':<6} | {'CERT. VÁLIDO':<12} | {'SCORE':<6} | {'RIESGO':<10} | {'FINDINGS':<8}"
        )
        print("-" * 80)

        for r in reports:
            cert_valido = (
                "SÍ"
                if (
                    r.certificate_info
                    and not r.certificate_info.is_expired
                    and r.certificate_info.is_trusted
                    and not r.certificate_info.error
                )
                else "NO"
            )
            https_str = "SÍ" if r.https_available else "NO"
            score_str = f"{r.score:.1f}"
            riesgo_str = r.risk_level.value if r.risk_level else "CRÍTICO"
            weak_count = len(r.weak_configurations)

            # Cortar dominio si es muy largo para no romper la tabla
            dom_truncated = r.domain[:23] + ".." if len(r.domain) > 25 else r.domain
            print(
                f"{dom_truncated:<25} | {https_str:<6} | {cert_valido:<12} | {score_str:<6} | {riesgo_str:<10} | {weak_count:<8}"
            )

        print("=" * 80)
        print(" [i] Los reportes detallados han sido guardados en el directorio: 'datos_salida/'")
        print("     - Reporte Excel (con múltiples hojas): ssl_tls_report*.xlsx")
        print("     - Reporte JSON completo: ssl_tls_report*.json")
        print("=" * 80 + "\n")
