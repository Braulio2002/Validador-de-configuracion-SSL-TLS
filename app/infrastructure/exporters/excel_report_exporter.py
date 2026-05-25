from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

from app.application.interfaces.report_exporter_interface import IReportExporter
from app.domain.entities.certificate_info import CertificateInfo
from app.domain.entities.ssl_tls_report import SslTlsReport
from app.domain.value_objects.tls_version import TlsVersion


class ExcelReportExporter(IReportExporter):
    def export(self, reports: List[SslTlsReport], output_path: Path) -> Path:
        """
        Implementación genérica de la interfaz. Llama a export_with_errors con lista de errores vacía.
        """
        return self.export_with_errors(reports, output_path, [])

    def export_with_errors(
        self, reports: List[SslTlsReport], output_path: Path, errors_list: List[Dict[str, Any]]
    ) -> Path:
        """
        Exporta los reportes a un libro de Excel con 6 pestañas diferenciadas,
        aplicando diseño limpio y cabeceras claras.
        """
        df_resumen = self._build_resumen_df(reports)
        df_cert = self._build_certificados_df(reports)
        df_tls = self._build_tls_df(reports)
        df_weak = self._build_weak_df(reports)
        df_rec = self._build_recommendations_df(reports)
        df_err = self._build_errors_df(errors_list)

        # Escribir todas las hojas usando ExcelWriter
        with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
            df_resumen.to_excel(writer, sheet_name="Resumen", index=False)
            df_cert.to_excel(writer, sheet_name="Certificados", index=False)
            df_tls.to_excel(writer, sheet_name="Versiones TLS", index=False)
            df_weak.to_excel(
                writer, sheet_name="Configuraciones Debiles", index=False)
            df_rec.to_excel(writer, sheet_name="Recomendaciones", index=False)
            df_err.to_excel(writer, sheet_name="Errores", index=False)

            self._adjust_column_dimensions(writer)

        return output_path

    def _build_resumen_df(self, reports: List[SslTlsReport]) -> pd.DataFrame:
        resumen_data = [self._build_resumen_row(rep) for rep in reports]
        return pd.DataFrame(resumen_data)

    def _build_resumen_row(self, rep: SslTlsReport) -> Dict[str, Any]:
        cert_valido = "NO"
        coincide_dom = "NO"
        dias_venc = 0

        if rep.certificate_info:
            ci = rep.certificate_info
            cert_valido = (
                "SÍ" if (
                    not ci.is_expired and ci.is_trusted and not ci.error) else "NO"
            )
            coincide_dom = "SÍ" if ci.matches_domain else "NO"
            dias_venc = ci.days_to_expire

        # Verificar TLS 1.2 y TLS 1.3
        t12_soportado = "NO"
        t13_soportado = "NO"
        for t in rep.tls_versions:
            if t.version == TlsVersion.TLS_1_2 and t.supported:
                t12_soportado = "SÍ"
            elif t.version == TlsVersion.TLS_1_3 and t.supported:
                t13_soportado = "SÍ"

        return {
            "dominio": rep.domain,
            "https_available": "SÍ" if rep.https_available else "NO",
            "certificado_valido": cert_valido,
            "coincide_dominio": coincide_dom,
            "dias_para_vencer": dias_venc,
            "tls_1_2_soportado": t12_soportado,
            "tls_1_3_soportado": t13_soportado,
            "configuraciones_debiles": len(rep.weak_configurations),
            "score": rep.score,
            "nivel_riesgo": rep.risk_level.value if rep.risk_level else "N/A",
            "error": rep.error or "",
            "fecha_analisis": rep.scan_date.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _build_certificados_df(self, reports: List[SslTlsReport]) -> pd.DataFrame:
        cert_data = [self._build_certificados_row(rep) for rep in reports]
        return pd.DataFrame(cert_data)

    def _build_certificados_row(self, rep: SslTlsReport) -> Dict[str, Any]:
        if rep.certificate_info:
            return self._build_certificados_valid_row(rep, rep.certificate_info)
        return self._build_certificados_invalid_row(rep)

    def _build_certificados_valid_row(
        self, rep: SslTlsReport, ci: CertificateInfo
    ) -> Dict[str, Any]:
        valido_desde = ci.valid_from.strftime(
            "%Y-%m-%d %H:%M:%S") if ci.valid_from else ""
        valido_hasta = ci.valid_until.strftime(
            "%Y-%m-%d %H:%M:%S") if ci.valid_until else ""
        expirado = "SÍ" if ci.is_expired else "NO"
        proximo_a_vencer = "SÍ" if ci.is_near_expiration else "NO"
        coincide_dominio = "SÍ" if ci.matches_domain else "NO"
        confiable = "SÍ" if ci.is_trusted else "NO"

        return {
            "dominio": rep.domain,
            "subject": ci.subject,
            "issuer": ci.issuer,
            "common_name": ci.common_name,
            "san_domains": ", ".join(ci.san_domains),
            "valido_desde": valido_desde,
            "valido_hasta": valido_hasta,
            "dias_para_vencer": ci.days_to_expire,
            "expirado": expirado,
            "proximo_a_vencer": proximo_a_vencer,
            "coincide_dominio": coincide_dominio,
            "confiable": confiable,
            "error": ci.error or "",
        }

    def _build_certificados_invalid_row(self, rep: SslTlsReport) -> Dict[str, Any]:
        return {
            "dominio": rep.domain,
            "subject": "",
            "issuer": "",
            "common_name": "",
            "san_domains": "",
            "valido_desde": "",
            "valido_hasta": "",
            "dias_para_vencer": 0,
            "expirado": "SÍ",
            "proximo_a_vencer": "SÍ",
            "coincide_dominio": "NO",
            "confiable": "NO",
            "error": rep.error or "Información de certificado no disponible.",
        }

    def _build_tls_df(self, reports: List[SslTlsReport]) -> pd.DataFrame:
        tls_data = []
        for rep in reports:
            for tv in rep.tls_versions:
                tls_data.append(
                    {
                        "dominio": rep.domain,
                        "version_tls": tv.version.value,
                        "soportado": "SÍ" if tv.supported else "NO",
                        "estado": tv.status.value,
                        "nivel_riesgo": tv.risk_level.value if tv.risk_level else "",
                        "recomendacion": tv.recommendation or "",
                    }
                )
        if not tls_data:
            return pd.DataFrame(
                columns=[
                    "dominio",
                    "version_tls",
                    "soportado",
                    "estado",
                    "nivel_riesgo",
                    "recomendacion",
                ]
            )
        return pd.DataFrame(tls_data)

    def _build_weak_df(self, reports: List[SslTlsReport]) -> pd.DataFrame:
        weak_data = []
        for rep in reports:
            for wc in rep.weak_configurations:
                weak_data.append(
                    {
                        "dominio": rep.domain,
                        "problema": wc.get("problema", ""),
                        "severidad": wc.get("severidad", ""),
                        "descripcion": wc.get("descripcion", ""),
                        "recomendacion": wc.get("recomendacion", ""),
                    }
                )
        if not weak_data:
            return pd.DataFrame(
                columns=["dominio", "problema", "severidad",
                         "descripcion", "recomendacion"]
            )
        return pd.DataFrame(weak_data)

    def _build_recommendations_df(self, reports: List[SslTlsReport]) -> pd.DataFrame:
        rec_data = []
        for rep in reports:
            for r in rep.recommendations:
                rec_data.append(
                    {
                        "dominio": r.get("dominio", ""),
                        "prioridad": r.get("prioridad", ""),
                        "problema": r.get("problema", ""),
                        "recomendacion": r.get("recomendacion", ""),
                    }
                )
        if not rec_data:
            return pd.DataFrame(columns=["dominio", "prioridad", "problema", "recomendacion"])
        return pd.DataFrame(rec_data)

    def _build_errors_df(self, errors_list: List[Dict[str, Any]]) -> pd.DataFrame:
        err_data = []
        for err in errors_list:
            fa = err.get("fecha_analisis")
            err_data.append(
                {
                    "dominio": err.get("dominio", ""),
                    "tipo_error": err.get("tipo_error", ""),
                    "mensaje_error": err.get("mensaje_error", ""),
                    "fecha_analisis": fa.strftime("%Y-%m-%d %H:%M:%S")
                    if isinstance(fa, datetime)
                    else str(fa),
                }
            )
        if not err_data:
            return pd.DataFrame(
                columns=["dominio", "tipo_error",
                         "mensaje_error", "fecha_analisis"]
            )
        return pd.DataFrame(err_data)

    def _adjust_column_dimensions(self, writer: pd.ExcelWriter) -> None:
        for name in writer.sheets:
            worksheet = writer.sheets[name]
            for col in worksheet.columns:
                max_len = max(len(str(cell.value or "")) for cell in col)
                col_letter = col[0].column_letter
                worksheet.column_dimensions[col_letter].width = max(
                    max_len + 3, 12)
