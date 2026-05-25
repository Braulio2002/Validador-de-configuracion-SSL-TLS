import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, List

from app.application.interfaces.report_exporter_interface import IReportExporter
from app.domain.entities.ssl_tls_report import SslTlsReport


class JsonReportExporter(IReportExporter):
    def export(self, reports: List[SslTlsReport], output_path: Path) -> Path:
        """
        Exporta los reportes generados a un archivo JSON con formato legible.
        """
        # Convertir recursivamente a estructuras serializables
        serialized = [self._to_serializable(r) for r in reports]

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(serialized, f, indent=4, ensure_ascii=False)

        return output_path

    def _to_serializable(self, obj: Any) -> Any:
        """
        Convierte recursivamente tipos de dominio (Dataclasses, Enums, Datetimes)
        a tipos primitivos de Python para serialización JSON segura.
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, Enum):
            return obj.value
        elif is_dataclass(obj):
            # Usar dict comprehension para recursividad personalizada
            return {key: self._to_serializable(val) for key, val in asdict(obj).items()}
        elif isinstance(obj, list):
            return [self._to_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {key: self._to_serializable(val) for key, val in obj.items()}
        return obj
