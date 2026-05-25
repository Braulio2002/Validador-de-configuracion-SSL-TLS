from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from app.domain.entities.ssl_tls_report import SslTlsReport


class IReportExporter(ABC):
    @abstractmethod
    def export(self, reports: List[SslTlsReport], output_path: Path) -> Path:
        """
        Exporta los reportes generados a la ruta especificada.
        Retorna la ruta del archivo generado.
        """
        pass
