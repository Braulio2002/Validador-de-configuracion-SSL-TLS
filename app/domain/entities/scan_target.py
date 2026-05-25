from dataclasses import dataclass
from datetime import datetime


@dataclass
class ScanTarget:
    dominio_original: str
    dominio_normalizado: str
    puerto: int
    fecha_analisis: datetime
