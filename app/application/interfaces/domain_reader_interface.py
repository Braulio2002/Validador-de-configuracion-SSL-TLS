from abc import ABC, abstractmethod
from pathlib import Path
from typing import List


class IDomainReader(ABC):
    @abstractmethod
    def read_domains(self, file_path: Path) -> List[str]:
        """
        Lee una lista de dominios desde el archivo especificado.
        Debe omitir líneas vacías, comentarios y duplicados.
        """
        pass
