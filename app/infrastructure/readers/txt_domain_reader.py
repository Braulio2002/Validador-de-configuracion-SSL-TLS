from pathlib import Path
from typing import List

from app.application.interfaces.domain_reader_interface import IDomainReader
from app.domain.exceptions.domain_exceptions import ReaderException


class TxtDomainReader(IDomainReader):
    def read_domains(self, file_path: Path) -> List[str]:
        """
        Lee dominios desde un archivo TXT, omitiendo comentarios, líneas vacías y duplicados.
        Mantiene el orden original de inserción.
        """
        if not file_path.exists():
            raise ReaderException(
                f"El archivo de dominios no existe en la ruta: {file_path}")

        domains = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    clean_line = line.strip()
                    # Ignorar comentarios y líneas vacías
                    if not clean_line or clean_line.startswith("#"):
                        continue
                    domains.append(clean_line)
        except Exception as e:
            raise ReaderException(
                f"Error de lectura en archivo TXT: {str(e)}") from e

        # Remover duplicados manteniendo el orden (usando dict.fromkeys)
        return list(dict.fromkeys(domains))
