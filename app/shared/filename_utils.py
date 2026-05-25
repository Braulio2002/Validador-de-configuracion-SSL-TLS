from pathlib import Path


def get_unique_filename(directory: Path, base_name: str, extension: str) -> Path:
    """
    Genera un nombre de archivo único dentro del directorio especificado.
    Si 'base_name.extension' ya existe, intenta con 'base_name_1.extension',
    'base_name_2.extension', etc.
    """
    ext = extension.lstrip(".")
    candidate = directory / f"{base_name}.{ext}"
    if not candidate.exists():
        return candidate

    counter = 1
    while True:
        candidate = directory / f"{base_name}_{counter}.{ext}"
        if not candidate.exists():
            return candidate
        counter += 1
