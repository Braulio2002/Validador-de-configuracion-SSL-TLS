from app.config.settings import settings
from app.shared.logger import logger


class DirectoryManager:
    def ensure_directories(self) -> None:
        """
        Crea automáticamente las carpetas de datos de entrada y salida si no existen.
        También genera un domains.txt por defecto con ejemplos si está ausente.
        """
        # Crear carpetas principales
        settings.INPUT_DIR.mkdir(parents=True, exist_ok=True)
        settings.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        # Crear archivos .gitkeep
        (settings.INPUT_DIR / ".gitkeep").touch(exist_ok=True)
        (settings.OUTPUT_DIR / ".gitkeep").touch(exist_ok=True)

        # Crear domains.txt de ejemplo si no existe
        if not settings.DOMAINS_FILE.exists():
            logger.info(
                f"Creando archivo de dominios de ejemplo en: {settings.DOMAINS_FILE}")
            default_content = (
                "# Dominios de ejemplo autorizados para auditoría defensiva\n"
                "google.com\n"
                "midominio.com\n"
                "api.empresa.com\n"
                "https://app.empresa.com\n"
            )
            with open(settings.DOMAINS_FILE, "w", encoding="utf-8") as f:
                f.write(default_content)
