import re
from typing import Optional, Tuple


class DomainValidatorService:
    # Basic domain validation regex
    DOMAIN_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9]"  # First character
        r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"  # Subdomains
        r"[a-zA-Z]{2,6}$"  # TLD (2 to 6 alphabetic chars)
    )

    def validate_and_normalize(self, raw_input: str) -> Optional[Tuple[str, int]]:
        """
        Valida el formato de un dominio y lo normaliza.
        Elimina esquemas HTTP/HTTPS, rutas, parámetros y espacios.
        Retorna una tupla (dominio_normalizado, puerto) o None si es inválido.
        """
        if not raw_input or not isinstance(raw_input, str):
            return None

        clean = raw_input.strip()

        # Eliminar protocolo si existe
        if clean.lower().startswith("http://"):
            clean = clean[7:]
        elif clean.lower().startswith("https://"):
            clean = clean[8:]

        # Eliminar ruta, query params, etc. si vienen en URL completa
        # E.g. 'google.com/search?q=1' -> 'google.com'
        clean = clean.split("/")[0].split("?")[0].split("#")[0]

        # Separar puerto si viene explícito (e.g. 'localhost:8443' o 'google.com:443')
        port = 443
        if ":" in clean:
            parts = clean.split(":")
            if len(parts) == 2:
                clean = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    return None  # Puerto inválido

        # Validar dominio limpio contra regex (también permitimos IPs de forma básica, pero dominis es lo principal)
        if not self.DOMAIN_REGEX.match(clean):
            # Check for localhosts / basic IP checks
            if not (
                clean == "localhost" or re.match(
                    r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean)
            ):
                return None

        return clean, port
