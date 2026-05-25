from typing import Dict

# TLS/SSL Standard Versions Identifiers
TLS_SSL_VERSIONS = {
    "SSLV2": "SSLv2",
    "SSLV3": "SSLv3",
    "TLS_1_0": "TLS 1.0",
    "TLS_1_1": "TLS 1.1",
    "TLS_1_2": "TLS 1.2",
    "TLS_1_3": "TLS 1.3",
}

# Severity/Priority strings to avoid duplication
PRIORITY_CRITICAL = "CRÍTICA"
PRIORITY_HIGH = "ALTA"
PRIORITY_MEDIUM = "MEDIA"
PRIORITY_LOW = "BAJA"

# Standard recommendation maps for specific weaknesses
RECOMMENDATIONS: Dict[str, Dict[str, str]] = {
    "HTTPS_UNAVAILABLE": {
        "problem": "HTTPS no disponible en el puerto 443.",
        "priority": PRIORITY_CRITICAL,
        "recomendacion": "Asegúrese de que el servidor web tenga instalado un certificado SSL/TLS y escuche en el puerto 443. Configure una redirección HTTP (puerto 80) a HTTPS (puerto 443).",
    },
    "CERT_EXPIRED": {
        "problem": "El certificado SSL/TLS ha expirado o aún no es válido.",
        "priority": PRIORITY_CRITICAL,
        "recomendacion": "Renueve el certificado SSL/TLS inmediatamente. Se recomienda usar herramientas de automatización como Certbot / Let's Encrypt para evitar futuras expiraciones.",
    },
    "CERT_NEAR_EXPIRATION": {
        "problem": "El certificado SSL/TLS está próximo a vencer.",
        "priority": PRIORITY_HIGH,
        "recomendacion": "Programe la renovación del certificado SSL/TLS antes de la fecha de vencimiento configurada.",
    },
    "CERT_DOMAIN_MISMATCH": {
        "problem": "El nombre del dominio no coincide con el Common Name (CN) ni con los Subject Alternative Names (SAN) del certificado.",
        "priority": PRIORITY_HIGH,
        "recomendacion": "Genere e instale un certificado que contenga el nombre de dominio correcto en el CN o en la lista de SANs.",
    },
    "CERT_UNTRUSTED": {
        "problem": "La cadena de confianza del certificado no pudo ser verificada (certificado autofirmado, emisor desconocido o cadena incompleta).",
        "priority": PRIORITY_HIGH,
        "recomendacion": "Utilice certificados emitidos por una Autoridad de Certificación (CA) de confianza pública. Si es un entorno interno, asegúrese de que la CA raíz esté instalada en el almacén de confianza de los clientes.",
    },
    "SSLV2_ENABLED": {
        "problem": "Protocolo SSLv2 habilitado.",
        "priority": PRIORITY_CRITICAL,
        "recomendacion": "Deshabilite completamente SSLv2 en la configuración del servidor web o balanceador de carga. Este protocolo es vulnerable a ataques graves y ha sido retirado (obsoleto desde 2011).",
    },
    "SSLV3_ENABLED": {
        "problem": "Protocolo SSLv3 habilitado.",
        "priority": PRIORITY_CRITICAL,
        "recomendacion": "Deshabilite completamente SSLv3 en el servidor web. Es vulnerable al ataque POODLE y ha sido declarado obsoleto (RFC 7568).",
    },
    "TLS10_ENABLED": {
        "problem": "Protocolo TLS 1.0 habilitado.",
        "priority": PRIORITY_HIGH,
        "recomendacion": "Deshabilite TLS 1.0. Las normativas de cumplimiento como PCI-DSS prohíben su uso debido a debilidades criptográficas (vulnerabilidad BEAST, entre otras).",
    },
    "TLS11_ENABLED": {
        "problem": "Protocolo TLS 1.1 habilitado.",
        "priority": PRIORITY_MEDIUM,
        "recomendacion": "Deshabilite TLS 1.1. Aunque es menos vulnerable que TLS 1.0, se considera débil y ya no se recomienda su uso en entornos modernos (obsoleto por RFC 8996).",
    },
    "TLS12_DISABLED": {
        "problem": "Protocolo TLS 1.2 no soportado.",
        "priority": PRIORITY_MEDIUM,
        "recomendacion": "Habilite el soporte para TLS 1.2. Actualmente es el estándar de compatibilidad mínima y debe permanecer activo para soportar clientes que no puedan negociar TLS 1.3.",
    },
    "TLS13_DISABLED": {
        "problem": "Protocolo TLS 1.3 no soportado.",
        "priority": PRIORITY_LOW,
        "recomendacion": "Habilite TLS 1.3 para mejorar el rendimiento del handshake y aprovechar los algoritmos criptográficos más modernos y seguros.",
    },
    "CERT_CHAIN_INCOMPLETE": {
        "problem": "Cadena de certificados intermedios incompleta o incorrecta.",
        "priority": PRIORITY_HIGH,
        "recomendacion": "Configure el servidor web para que entregue la cadena completa de certificados, incluyendo todos los certificados intermedios hasta la CA raíz.",
    },
}
