import socket
import ssl
from datetime import timezone

import cryptography.x509
from cryptography.x509.oid import NameOID

from app.application.interfaces.ssl_client_interface import ISslClient
from app.domain.entities.certificate_info import CertificateInfo
from app.domain.value_objects.tls_version import TlsVersion
from app.shared.logger import logger


class PythonSslClient(ISslClient):
    def check_https_available(self, domain: str, port: int, timeout: float) -> bool:
        """
        Verifica si el puerto responde y permite completar un saludo SSL básico.
        """
        try:
            # Intento de conexión socket básico
            sock = socket.create_connection((domain, port), timeout=timeout)
            sock.close()

            # Intento de handshake SSL básico con verificación deshabilitada para soportar certificados autofirmados/vencidos
            context = ssl._create_unverified_context()  # nosec

            with socket.create_connection((domain, port), timeout=timeout) as s:
                with context.wrap_socket(s, server_hostname=domain) as ss:
                    _ = ss.cipher()
            return True
        except Exception as e:
            logger.debug(f"HTTPS verificación fallida para {domain}: {str(e)}")
            return False

    def get_certificate_info(self, domain: str, port: int, timeout: float) -> CertificateInfo:
        """
        Obtiene y parsea la información del certificado, incluso si tiene errores de validez.
        Usa cryptography para parsear los bytes binarios (DER).
        """
        cert_info = CertificateInfo()
        is_trusted = False
        handshake_error = None

        # Paso 1: Intentar handshake de confianza (verificación activa)
        context_trusted = ssl.create_default_context()
        context_trusted.check_hostname = True
        context_trusted.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((domain, port), timeout=timeout) as s:
                with context_trusted.wrap_socket(s, server_hostname=domain) as ss:
                    # Si esto tiene éxito, el certificado es de plena confianza para el sistema operativo
                    is_trusted = True
        except ssl.SSLCertVerificationError as ve:
            handshake_error = (
                f"Error de verificación: {ve.verify_message} (Código {ve.verify_code})"
            )
            is_trusted = False
        except ssl.SSLError as se:
            handshake_error = f"SSL Error: {str(se)}"
            is_trusted = False
        except Exception as e:
            handshake_error = f"Error de conexión: {str(e)}"
            is_trusted = False

        # Paso 2: Conectar con validación desactivada para extraer el certificado DER
        context_unverified = ssl._create_unverified_context()  # nosec

        try:
            with socket.create_connection((domain, port), timeout=timeout) as s:
                with context_unverified.wrap_socket(s, server_hostname=domain) as ss:
                    der_data = ss.getpeercert(binary_form=True)
                    if not der_data:
                        cert_info.error = (
                            handshake_error or "No se pudo extraer el certificado binario."
                        )
                        return cert_info
        except Exception as e:
            cert_info.error = (
                handshake_error or f"Error al recuperar certificado sin verificación: {str(e)}"
            )
            return cert_info

        # Paso 3: Parsear los bytes DER usando la librería cryptography
        try:
            cert = cryptography.x509.load_der_x509_certificate(der_data)

            # Extraer CN (Common Name)
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            common_name = cn_attrs[0].value if cn_attrs else ""

            # Extraer SANs (Subject Alternative Names)
            san_domains = []
            try:
                san_ext = cert.extensions.get_extension_for_class(
                    cryptography.x509.SubjectAlternativeName
                )
                san_domains = san_ext.value.get_values_for_type(
                    cryptography.x509.DNSName)
            except cryptography.x509.ExtensionNotFound:
                pass

            # Extraer fechas de validez con compatibilidad hacia atrás
            if hasattr(cert, "not_valid_before_utc"):
                valid_from = cert.not_valid_before_utc
                valid_until = cert.not_valid_after_utc
            else:
                # Versiones más antiguas de cryptography
                valid_from = cert.not_valid_before.replace(tzinfo=timezone.utc)
                valid_until = cert.not_valid_after.replace(tzinfo=timezone.utc)

            # Llenar datos de la entidad
            cert_info.subject = cert.subject.rfc4514_string()
            cert_info.issuer = cert.issuer.rfc4514_string()
            cert_info.common_name = common_name
            cert_info.san_domains = san_domains
            cert_info.valid_from = valid_from
            cert_info.valid_until = valid_until
            cert_info.is_trusted = is_trusted

            if not is_trusted and handshake_error:
                cert_info.error = handshake_error

        except Exception as e:
            cert_info.error = f"Error al parsear el certificado: {str(e)}"

        return cert_info

    def check_tls_version_supported(
        self, domain: str, port: int, version: TlsVersion, timeout: float
    ) -> bool:
        """
        Prueba de forma proactiva y segura si el servidor remoto soporta la versión especificada.
        Asegura compatibilidad con las configuraciones OpenSSL del host local.
        """
        # Mapear versiones de TlsVersion a ssl.TLSVersion si existen
        tls_version_mapping = {}
        if hasattr(ssl, "TLSVersion"):
            if hasattr(ssl.TLSVersion, "SSLv3"):
                tls_version_mapping[TlsVersion.SSLV3] = ssl.TLSVersion.SSLv3
            if hasattr(ssl.TLSVersion, "TLSv1"):
                tls_version_mapping[TlsVersion.TLS_1_0] = ssl.TLSVersion.TLSv1
            if hasattr(ssl.TLSVersion, "TLSv1_1"):
                tls_version_mapping[TlsVersion.TLS_1_1] = ssl.TLSVersion.TLSv1_1
            if hasattr(ssl.TLSVersion, "TLSv1_2"):
                tls_version_mapping[TlsVersion.TLS_1_2] = ssl.TLSVersion.TLSv1_2
            if hasattr(ssl.TLSVersion, "TLSv1_3"):
                tls_version_mapping[TlsVersion.TLS_1_3] = ssl.TLSVersion.TLSv1_3

        # Si el cliente OpenSSL local no soporta ni define la versión, asumimos False (no negociable localmente)
        if version not in tls_version_mapping:
            # SSLv2 no se expone directamente en TLSVersion moderno. Lo manejamos como no soportado
            return False

        tls_enum = tls_version_mapping[version]

        # Crear contexto forzando únicamente la versión a evaluar
        context = ssl._create_unverified_context()  # nosec

        try:
            context.minimum_version = tls_enum
            context.maximum_version = tls_enum
        except (ValueError, ssl.SSLError, AttributeError):
            # La librería SSL local o el sistema operativo no permiten configurar esta versión específica
            return False

        try:
            with socket.create_connection((domain, port), timeout=timeout) as s:
                with context.wrap_socket(s, server_hostname=domain) as ss:
                    _ = ss.cipher()
                    return True
        except Exception:
            # Si hay cualquier error de handshake, asumimos que no se soporta
            return False
