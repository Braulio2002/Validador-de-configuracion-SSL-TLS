from enum import Enum


class TlsVersion(str, Enum):
    SSLV2 = "SSLv2"
    SSLV3 = "SSLv3"
    TLS_1_0 = "TLS 1.0"
    TLS_1_1 = "TLS 1.1"
    TLS_1_2 = "TLS 1.2"
    TLS_1_3 = "TLS 1.3"
