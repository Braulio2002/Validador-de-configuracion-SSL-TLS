class DomainException(Exception):
    """Base exception for all domain logic related errors."""

    pass


class InvalidDomainException(DomainException):
    """Raised when a domain format is invalid or empty."""

    pass


class ConnectionException(DomainException):
    """Raised when a socket connection cannot be established."""

    pass


class SSLValidationException(DomainException):
    """Raised when there is a severe SSL handshake or parsing failure."""

    pass


class ReaderException(DomainException):
    """Raised when inputs could not be read."""

    pass
