from app.application.services.domain_validator_service import DomainValidatorService


def test_domain_normalization_schemes():
    service = DomainValidatorService()

    assert service.validate_and_normalize("https://google.com") == ("google.com", 443)
    assert service.validate_and_normalize("http://api.example.com") == ("api.example.com", 443)
    assert service.validate_and_normalize("google.com") == ("google.com", 443)


def test_domain_normalization_paths_and_queries():
    service = DomainValidatorService()

    assert service.validate_and_normalize("https://google.com/search?q=query") == (
        "google.com",
        443,
    )
    assert service.validate_and_normalize("api.example.com/v1/users#section") == (
        "api.example.com",
        443,
    )


def test_domain_normalization_custom_port():
    service = DomainValidatorService()

    assert service.validate_and_normalize("example.com:8443") == ("example.com", 8443)
    assert service.validate_and_normalize("https://myhost.com:9443/api") == ("myhost.com", 9443)


def test_invalid_domains():
    service = DomainValidatorService()

    assert service.validate_and_normalize("not_a_domain") is None
    assert service.validate_and_normalize("") is None
    assert service.validate_and_normalize("  ") is None
    assert service.validate_and_normalize("invalid@domain.com") is None
