from app.application.services.recommendation_service import RecommendationService


def test_recommendation_priority_sorting():
    service = RecommendationService()

    weak_configs = [
        {"problema": "TLS13_DISABLED", "severidad": "BAJO", "recomendacion": "Habilitar TLS 1.3"},
        {
            "problema": "CERT_EXPIRED",
            "severidad": "CRÍTICO",
            "recomendacion": "Renovar certificado",
        },
        {
            "problema": "CERT_DOMAIN_MISMATCH",
            "severidad": "ALTO",
            "recomendacion": "Configurar CN correcto",
        },
        {
            "problema": "TLS11_ENABLED",
            "severidad": "MEDIO",
            "recomendacion": "Deshabilitar TLS 1.1",
        },
    ]

    recs = service.generate_recommendations("example.com", weak_configs)

    assert len(recs) == 4
    # Verificar ordenación: CRÍTICO -> ALTO -> MEDIO -> BAJO
    assert recs[0]["prioridad"] == "CRÍTICO"
    assert recs[1]["prioridad"] == "ALTO"
    assert recs[2]["prioridad"] == "MEDIO"
    assert recs[3]["prioridad"] == "BAJO"

    assert recs[0]["dominio"] == "example.com"
    assert recs[0]["problema"] == "CERT_EXPIRED"
