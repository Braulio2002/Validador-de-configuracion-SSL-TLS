from typing import Dict, List


class RecommendationService:
    def generate_recommendations(
        self, domain: str, weak_configurations: List[Dict[str, str]]
    ) -> List[Dict[str, str]]:
        """
        Toma los hallazgos de configuración débil y genera un listado limpio
        de recomendaciones con prioridad ordenada para el dominio.
        """
        recommendations = []

        # Mapeo de severidad a orden numérico de prioridad para clasificar y ordenar
        priority_order = {"CRÍTICO": 1, "ALTO": 2, "MEDIO": 3, "BAJO": 4}

        # Generar recomendaciones combinando severidad como prioridad
        for wc in weak_configurations:
            severity = wc.get("severidad", "BAJO")
            recommendations.append(
                {
                    "dominio": domain,
                    "prioridad": severity,  # E.g. CRÍTICO, ALTO, etc.
                    "problema": wc.get("problema", "Desconocido"),
                    "recomendacion": wc.get("recomendacion", ""),
                }
            )

        # Ordenar recomendaciones por severidad (CRÍTICO primero)
        recommendations.sort(
            key=lambda x: priority_order.get(x["prioridad"], 5))

        return recommendations
