# 🛡️ Enterprise SSL/TLS Configuration Validator
> **Auditoría Avanzada, Scoring Dinámico y Hardening de Seguridad de Redes**

[![Python Version](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Architecture](https://img.shields.io/badge/Architecture-Clean%20%2F%20SOLID-orange.svg?style=for-the-badge)](https://en.wikipedia.org/wiki/Clean_Architecture)
[![Quality Gate](https://img.shields.io/badge/Ruff-Passed%20100%25-green.svg?style=for-the-badge)](https://github.com/astral-sh/ruff)
[![Tests](https://img.shields.io/badge/Tests-16%20Passed-brightgreen.svg?style=for-the-badge)](https://docs.pytest.org/)

El **Enterprise SSL/TLS Configuration Validator** es una solución defensiva de ciberseguridad industrial y auditoría web en Python. Diseñada bajo principios estrictos de **Clean Architecture** y **SOLID**, esta herramienta realiza análisis exhaustivos e individuales del estado criptográfico y de cifrado de múltiples dominios de forma concurrente, resiliencia ante fallos de conexión y una evaluación de riesgos integrada orientada a cumplimiento normativo (**PCI-DSS**, **RFC 8996**, **RFC 7568**).

---

> [!WARNING]
> **DECLARACIÓN DE USO AUTORIZADO Y ÉTICA**  
> Esta suite de herramientas ha sido desarrollada exclusivamente para auditorías de seguridad defensivas y control de cumplimiento en redes internas u organizaciones con consentimiento expreso por escrito. El escaneo no autorizado de dominios externos o de terceros puede violar regulaciones locales e internacionales de ciberdelincuencia. Úselo de manera responsable y ética.

---

## 🏗️ Arquitectura del Software (Clean Architecture)

El software divide estrictamente sus responsabilidades para aislar la **lógica de negocio** de los detalles de **infraestructura**, facilitando su extensibilidad, testeo unitario y robustez ante fallos. El dominio central no posee importaciones de librerías de terceros.

```
ssl_tls_validator/
│
├── app/
│   ├── main.py                     # Punto de entrada y Bootstrap de inyección de dependencias
│   │
│   ├── config/
│   │   └── settings.py             # Parámetros del motor de escaneo y matriz de pesos del Scoring
│   │
│   ├── domain/                     # Capa de Dominio (Pura, sin dependencias externas)
│   │   ├── entities/               # Entidades ricas y modelos de datos
│   │   │   ├── scan_target.py
│   │   │   ├── certificate_info.py
│   │   │   ├── tls_version_result.py
│   │   │   └── ssl_tls_report.py
│   │   │
│   │   ├── value_objects/          # Objetos de Valor inmutables y Enums
│   │   │   ├── tls_version.py
│   │   │   ├── check_status.py
│   │   │   └── risk_level.py
│   │   │
│   │   └── exceptions/             # Excepciones de negocio tipadas
│   │       └── domain_exceptions.py
│   │
│   ├── application/                # Capa de Aplicación (Orquestación y Reglas de Negocio)
│   │   ├── use_cases/
│   │   │   └── validate_ssl_tls_use_case.py  # Orquestador lineal del proceso
│   │   │
│   │   ├── services/               # Servicios de dominio y algoritmos matemáticos
│   │   │   ├── domain_validator_service.py
│   │   │   ├── certificate_analyzer_service.py
│   │   │   ├── tls_version_checker_service.py
│   │   │   ├── risk_analyzer_service.py
│   │   │   ├── score_calculator_service.py
│   │   │   └── recommendation_service.py
│   │   │
│   │   └── interfaces/             # Puertos y Abstracciones (Inversión de Dependencias)
│   │       ├── domain_reader_interface.py
│   │       ├── ssl_client_interface.py
│   │       └── report_exporter_interface.py
│   │
│   ├── infrastructure/             # Capa de Infraestructura (Implementaciones Concretas y E/S)
│   │   ├── readers/
│   │   │   └── txt_domain_reader.py          # Lector y sanitizador robusto de domains.txt
│   │   │
│   │   ├── ssl/
│   │   │   └── python_ssl_client.py          # Socket de bajo nivel y parseador DER X.509
│   │   │
│   │   ├── exporters/
│   │   │   ├── excel_report_exporter.py      # Generador del libro Excel de 6 hojas altamente estilizado
│   │   │   └── json_report_exporter.py       # Exportador nativo JSON para integración en Pipelines
│   │   │
│   │   └── filesystem/
│   │       └── directory_manager.py          # Manager de carpetas e inicialización automática
│   │
│   └── shared/                     # Utilidades transversales desacopladas
│       ├── logger.py
│       ├── constants.py
│       └── filename_utils.py
│
├── tests/                          # Suite completa de verificación
│   ├── unit/                       # Cobertura unitaria de todos los servicios
│   │   ├── test_domain_validator.py
│   │   ├── test_certificate_analyzer.py
│   │   ├── test_tls_version_checker.py
│   │   ├── test_score_calculator.py
│   │   └── test_recommendation_service.py
│   │
│   └── integration/                # Test de integración del flujo coordinado
│       └── test_validate_ssl_tls_flow.py
│
├── datos_entrada/                  # Directorio autogenerado para archivos de entrada
│   └── domains.txt
│
├── datos_salida/                   # Directorio autogenerado para reportes (histórico)
│
├── pyproject.toml                  # Configuración central del linter Ruff y PyTest
├── requirements.txt                # Dependencias estrictas del entorno
└── README.md                       # Documentación Técnica
```

---

## ⚡ Capacidades del Motor de Escaneo

* **Auditoría Multiversión de Handshakes**: Inspección activa del comportamiento de negociación del servidor ante protocolos legados e inseguros (`SSLv2`, `SSLv3`, `TLS 1.0`, `TLS 1.1`) y los estándares actuales recomendados (`TLS 1.2`, `TLS 1.3`).
* **Decodificación Binaria DER X.509**: A través de un enfoque de doble handshake defensivo, si la cadena de confianza falla (certificados autofirmados, expirados, o con nombres incorrectos), la herramienta se conecta mediante un contexto TLS no verificado para capturar el certificado binario y decodificar metadatos críticos como Common Name (CN), Subject Alternative Names (SAN), Issuer y periodos de validez directamente desde los bytes de la firma.
* **Sanitización Inteligente**: Detección y normalización automatizada de URLs, puertos custom (e.g. `dominio.com:443/ruta?query`), protocolos implícitos (`http://`), eliminando duplicaciones y espacios en blanco.
* **Resiliencia Operativa**: Los fallos por resolución DNS, timeouts o denegaciones de conexión en puertos cerrados no detienen la auditoría global. Estos hosts se marcan individualmente y se registran en una hoja de errores para un posterior triaje.
* **Scoring Ponderado Multicriterio**: Asignación de una puntuación matemática estricta sobre 100 basada en la robustez general de la configuración.
* **Hardening Prescriptivo**: Generación automatizada de recomendaciones de hardening estructuradas, priorizadas por criticidad e indicando el archivo RFC de referencia o la acción paliativa concreta.

---

## ⚙️ Especificaciones Técnicas y Requisitos

La solución ha sido construida con enfoque en minimalismo y alto rendimiento.
- **Plataforma de Ejecución**: Python 3.11 o superior.
- **Frameworks de Infraestructura**:
  - `cryptography`: Criptografía avanzada para interactuar con certificados X.509 e interpretar bytes DER.
  - `pandas`: Modelado bidimensional y manipulación de datos tabulares.
  - `openpyxl`: Inyección de diseño y hojas de estilos de celdas en archivos de Microsoft Excel.
  - `pytest` & `pytest-asyncio`: Automatización del control de calidad del código.
  - `ruff`: Linter de alto rendimiento.

---

## 🚀 Guía de Instalación y Despliegue Rápido

Siga estos sencillos pasos para aprovisionar el entorno virtual y poner en marcha el validador:

### 1. Preparación del Directorio
Acceda a la raíz del proyecto desde su consola de comandos:
```bash
cd "Validador de configuración SSL & TLS"
```

### 2. Creación y Activación de Entorno Virtual

**En sistemas Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**En sistemas Linux o macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instalación de Dependencias
Asegure el aprovisionamiento de las versiones correctas de las librerías utilizando el archivo `requirements.txt`:
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configuración del Archivo de Entrada
Al ejecutar el validador por primera vez, este inicializará automáticamente los directorios requeridos y generará un archivo `datos_entrada/domains.txt` con ejemplos predeterminados. Puede modificar este archivo escribiendo un host por línea:
```text
# Archivo de Auditoría - Enterprise SSL/TLS Validator
google.com
expired.badssl.com
self-signed.badssl.com
https://example.com:443/index.html
```

### 5. Lanzamiento del Motor de Auditoría
Inicie el análisis ejecutando el módulo principal:
```bash
python -m app.main
```

---

## 📊 Matriz Matemática de Scoring (Puntuación de Seguridad)

La puntuación final asignada a cada servidor auditado se calcula en `app/application/services/score_calculator_service.py` basándose en las variables de configuración de peso declaradas en `app/config/settings.py` (las cuales suman un total de **100 puntos**):

| Criterio de Auditoría | Peso Asignado | Justificación de Ciberseguridad / Cumplimiento |
| :--- | :---: | :--- |
| **HTTPS Disponible** | `15` pts | Disponibilidad de respuesta cifrada en el puerto 443. |
| **Certificado Válido** | `25` pts | Vigencia del certificado temporal y cadena de CA pública y firmada. |
| **Coincidencia de Dominio** | `15` pts | El dominio coincide con Common Name (CN) o Subject Alternative Names (SAN). |
| **No Próximo a Expirar** | `10` pts | El certificado no vencerá en el umbral de advertencia (default: 30 días). |
| **Soporte TLS 1.2** | `10` pts | Estándar base global recomendado para máxima compatibilidad de clientes seguros. |
| **Soporte TLS 1.3** | `10` pts | Protocolo de máxima seguridad con handshake simplificado y algoritmos modernos. |
| **Ausencia de TLS 1.0** | `5` pts | Cumplimiento estricto de **PCI-DSS**. TLS 1.0 cuenta con vulnerabilidades conocidas. |
| **Ausencia de TLS 1.1** | `5` pts | Obsolescencia dictada por la **RFC 8996**. |
| **Ausencia de SSLv2/v3** | `5` pts | Mitigación del ataque **POODLE** e inseguridad criptográfica absoluta. |

### Clasificación y Umbrales de Nivel de Riesgo Corporativo

```
 🟢 90.0 - 100.0  --> EXCELENTE  [Riesgo Bajo]
 🔵 75.0 - 89.9   --> BUENO      [Riesgo Bajo]
 🟡 50.0 - 74.9   --> REGULAR    [Riesgo Medio]
 🟠 25.0 - 49.9   --> RIESGOSO   [Riesgo Alto]
 🔴  0.0 - 24.9   --> CRÍTICO    [Riesgo Crítico]
```

---

## 📊 Estructura Profesional de Reportes Generados

Los archivos de salida se escriben dentro de la carpeta `datos_salida/`. Para evitar la sobreescritura accidental de evidencias en auditorías pasadas, los nombres de archivos incluyen un número incremental automático (`ssl_tls_report_1.xlsx`, `ssl_tls_report_2.xlsx`, etc.).

### Reporte de Auditoría Excel Corporativo (`.xlsx`)
El reporte Excel de nivel corporativo incluye **6 hojas de trabajo (Worksheets)** estructuradas con colores armoniosos (paleta de HSL profesional) y formato automatizado de anchos de columna:

1. **📊 Resumen General**: Una vista de nivel directivo (C-Level) que consolida para cada dominio el estado general de HTTPS, el Score de Seguridad numérico, la Clasificación Cualitativa del Riesgo, la cantidad de fallos de configuración hallados, los días de vigencia restantes en su certificado, y el cumplimiento de protocolos estándar (TLS 1.2/1.3).
2. **📜 Certificados**: Detalle forense de los certificados X.509 capturados de cada host (Common Name, Issuer, Subject, lista completa de SANs, fechas exactas de validez, errores del sistema operativo al verificar la firma de confianza y días restantes para la fecha de expiración).
3. **⚙️ Versiones TLS**: Una matriz completa y granular indicando el soporte explícito de cada servidor para cada protocolo (`SSLv2`, `SSLv3`, `TLS 1.0`, `TLS 1.1`, `TLS 1.2`, `TLS 1.3`), especificando las advertencias técnicas si los protocolos prohibidos se encuentran activos.
4. **⚠️ Configuraciones Débiles**: Bitácora centralizada de todos los hallazgos de debilidades de seguridad identificados, asignando severidad del riesgo y una descripción del problema técnico para agilizar el triaje.
5. **🎯 Recomendaciones**: Plan de acción e instrucciones ordenadas con prioridad cronológica (desde severidad Crítica a Baja) que los administradores de sistemas y equipos de infraestructura deben seguir para aplicar hardening web efectivo.
6. **❌ Errores Operacionales**: Registro transparente de aquellos dominios que fallaron debido a caídas de red, problemas de resolución de DNS (e.g. host inalcanzable) o timeouts de socket. De esta forma, el auditor sabrá qué activos estaban inactivos en el momento de la prueba sin alterar el flujo general del resto de los activos del alcance.

### Reporte JSON Integrable (`.json`)
Consolida un volcado estructurado del estado de cada host en formato JSON puro. Ideal para la importación directa a herramientas de SIEM, dashboards de vulnerabilidades o integración continua en pipelines de DevSecOps corporativos.

---

## 🧪 Pruebas Unitarias y de Integración (QA)

El aseguramiento de la calidad está garantizado mediante una amplia cobertura de pruebas unitarias que evalúan de forma simulada (Mocking) y real todos los componentes lógicos del software.

Para ejecutar la suite de pruebas completa:
```bash
python -m pytest
```

Para generar estadísticas rápidas de rendimiento e integración:
```bash
python -m pytest -v
```

---

## 📈 Plan de Expansión y Escalabilidad Futura

1. **Análisis de Suites de Cifrado (Cipher Suites)**: Clasificación de robustez en algoritmos como RSA, ECDHE, AES-GCM, y detección de cifrados obsoletos o propensos a debilidades criptográficas (e.g. RC4, 3DES, ciphers en modo CBC).
2. **Escaneo de Cabeceras de Seguridad Web**: Validación integrada de headers de protección como `HSTS` (HTTP Strict Transport Security) con su directiva `preload`, `CSP` (Content Security Policy) y `X-Frame-Options`.
3. **Procesamiento Concurrente Asíncrono**: Transición del motor de sockets bloqueantes a concurrencia asíncrona mediante `asyncio` para permitir el escaneo masivo de miles de dominios en segundos.
4. **Dashboard Ejecutivo Web**: Creación de una interfaz visual moderna (FastAPI / Next.js) que permita a los auditores cargar listas de dominios interactivamente, programar ejecuciones, ver gráficos y dashboards históricos de scores de seguridad de la infraestructura empresarial.
