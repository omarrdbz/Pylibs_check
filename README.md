# Pylibs Check

Herramientas internas para auditar las librerías Python aprobadas en la empresa: verificar que estén actualizadas, detectar vulnerabilidades conocidas y generar reportes para el equipo de desarrollo.

## Scripts

| Script | Qué hace |
|--------|----------|
| `daily_checks.py` | Verifica **todas** las librerías de un Excel: compara versiones contra PyPI, detecta vulnerabilidades (OSV.dev) y genera un reporte HTML para Teams. |
| `pylibs_check.py` | Audita **una sola** librería a profundidad: crea un entorno virtual aislado, analiza sus dependencias, licencias y vulnerabilidades. Genera CSV. |

## Estructura del proyecto

```
Pylibs_check/
├── daily_checks.py            # Verificador masivo (Excel → HTML)
├── pylibs_check.py            # Auditor individual (paquete → CSV)
├── requirements.txt           # Dependencias de daily_checks.py
├── templates/
│   └── report_template.html   # Plantilla Jinja2 del reporte HTML
├── .gitignore
└── README.md
```

---

## daily_checks.py

### ¿Qué hace?

1. Lee un archivo Excel con las librerías aprobadas (nombre + versión)
2. Consulta [PyPI](https://pypi.org) para saber si hay versiones más recientes
3. Consulta [OSV.dev](https://osv.dev) para detectar vulnerabilidades en la versión aprobada
4. Busca vulnerabilidades publicadas en las **últimas 24 horas** para esas librerías (en cualquier versión)
5. Genera un reporte HTML auto-contenido, listo para publicar en un canal de Teams

### Instalación

```bash
pip install -r requirements.txt
```

Dependencias: `openpyxl`, `requests`, `packaging`, `jinja2`

### Formato del Excel de entrada

El Excel debe tener al menos dos columnas (la búsqueda del encabezado es case-insensitive):

| Library | Version |
|---------|---------|
| requests | 2.31.0 |
| django | 5.0.0 |
| flask | 3.0.0 |
| cryptography | 42.0.0 |

Puedes agregar más columnas, el script solo lee `Library` y `Version`.

### Uso

```bash
# Ejecutar (genera library_report.html)
python daily_checks.py --input librerías_aprobadas.xlsx

# Especificar nombre del reporte de salida
python daily_checks.py --input libs.xlsx --output reporte_marzo.html
```

### El reporte HTML

El archivo generado es **auto-contenido** (CSS inline, sin JavaScript, sin archivos externos) para máxima compatibilidad al subirlo a Teams, correo o cualquier plataforma.

#### Secciones del reporte

| # | Sección | Descripción |
|---|---------|-------------|
| 1 | **Alerta de resumen** | Banner de color al inicio: 🔴 rojo si hay vulnerabilidades, 🟡 amarillo si solo hay actualizaciones, 🟢 verde si todo está OK. |
| 2 | **Tarjetas KPI** | Números grandes: Total · Actualización disponible · Con vulns (versión aprobada) · Vulns recientes (24h) · Errores. |
| 3 | **Tabla de detalle** | Una fila por librería con: nombre (link a PyPI), versión aprobada, última versión en PyPI, badges de estado (`↑ Actualizar`, `⚠ Vulnerable`), y los IDs de vulnerabilidades como links a OSV.dev. Una librería puede tener ambos badges si está desactualizada Y es vulnerable. |
| 4 | **Vulnerabilidades en versión aprobada** | Detalle de cada vulnerabilidad que afecta directamente la versión del Excel: ID (GHSA/PYSEC/CVE), aliases, severidad (Crítica/Alta/Media/Baja), descripción y versión corregida. Solo aparece si hay. |
| 5 | **Vulnerabilidades recientes (últimas 24h)** | CVEs publicados o modificados en las últimas 24 horas para estas librerías en **cualquier versión**. Útil para anticipar nuevos riesgos aunque no afecten la versión aprobada. Incluye rango de versiones afectadas. Solo aparece si hay. |
| 6 | **Footer** | Fecha, hora, fuentes de datos (PyPI + OSV.dev) y tiempo de ejecución. |

### Códigos de salida

| Código | Significado |
|--------|-------------|
| `0` | Sin vulnerabilidades en la versión aprobada |
| `1` | Se encontraron vulnerabilidades (útil para CI/CD) |
| `2` | Error de entrada: archivo no encontrado, columnas incorrectas, Excel vacío |
| `3` | Error inesperado |

### Logging

Genera `daily_checks.log` con rotación automática (5 MB máx, 3 backups). También imprime en consola en tiempo real.

### APIs utilizadas

| API | Uso | Endpoint |
|-----|-----|----------|
| PyPI JSON | Última versión publicada de cada paquete | `https://pypi.org/pypi/{pkg}/json` |
| OSV.dev Batch | Vulnerabilidades de la versión aprobada (una sola llamada para todas) | `https://api.osv.dev/v1/querybatch` |
| OSV.dev Batch (sin versión) | Vulnerabilidades recientes en cualquier versión | `https://api.osv.dev/v1/querybatch` |
| OSV.dev Vulns | Detalle individual de cada vulnerabilidad | `https://api.osv.dev/v1/vulns/{id}` |

### Resiliencia

- Reintentos automáticos con backoff exponencial en errores HTTP 429/5xx
- Rate limiting entre requests a PyPI (200ms)
- Si una librería falla, se marca como `ERROR` y las demás continúan
- Si el archivo de salida está bloqueado, genera uno con timestamp como fallback

---

## pylibs_check.py

Auditor individual de un paquete Python. Crea un entorno virtual temporal, instala el paquete y sus dependencias, y ejecuta herramientas de análisis.

### ¿Qué analiza?

- **Dependencias**: Árbol completo (directas y transitivas) con `pipdeptree`
- **Licencias**: Tipo de licencia de cada dependencia con `pip-licenses`, marca las restrictivas (GPL, AGPL, etc.)
- **Vulnerabilidades**: Escaneo con `pip-audit` vía OSV.dev
- **Metadatos**: Última actualización, URLs del proyecto, versión actual vs. última en PyPI

### Uso

```bash
python pylibs_check.py requests
```

Genera un archivo CSV con los resultados del análisis.

### Requisitos

Necesita Python con acceso a `venv`. Las herramientas de análisis (`pip-audit`, `pip-licenses`, `pipdeptree`) se instalan automáticamente en el entorno virtual temporal.
