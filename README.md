# Pylibs Check

Herramientas para verificar las librerías Python aprobadas en la empresa.

## Contenido

| Script | Descripción |
|--------|-------------|
| `daily_checks.py` | Verifica versiones y vulnerabilidades de un listado de librerías. Genera un reporte HTML. |
| `pylibs_check.py` | Audita una librería individual y todas sus dependencias (licencias, vulnerabilidades, metadatos). |

---

## daily_checks.py

Lee un archivo Excel con las librerías aprobadas y genera un **reporte HTML** con:

- **Versiones**: Compara la versión aprobada contra la última publicada en PyPI.
- **Vulnerabilidades**: Consulta la base de datos [OSV.dev](https://osv.dev) para detectar CVEs conocidos.

### Requisitos

```bash
pip install -r requirements.txt
```

**Dependencias**: `openpyxl`, `requests`, `packaging`, `jinja2`

### Formato del Excel

El Excel debe tener al menos estas dos columnas (la búsqueda es case-insensitive):

| Library | Version |
|---------|---------|
| requests | 2.31.0 |
| django | 5.0.0 |
| flask | 3.0.0 |

### Uso

```bash
# Básico (genera library_report.html)
python daily_checks.py --input librerías_aprobadas.xlsx

# Especificando archivo de salida
python daily_checks.py --input libs.xlsx --output reporte_febrero.html
```

### El reporte HTML

El archivo HTML generado es **auto-contenido** (todo el CSS está inline, sin JavaScript) para que puedas subirlo directamente a un canal de Teams como archivo.

#### ¿Qué contiene?

1. **Alerta de resumen** — Banner al inicio que dice de un vistazo si hay problemas:
   - 🔴 Rojo si hay vulnerabilidades
   - 🟡 Amarillo si solo hay actualizaciones pendientes
   - 🟢 Verde si todo está al día

2. **Tarjetas KPI** — Números grandes con el conteo de librerías:
   - Total | Versión al día | Actualización disponible | Con vulns (v. aprobada) | Vulns recientes (24h)

3. **Tabla de detalle** — Una fila por librería con:
   - Nombre (con link a PyPI)
   - Versión aprobada vs. última versión en PyPI
   - Badge de estado: `✔ OK` / `↑ Actualizar` / `⚠ Vulnerable` / `✗ Error`
   - IDs de vulnerabilidades **de la versión aprobada** como links clickeables a OSV.dev

4. **Vulnerabilidades en versión aprobada** (solo aparece si hay) — Para cada librería vulnerable:
   - Título explícito: "Estas vulnerabilidades afectan directamente la versión aprobada"
   - ID de la vulnerabilidad (GHSA, PYSEC, CVE)
   - Aliases (CVE asociados)
   - Severidad con badge de color: Crítica / Alta / Media / Baja
   - Descripción breve
   - Versión donde se corrigió

5. **Vulnerabilidades recientes (últimas 24h)** — Vulnerabilidades publicadas o modificadas en las últimas 24 horas para cualquier versión de las librerías del Excel:
   - Útil para detectar nuevos CVEs aunque no afecten directamente la versión aprobada
   - Muestra: librería, ID, severidad, resumen, rango de versiones afectadas, versión corregida, fecha de modificación
   - Si no hay vulns recientes, esta sección no aparece

6. **Footer** — Fecha, hora de ejecución, fuentes de datos (PyPI + OSV.dev), tiempo total.

### Códigos de salida

| Código | Significado |
|--------|-------------|
| `0` | Todo OK, sin vulnerabilidades |
| `1` | Se encontraron vulnerabilidades |
| `2` | Error de entrada (archivo no encontrado, columnas incorrectas) |
| `3` | Error inesperado |

### Logging

El script genera un archivo `daily_checks.log` con rotación automática (5 MB máx, 3 backups). También imprime todo en consola.

---

## pylibs_check.py

Auditor de una sola librería. Crea un entorno virtual aislado, instala el paquete, y analiza:

- Árbol de dependencias (directas y transitivas)
- Licencias de cada dependencia
- Vulnerabilidades conocidas (pip-audit + OSV)
- Metadatos de PyPI (última actualización, URLs)

```bash
python pylibs_check.py requests
```

Genera un reporte CSV con los resultados.
