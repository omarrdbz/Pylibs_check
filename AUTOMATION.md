# Evaluación preventiva OSS

La automatización produce evidencia para Seguridad. Una vulnerabilidad o una licencia
de riesgo **no aprueba, rechaza ni detiene** una evaluación. Toda ejecución comienza
con decisión `pending`. La decisión posterior se gestiona fuera de esta herramienta,
mediante el proceso del equipo responsable. `OK` en el CSV significa únicamente que las fuentes consultadas no
produjeron hallazgos para esa versión; no constituye una aprobación.

## Ejecutar

Python 3.10 o superior y `python -m pip install -r requirements-audit.txt`.
Para npm se requiere Node.js con npm 7+; para NuGet, el SDK .NET correspondiente al
framework del proyecto (el pipeline instala .NET 8). Ejecutar preferentemente desde
Azure DevOps en agentes Microsoft-hosted.

```bash
python -m oss_audit evaluate --ecosystem PyPI --target 'requests==2.32.3'
python -m oss_audit evaluate --ecosystem npm --target 'express@4.18.2'
python -m oss_audit evaluate --ecosystem NuGet --target 'Newtonsoft.Json@13.0.3'
python -m oss_audit evaluate --ecosystem PyPI --project requirements.txt
python -m oss_audit evaluate --ecosystem npm --project ./project/package.json
python -m oss_audit evaluate --ecosystem NuGet --project ./project/App.csproj
python pylibs_check.py 'requests==2.32.3'
```

El último comando conserva la interfaz anterior y copia las nueve columnas originales
a `audit_report_requests.csv`. Cada ejecución tiene además su carpeta UUID propia
en `artifacts/`, sin sobreescribir evidencia histórica. `daily_checks.py` mantiene
su flujo Excel/HTML existente.

Parámetros: `--output DIR`, `--policy archivo.json`, `--framework net8.0`.
Para proyectos, `--framework` no reemplaza los frameworks definidos en el `.csproj`.
Conviene especificar versiones concretas; si se omiten, el resolver elige una versión
y la evidencia conserva la versión exacta resultante.

## Resolución y alcance

* **PyPI:** `pip install --dry-run --ignore-installed --only-binary=:all: --report`.
  El reporte del resolver determina el conjunto completo; los metadatos
  `Requires-Dist`, marcadores de plataforma y extras determinan las aristas.
  No se instalan paquetes objetivo ni herramientas de auditoría dentro de su grafo.
  El modo proyecto admite archivos de requirements; no interpreta Poetry/uv locks.
  Paquetes sin wheels compatibles quedan como resolución incompleta.
* **npm:** resuelve en un directorio temporal con `--package-lock-only`,
  `--ignore-scripts` y `--no-audit`. Usa lock v2/v3, incluyendo dependencias de
  desarrollo, opcionales resueltas y peers. Conserva versiones múltiples y nombres
  scoped; admite package-lock y shrinkwrap. Workspaces y enlaces locales no se
  admiten y generan un análisis incompleto. El lock puede actualizarse si es
  incompatible con package.json; se guarda el lock resultante realmente evaluado.
* **NuGet:** `dotnet restore` usa directorio de paquetes, configuración pública y
  caché propios. Lee `project.assets.json` y las licencias de los `.nuspec` descargados.
  Une los componentes de todos los frameworks/RIDs restaurados; conserva los assets
  para consultar el contexto individual. `ProjectReference` requiere evaluar cada
  proyecto por separado; las configuraciones importadas desde carpetas superiores
  deben estar dentro del directorio de proyecto copiado. Fuentes privadas no se
  configuran en esta versión.

En modo paquete, `ROOT` es el paquete solicitado, `DIRECT` sus dependencias
inmediatas y `TRANSITIVE` el resto. En modo proyecto, `DIRECT` corresponde a las
referencias declaradas del proyecto. La clasificación prioriza ROOT y DIRECT cuando
un componente también aparece por otra ruta. La resolución refleja plataforma,
runtime y fecha de ejecución; no afirma cubrir plataformas que no se resolvieron.

Los directorios temporales se eliminan incluso ante errores. No son un sandbox de
seguridad por sí mismos: proyectos MSBuild y entradas de construcción pueden ejecutar
código durante resolución. Usar agentes efímeros, sin credenciales corporativas ni
acceso a redes internas; revisar la entrada de proyecto antes de ejecutar. El pipeline
no expone tokens de Azure ni persiste las credenciales del checkout al resolver.

## Vulnerabilidades y licencias

OSV se consulta por ecosistema, nombre y versión exacta para los tres ecosistemas.
Se recorren todas las páginas, se reintentan errores transitorios y se guarda la
respuesta original. Los registros retirados no se presentan como hallazgos activos.
Las severidades son etiquetas y/o vectores tal como los informa OSV: no se inventan
puntajes cuando faltan. Las versiones corregidas provienen únicamente de entradas
`affected` del componente coincidente; pueden corresponder a varias ramas, por lo
que **no son una recomendación automática de actualización**. El detalle original
conserva rangos y contexto. CVEs/aliases permanecen en `evaluation.json` y evidencia.

`policies/licenses.json` contiene patrones, versión y tratamiento de licencia
desconocida. Es una política inicial que Seguridad/Legal debe ajustar. Se conserva
una copia por evaluación. Se evalúan términos de expresiones `AND`, `OR` y `WITH`
con criterio conservador: cualquier término coincidente se señala para revisión.
No se determina automáticamente compatibilidad legal ni se resuelven excepciones
SPDX. Las licencias no declaradas y referencias a archivos requieren revisión.

## Evidencia y códigos de salida

Cada carpeta de evaluación contiene:

| Archivo | Contenido |
| --- | --- |
| `audit_report.csv` | Las nueve columnas originales, una fila por componente/version |
| `vulnerabilities.csv` | Una fila por componente/vulnerabilidad, severidad y versiones corregidas |
| `evaluation.json` | Metadatos, componentes, hallazgos, errores, política, UUID y decisión pendiente |
| `sbom.cdx.json` | CycloneDX 1.6: componentes, purls, licencias y relaciones resueltas |
| `evidence/` | Reportes originales, comandos, OSV y política efectiva |
| `manifest.json` | SHA-256 de los archivos de evidencia (integridad, no firma digital) |

Los CSV usan UTF-8 con BOM, escape CSV y protección de celdas con prefijos de
fórmula para su apertura en Excel. El JSON conserva valores sin transformación.
SBOM contiene inventario y dependencias; los hallazgos se consultan en el reporte
y CSV detallado. Un SBOM de evaluación incompleta lleva esa marca en metadata.

Código **0**: análisis completado, incluso si tiene hallazgos.
Código **2**: error operativo/análisis incompleto, sin decisión automática.
Los fallos OSV de un componente no impiden consultar los demás; nunca se traducen
en un componente limpio. Un error de resolución conserva reportes vacíos más
el error y los logs disponibles. La escritura en un destino no accesible o la
terminación forzada del agente puede impedir conservar evidencia.

## Evidencia y revisión manual

Cada evaluación conserva sus reportes y evidencia en una carpeta UUID independiente.
La herramienta no usa una base de datos ni registra decisiones posteriores del analista.
El campo `decision: pending` indica que la evidencia está pendiente de revisión;
la decisión final se gestiona en el proceso habitual del equipo de Seguridad.
Los CSV y JSON pueden utilizarse para una integración futura si se requiere.

## Azure DevOps

Crear un pipeline apuntando a `azure-pipelines.yml` y ejecutarlo manualmente.
Seleccionar ecosistema y target, o ruta de proyecto dentro del checkout. Los
parámetros pasan por variables de entorno y argumentos citados. Microsoft-hosted
`ubuntu-24.04` proporciona una VM efímera por job; las herramientas se preparan en
un venv y las resoluciones en carpetas temporales. Los hallazgos no fallan el job;
un problema operativo sí lo señala. `PublishPipelineArtifact` se ejecuta con
`always()` para conservar evidencia aun ante análisis incompleto.

Configurar retención de artefactos y descargar la evaluación antes de su
expiración. No se ha desplegado el YAML en una
organización Azure desde este repositorio; requiere crear allí el pipeline.

## Relación con Qualys SwCA

Esta automatización es preventiva y evalúa una resolución concreta antes de su
incorporación. Qualys SwCA aporta descubrimiento y monitoreo continuo en los activos.
No se equipara un resultado preventivo con cobertura de los activos, ni se cambian
hallazgos o decisiones en Qualys.

Para una futura conciliación, normalizar el export observado por Qualys a
`ecosystem, name, version` o purl y conservar `asset_id`, `observed_at` y fuente.
Comparar con `components` de los reportes JSON y las decisiones del proceso externo: observado
sin evaluación, evaluado no observado, diferencia de versión, y observado con
decisión pendiente/rechazada. Las coincidencias deben respetar ecosistema y versión;
no basta comparar el nombre. No se incluye un conector Qualys ni se presupone su
formato/API: esa integración queda para la fase futura solicitada.

## Verificación y referencias

`python -m unittest discover -s tests -v` ejecuta pruebas offline de resolución,
política, paginación, errores y exportación. Pruebas con registros reales
requieren salida HTTPS a PyPI, npm, NuGet y OSV. La conectividad no garantiza que
una fuente conozca todas las vulnerabilidades o licencias de un componente.

Para validar el SBOM contra el esquema oficial, instalar `jsonschema` en un entorno
de verificación y ejecutar `python tests/validate_sbom.py ruta/sbom.cdx.json`.
El validador consulta la versión 1.6 del repositorio oficial de CycloneDX.

* [Reporte de resolución pip](https://pip.pypa.io/en/stable/reference/installation-report/)
* [Lockfiles npm](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/)
* [API OSV y paginación](https://google.github.io/osv.dev/post-v1-query/)
* [Esquema CycloneDX 1.6](https://cyclonedx.org/schema/bom-1.6.schema.json)
* [Agentes Microsoft-hosted](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/hosted)
