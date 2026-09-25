# Validación de la implementación

Ejecutada el 24 de septiembre de 2026 en Windows, Python 3.12, Node.js 24 y
.NET SDK 10 (restaurando proyectos net8.0). El pipeline está configurado para
Ubuntu, Python 3.12, Node.js 22 y .NET 8; no se ejecutó en Azure DevOps durante
esta implementación.

* 13 pruebas unitarias offline: marcadores/extras Python, versiones múltiples y
  paquetes scoped npm, grafo NuGet, clasificación raíz/directa/transitiva, política
  externa, paginación OSV, sensibilidad de nombres NuGet, fuente caída, ejecución
  continua con errores y CSV compatible. Suite revisada tras retirar el almacenamiento
  en base de datos el 25 de septiembre de 2026.
* Evaluaciones reales por paquete: requests 2.32.3 (5 componentes), yargs 17.7.2
  (16 componentes) y Microsoft.Extensions.Logging 8.0.0 (6 componentes).
* Evaluaciones reales por proyecto: requirements con python-dateutil 2.9.0.post0;
  package.json con debug 4.1.1; csproj con Newtonsoft.Json 12.0.1.
* Newtonsoft.Json 12.0.1: OSV devolvió GHSA-5crp-9r3c-p9vr, severidad HIGH y
  versión corregida 13.0.1. La ejecución finalizó con código 0 y decisión pending.
* Los SBOM de requests, yargs y Microsoft.Extensions.Logging validaron contra
  el JSON Schema oficial CycloneDX 1.6 mediante `tests/validate_sbom.py`.
* La entrada `pylibs_check.py` produjo el CSV con las nueve columnas originales.

Los artefactos locales de estas pruebas se conservan en `artifacts/` (ignorado por
Git). Los resultados dependen de la fecha, plataforma y fuentes; los conteos no
son resultados esperados permanentes para pruebas de regresión. La configuración
corporativa de Azure DevOps y retención de evidencia requiere despliegue
en la infraestructura correspondiente.
