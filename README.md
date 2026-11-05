# secscan

Un escáner de seguridad que junta varias herramientas open source en una sola. Las ejecuta en contenedores Docker y
reúne lo que encuentran en un único informe.

| Qué busca | Herramienta | Comando |
|---|---|---|
| Secretos en el código | Gitleaks | `scan` |
| Vulnerabilidades en el código | Semgrep | `scan` |
| Dependencias vulnerables y malas configuraciones (Dockerfile, IaC) | Trivy | `scan` |
| Una aplicación web en marcha (cabeceras, cookies, formularios…) | OWASP ZAP | `web` |
| Los puertos y servicios expuestos de un host | Nmap | `ports` |
| Una imagen de contenedor (paquetes, dependencias, secretos en capas) | Trivy | `image` |

El informe sale en la terminal, en HTML, en Markdown, en JSON o en SARIF. Hay también una GitHub Action que lo comenta
en cada pull request.

## Requisitos e instalación

- **Docker**, con el demonio accesible para tu usuario. Todas las herramientas corren en contenedores.
- **Python 3.13 o superior** y [`uv`](https://docs.astral.sh/uv/), que descarga Python si hace falta.
- **Probado solo en Linux.** En Windows no funciona y en macOS no se ha probado.

```bash
git clone https://github.com/<propietario>/secscan && cd secscan
uv sync
uv run secscan --help

# o como herramienta global, sin clonar:
uv tool install git+https://github.com/<propietario>/secscan
```

La primera ejecución descarga las imágenes (varios GB si usas ZAP) y la base de datos de Trivy.

## Uso

```bash
secscan scan ./mi-repo                            # tabla en la terminal
secscan scan ./mi-repo --report-dir ./informe     # HTML, Markdown, JSON y SARIF a la vez
secscan scan ./mi-repo --tools semgrep,trivy --fail-on medium
secscan scan ./mi-repo --history                  # Gitleaks revisa también todos los commits
secscan scan ./mi-repo --no-semgrep-metrics       # Semgrep sin enviar métricas

secscan web http://localhost:8000                 # escaneo web pasivo de tu app en local
secscan web https://mi-app.example --i-own-this   # cualquier otro destino hay que confirmarlo
secscan ports mi-servidor.example --i-own-this    # puertos TCP abiertos (dominio o IP, sin http://)
secscan image mi-app:1.0                          # la imagen debe estar ya en local
```

`web` no envía ataques, pero sí genera tráfico hacia el destino: escanea solo lo tuyo o lo que tengas permiso para
revisar. `--report-dir` crea una carpeta que git ignora sola.

La salida es 0 si todo va bien, 1 si hay hallazgos de la severidad de `--fail-on` (por defecto `high`) o más, y 2 si
una herramienta falló. Una herramienta que falla nunca da «limpio».

## En cada pull request

La GitHub Action escanea el código de cada PR, comenta el resumen, sube los hallazgos a la pestaña de seguridad y
falla si hay algo grave. Para usarla en un repo tuyo, añade `.github/workflows/secscan.yml`:

```yaml
on:
  pull_request:
    branches: [main]
permissions: {}
jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read
      pull-requests: write
      security-events: write
    steps:
      - uses: actions/checkout@<commit>
        with:
          persist-credentials: false
      - uses: <propietario>/secscan@<commit>
        with:
          fail-on: high
```

Fija siempre el commit y usa `pull_request`, nunca `pull_request_target`. Todas las entradas, los pasos para instalarla
y varias recetas están en [docs/configuration.md](docs/configuration.md). La action se ha probado en GitHub, en este repo y en tres repositorios privados; lo que sigue sin probarse está en
[docs/limitations.md](docs/limitations.md).

## Ignorar falsos positivos

Un fichero `.secscan.yml` en la raíz del repo escaneado dice qué ignorar, siempre con el motivo:

```yaml
ignore:
  paths: ["**/tests/**"]
  rules: [generic-api-key]
  findings:
    - id: 3f9a1c2b7d4e8a10
      reason: valor fijo de configuración, no viene de fuera
```

## Más información

- [Configuración](docs/configuration.md): todas las opciones, los formatos, la action y qué contacta con internet.
- [Limitaciones](docs/limitations.md): lo que no hace, lo que no se ha probado y los fallos conocidos.
- [Decisiones de diseño](docs/design.md): por qué se hace cada cosa así, sobre todo en seguridad.

## Licencia y uso libre

Dominio público ([Unlicense](LICENSE)): copia, modifica, vende o usa esto para lo que quieras, sin pedir permiso ni
citar a nadie. Va sin garantía ni soporte, y sus resultados no son una auditoría: que no salga nada no quiere decir
que no haya nada, y lo que salga puede ser un falso positivo.

## Tests

```bash
uv run pytest
```

Algunos tests vigilan reglas del proyecto, no solo el código: los ficheros de `tests/fixtures` salen de proyectos
inventados, el proyecto no lleva el nombre, el correo ni la ruta de nadie, y los workflows usan `pull_request`
(nunca `pull_request_target`) con las actions fijadas por commit.
