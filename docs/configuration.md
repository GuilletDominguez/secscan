# Configuración

Todo lo que se puede ajustar, con sus valores por defecto. Para lo que no hace la herramienta, mira
[limitations.md](limitations.md).

## Comandos y opciones

`secscan` tiene tres comandos. Las opciones de salida (`--format`, `-o`, `--report-dir`, `--signed-by`, `--fail-on`)
son iguales en los tres.

### `secscan scan RUTA`

Analiza una carpeta con Gitleaks, Semgrep y Trivy.

| Opción | Valores | Por defecto |
|---|---|---|
| `--tools` | lista separada por comas de `gitleaks`, `semgrep`, `trivy` | las tres |
| `--history` | Gitleaks revisa también todos los commits | no |
| `--semgrep-metrics` / `--no-semgrep-metrics` | con `--no-`, Semgrep no envía métricas ni comprueba su versión y usa las reglas `p/default` en vez de `auto` | con métricas |

### `secscan web URL`

Escaneo web pasivo con ZAP. Rastrea y examina las respuestas; no envía ataques.

| Opción | Valores | Por defecto |
|---|---|---|
| `--i-own-this` | confirma que el sistema es tuyo o tienes permiso. Obligatorio salvo para `localhost` o una IP de loopback | no |
| `--minutes` | de 1 a 30: minutos máximos de rastreo | 1 |
| `--config` | fichero `.secscan.yml` con lo que se ignora | ninguno |

### `secscan ports HOST`

Escaneo de puertos TCP con nmap. `HOST` es un dominio o una IP, sin `http://` ni puerto.

| Opción | Valores | Por defecto |
|---|---|---|
| `--i-own-this` | confirma que el sistema es tuyo o tienes permiso. Obligatorio salvo para `localhost` o una IP de loopback | no |
| `--ports` | puertos del 1 al 65535, separados por comas o en rango: `80,443` o `1-1024` | los 1000 más comunes |
| `--versions` | identifica el servicio y la versión de cada puerto abierto; envía sondas, así que es más intrusivo | no |
| `--config` | fichero `.secscan.yml` con lo que se ignora | ninguno |

### `secscan image IMAGEN`

Escanea una imagen de Docker que ya esté en local (`docker pull` antes si hace falta).

| Opción | Valores | Por defecto |
|---|---|---|
| `--config` | fichero `.secscan.yml` con lo que se ignora | ninguno |

### Opciones comunes de salida

| Opción | Valores | Por defecto |
|---|---|---|
| `--format` | `table`, `json`, `sarif`, `md`, `html` | `table` |
| `-o`, `--output` | fichero de salida | la salida estándar |
| `--report-dir` | carpeta donde escribir `secscan-report.html`, `.md`, `.json` y `.sarif` a la vez | no |
| `--signed-by` | texto (hasta 100 caracteres, sin saltos de línea) que sale como firma en el HTML, el Markdown y el JSON | nadie firma |
| `--fail-on` | `none`, `low`, `medium`, `high`, `critical` | `high` |

## Códigos de salida

| Código | Significa |
|---|---|
| 0 | Todo bien: ningún hallazgo llega al umbral de `--fail-on` y ninguna herramienta falló. |
| 1 | Hay hallazgos de la severidad de `--fail-on` o más. |
| 2 | Una herramienta falló, un argumento no es válido o `.secscan.yml` está mal. |

Si se dan el 1 y el 2 a la vez, sale el 1. Una herramienta que falla nunca da «limpio»: se sale con 2 y el informe lo
dice arriba. `--fail-on none` desactiva el código 1.

## Severidades

Todas las herramientas se convierten a cinco niveles: crítica, alta, media, baja e info.

| Herramienta | Cómo se decide |
|---|---|
| Gitleaks | Todo secreto es **alta**. |
| Semgrep | El nivel de la regla: `error` es alta, `warning` media, `note` baja. Si la regla se declara de **baja confianza**, baja un nivel. |
| Trivy | La severidad que da Trivy. Si no la reconoce, info. |
| ZAP | El riesgo de la alerta: alto, medio, bajo o informativo. Si la confianza es baja, baja un nivel. |

En SARIF, crítica y alta salen como `error`, media como `warning`, y baja e info como `note`.

## `.secscan.yml`

Sirve para ignorar hallazgos que no te interesan, siempre dejando escrito por qué. Se lee de la **raíz de la carpeta
escaneada** (`scan`) o del fichero que pases con `--config` (`web` e `image`).

```yaml
ignore:
  paths:
    - "**/tests/**"            # globs; `**` cruza carpetas y también vale en la raíz (`tests/x.py`)
  rules:
    - generic-api-key          # por el id corto de la regla: CVE-…, DS-0026, 10038-1…
  findings:
    - id: 3f9a1c2b7d4e8a10     # la huella de un hallazgo concreto
      reason: URL fija de configuración, no viene de la petición   # obligatorio
```

- `paths` se compara con la ruta que sale en el hallazgo: relativa al repo en `scan`, y la ruta dentro de la imagen
  en `image`. En `web` los hallazgos llevan una URL, así que no suele servir.
- `rules` ignora esa regla en todo el proyecto.
- `findings` ignora un hallazgo concreto. La **huella** sale en los informes JSON, Markdown y HTML. No incluye el
  número de línea: si el código se mueve, el hallazgo sigue siendo el mismo. Cambia si cambia la regla, el fichero o
  el fragmento.
- Los ignorados no aparecen en el informe, pero se cuentan («12 ignorados»).
- Una clave que no existe (`rulez:`) o un `reason` que falta es un error (código 2), no algo que se pasa por alto.

## Informes

| Formato | Para qué sirve |
|---|---|
| `table` | Terminal. Con `-o` se guarda sin colores. |
| `html` | Un solo fichero, sin JavaScript ni recursos externos. Se abre en cualquier navegador y se lee en el móvil. |
| `md` | Para pegar en un PR, una wiki o una incidencia. |
| `json` | Todos los datos: `findings`, `scanned`, `errors`, `warnings`, `alerts`, `hostile_hits`, `suppressed`, `signed_by`… |
| `sarif` | Para la pestaña de seguridad de GitHub y otras herramientas. |

La fecha de «Generado» sale en hora de Madrid, con un paréntesis que lo indica («5 de noviembre de 2026, 13:29 (hora de
Madrid)»), en el HTML y en el Markdown, y por tanto también en el comentario que publica la action en el PR y en el
resumen del job. El horario de verano se aplica solo. El JSON la guarda en UTC (`scanned_at`, formato ISO 8601), para
quien lo lea una máquina.

Ningún informe lleva la ruta completa de tu máquina: el HTML, el Markdown y el JSON guardan solo el nombre de la
carpeta escaneada, y el SARIF usa rutas relativas. Todo el texto que viene del repo o de la web escaneados se escapa
antes de mostrarlo.

`--report-dir` crea dentro de la carpeta un `.gitignore` con `*`, para que los informes no acaben en un commit. Con
`-o fichero.md` el nombre lo pones tú: añádelo a tu `.gitignore`.

Si un nombre de fichero, una regla o un mensaje del repo escaneado lleva algo que parece código para ejecutar
(`<script>`, `onerror=`, `javascript:`…), el informe abre con una alerta y una lista de los fragmentos, para que los
revises. Se detallan hasta 20.

## GitHub Action

La action escanea el código de cada pull request, comenta el resumen, sube los hallazgos a la pestaña de seguridad y
falla si hay algo grave.

### Entradas

| Entrada | Por defecto | Qué hace |
|---|---|---|
| `path` | `.` | Carpeta a escanear. Para que las alertas de la pestaña de seguridad apunten a la línea correcta, la raíz del repo. |
| `tools` | `gitleaks,semgrep,trivy` | Qué herramientas lanzar. |
| `fail-on` | `high` | El job falla con hallazgos de esta severidad o más (`none`, `low`, `medium`, `high`, `critical`). |
| `history` | `false` | Gitleaks revisa todos los commits. Necesita `fetch-depth: 0` en el checkout. |
| `semgrep-metrics` | `true` | Con `false`, Semgrep no envía métricas y usa `p/default`. |
| `upload-sarif` | `true` | Sube los hallazgos a la pestaña de seguridad. En un repo privado hace falta GitHub Advanced Security. |
| `comment-on-pr` | `true` | Publica un comentario con el resumen y lo mantiene actualizado en cada push. |
| `report-dir` | carpeta temporal | Dónde dejar los informes. Por defecto, fuera del repo escaneado. |
| `artifact-name` | `secscan-report` | Nombre del artefacto con el informe completo. |
| `signed-by` | vacío | Quién firma el informe. |
| `category` | `secscan` | Categoría del SARIF. Pon una distinta por cada ejecución si usas una matriz. |

### Salidas

| Salida | Qué es |
|---|---|
| `exit-code` | El código de salida de `secscan` (0, 1 o 2). |
| `report-dir` | La carpeta donde quedaron los informes. |

### Permisos

```yaml
permissions:
  contents: read          # leer el código
  pull-requests: write    # comentar en el PR (solo si comment-on-pr es true)
  security-events: write  # subir el SARIF (solo si upload-sarif es true)
```

### Instalarla en un repositorio tuyo

1. Sube `secscan` a GitHub. Si es privado, en sus ajustes de Actions permite que otros repos tuyos lo usen.
2. Coge el commit exacto que quieres usar: `gh api repos/<propietario>/secscan/commits/main --jq .sha`.
3. En el repo que quieres vigilar, crea `.github/workflows/secscan.yml`:

```yaml
name: secscan
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
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: <propietario>/secscan@<commit>
        with:
          fail-on: high
```

4. Abre un PR de prueba. Verás el comentario, los hallazgos en la pestaña *Security*, el informe completo en los
   artefactos de la ejecución y el job en rojo si hay algo de severidad alta o más.
5. Para que un PR en rojo no se pueda fusionar: Settings → Branches → protección de `main` → exigir el check `scan`.

Usa siempre el evento `pull_request`, no `pull_request_target`: el segundo da permisos de escritura y secretos a
código de forks.

### Recetas

- **Sin comentario ni pestaña de seguridad**: `comment-on-pr: "false"` y `upload-sarif: "false"`. El resumen del job y
  el artefacto se siguen generando.
- **Repo privado sin GitHub Advanced Security**: `upload-sarif: "false"`.
- **Solo secretos y código**: `tools: "gitleaks,semgrep"`.
- **Revisar también el historial**: `history: "true"` y, en el checkout, `fetch-depth: 0`.
- **Semgrep sin métricas**: `semgrep-metrics: "false"`.
- **Que no salte por un umbral tan estricto**: `fail-on: critical`.
- **Mantener la versión al día**: la action va fijada por commit, así que hay que cambiarlo a mano. Dependabot lo hace
  por ti si añades un `.github/dependabot.yml` con el ecosistema `github-actions`.

## Qué contacta con internet

| Qué | Con quién | Para qué |
|---|---|---|
| Docker | Docker Hub y `ghcr.io` | Descargar las imágenes la primera vez. |
| Trivy | su base de datos, publicada en registros de contenedores | Descargar las vulnerabilidades conocidas (~130 MB, a diario en la action). |
| Semgrep | el registro de Semgrep y, con métricas, `semgrep.dev` | Descargar las reglas y enviar métricas anónimas. Con `--no-semgrep-metrics` no hay métricas. |
| ZAP | los servidores de ZAP | Descargar las reglas pasivas beta al arrancar. |
| Nmap | el host que escaneas | Conectarse a sus puertos. No contacta con nadie más. |
| Gitleaks | nadie | Corre sin red. |

Nada del contenido de tus repos se guarda fuera de lo que pides.

## Dónde deja ficheros

- Los informes, solo donde tú pidas.
- `~/.cache/secscan/trivy`: la base de datos de Trivy. No lleva nada de tus repos.
- Carpetas temporales `secscan-*` (informes intermedios, el clon de `--history`, el `.tar` de una imagen). Se borran al
  terminar.
- Contenedores `secscan-<herramienta>-<aleatorio>`. Se borran al terminar, y se matan si el escaneo vence o lo
  interrumpes con Ctrl-C.
- Las imágenes de Docker descargadas se quedan en tu Docker.
