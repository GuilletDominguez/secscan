# secscan

Escáner de seguridad unificado. Ejecuta herramientas open source en contenedores Docker de solo lectura y junta sus resultados en un único formato.

| Qué busca | Herramienta | Comando |
|---|---|---|
| Secretos en el código | Gitleaks | `scan` |
| Vulnerabilidades en el código (SAST) | Semgrep | `scan` |
| Dependencias vulnerables y malas configuraciones (Dockerfile, IaC) | Trivy | `scan` |
| Una aplicación web en ejecución (cabeceras, cookies, formularios…) | OWASP ZAP | `web` |
| Una imagen de contenedor (paquetes del sistema, dependencias, secretos en capas) | Trivy | `image` |

## Uso

```bash
uv sync
uv run secscan scan ./mi-repo                       # tabla en terminal
uv run secscan scan ./mi-repo --format sarif -o r.sarif
uv run secscan scan ./mi-repo --report-dir ./informe  # informe.html + .md + .json de una vez
uv run secscan scan ./mi-repo --format html -o informe.html
uv run secscan scan ./mi-repo --tools semgrep,trivy --fail-on medium
uv run secscan scan ./mi-repo --history             # Gitleaks revisa también todos los commits (requiere un `.git` real)
uv run secscan scan ./mi-repo --no-semgrep-metrics  # Semgrep sin métricas ni comprobación de versión
```

### Web y contenedores

```bash
uv run secscan web http://localhost:8000                       # tu app en local: sin confirmación
uv run secscan web https://mi-app.example --i-own-this         # cualquier otro destino exige confirmarlo
uv run secscan web http://localhost:8000 --minutes 5 --report-dir ./informe-web
uv run secscan image mi-app:1.0 --report-dir ./informe-imagen  # la imagen debe estar en local (docker pull)
```

**`web` es un escaneo pasivo** (ZAP con un plan propio del *Automation Framework*): rastrea los enlaces y examina las respuestas, **sin enviar ataques**. El escaneo activo no está implementado a propósito. Aun así genera tráfico hacia el destino: escanea solo sistemas tuyos o con permiso.

Protecciones del destino, antes de lanzar ningún contenedor:

- Solo `http://` y `https://`, sin usuario ni contraseña en la URL (quedarían en los informes), sin fragmento y sin espacios ni caracteres de control.
- **Nunca** direcciones de enlace local (`169.254.0.0/16`, el *metadata* de la nube), sin especificar ni multicast, ni siquiera con `--i-own-this`. Se comprueba también lo que resuelve un nombre.
- Solo una IP literal de loopback o el nombre exacto `localhost` se permiten sin confirmar. **Cualquier otro nombre exige `--i-own-this`, aunque hoy resuelva a `127.0.0.1`**: su DNS lo controla otra persona y mañana puede apuntar a otra dirección. Los rangos privados también lo exigen.
- Las direcciones validadas de un nombre (también `localhost`) se **fijan dentro del contenedor** (`--add-host`), para que un cambio posterior del DNS no desvíe el escaneo.
- Para alcanzar `localhost` el contenedor usa la red del host (`--network host`); para el resto, la red normal de Docker.
- ZAP se limita a la URL pedida (host, puerto y ruta): no sigue enlaces ni redirecciones hacia otros destinos. El alcance se construye a partir de la URL ya analizada, con un límite explícito tras el host, el puerto y la ruta, de modo que `https://mia.example` no admite `https://mia.example.evil.com/`, `https://mia.example@evil.com/` ni el puerto `:12345` cuando el destino es `:1234`, y `/app` no admite `/application`.
- **El Automation Framework de ZAP trata cada URL del contexto como un prefijo `url.*`** y lo suma a nuestro alcance. Por eso la URL del contexto lleva siempre una barra final: sin ella, `http://127.0.0.1:1234` era prefijo de `http://127.0.0.1:12345/…` y el rastreo lo seguía (se comprobó: el servidor del otro puerto recibía la petición).

**Por qué no se usa `zap-baseline.py`.** El script oficial arranca ZAP como demonio con `-host 0.0.0.0` y la API sin clave (`api.disablekey=true`). Con `--network host` eso dejaba la API —y un proxy— accesibles desde la red mientras duraba el escaneo (se comprobó). `secscan` ejecuta ZAP con `-cmd -autorun` y su propio plan, sin `-host`, e instala igualmente las reglas pasivas beta para no perder cobertura. El complemento OAST abre además un servidor de *callbacks* en todas las interfaces; se limita a loopback (`oast.callback.localaddr`). Medido con ZAP 2.17: todo lo que abre el proceso escucha solo en `127.0.0.1`. Sigue habiendo puertos locales abiertos mientras dura el escaneo: en una máquina con varios usuarios, otro usuario local podría alcanzarlos.

Cada contenedor lleva un nombre único y, si el escaneo vence o se interrumpe con Ctrl-C, se mata con `docker kill`: no queda nada corriendo.

`image` exporta la imagen con `docker save` y Trivy lee el `.tar`: **no se monta el socket de Docker** en ningún contenedor (daría control total del host). El nombre de la imagen se valida para que no pueda leerse como una opción. Ambos comandos aceptan `--config` con un fichero `.secscan.yml` para ignorar hallazgos, y los mismos formatos, `--report-dir` y `--fail-on` que `scan`.

Requiere Docker. Códigos de salida: `0` correcto, `1` hay hallazgos de la severidad de `--fail-on` o más, `2` una herramienta falló (nunca se informa «limpio» si no se pudo mirar).

## Como GitHub Action

Añade `.github/workflows/secscan.yml` a tu repo (un ejemplo completo en este mismo repositorio):

```yaml
on:
  pull_request:           # SIEMPRE pull_request, nunca pull_request_target
    branches: [main]
permissions: {}
jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read          # leer el código
      pull-requests: write    # comentar en el PR
      security-events: write  # subir el SARIF a la pestaña de seguridad
    steps:
      - uses: actions/checkout@<commit> # v7
        with:
          persist-credentials: false
      - uses: <propietario>/secscan@<commit>   # fija el commit, no una etiqueta
        with:
          fail-on: high
          signed-by: ${{ github.repository_owner }}   # opcional: quién firma el informe
```

En cada PR la action comenta el resumen (y lo mantiene actualizado en cada push), sube los hallazgos a la pestaña de seguridad, guarda el informe completo como artefacto, lo copia al resumen del job y **falla si hay hallazgos de la severidad de `fail-on` o si una herramienta no pudo ejecutarse**. Entradas: `path`, `tools`, `fail-on`, `history`, `semgrep-metrics`, `upload-sarif`, `comment-on-pr`, `report-dir`, `artifact-name`, `signed-by` y `category`.

Decisiones de seguridad, pensadas para un workflow que procesa código de terceros:

- **`pull_request`, no `pull_request_target`**: éste da permisos de escritura y secretos a código de forks.
- **Permisos mínimos**, y en los PR de forks (token de solo lectura) el comentario y el SARIF se omiten sin romper el job; el informe sigue en el resumen y en el artefacto.
- **Ninguna expresión `${{ }}` dentro de un `run:`**: las entradas viajan por variables de entorno, así que el título de un PR o el nombre de una rama no pueden inyectar comandos.
- **Log protegido con `stop-commands` y un token aleatorio**: una línea del repo escaneado que empiece por `::error::` no la interpreta el runner.
- **El comentario no puede notificar a nadie**: `@usuario` y `#123` del repo escaneado se rompen con un espacio de ancho cero.
- Solo se actualiza el comentario del propio `github-actions[bot]`.
- Las actions de terceros van **fijadas por commit**; Dependabot propone las nuevas con 7 días de espera.
- `uses: ./` en lugar de la sintaxis nueva `$/`: `actionlint` no la acepta todavía y no se pudo comprobar contra GitHub.

Tests (`tests/test_workflows.py`) impiden volver atrás en todo lo anterior: se ha comprobado que cada guarda falla si se rompe a propósito.

## Quién firma

`secscan` **no firma nada ni lleva ningún nombre**: ni en los informes, ni en los comentarios, ni en los metadatos del paquete o de la action. Quien instala la herramienta decide si firma sus informes y con qué:

```bash
secscan scan ./mi-repo --report-dir ./informe --signed-by "Equipo de Seguridad"
```

La firma aparece en el HTML, el Markdown y el JSON (`signed_by`). En la action, la entrada `signed-by`. Por defecto, nadie firma. Una firma no puede llevar saltos de línea ni caracteres de control y siempre se escapa. El comentario del PR lo publica `github-actions[bot]`.

## Qué rastros deja (y cuáles no)

- **En el proyecto**: nada de ningún repositorio analizado. Los fixtures de los tests salen de proyectos de ejemplo inventados, y hay un test (`tests/test_signature_and_traces.py`) que falla si se cuela la ruta personal, el nombre o el correo de quien ejecuta los tests, o cualquier dirección de correo.
- **En tu máquina**: los directorios temporales (el `.tar` de una imagen, los informes intermedios, el clon de `--history`) se borran al terminar. Quedan los informes que tú pides y la caché de la base de datos de Trivy (`~/.cache/secscan/trivy`), que no contiene datos de tus repos, y las imágenes de Docker descargadas.
- **Los informes se quedan en local y no se versionan.** `--report-dir` deja dentro de la carpeta un `.gitignore` con `*` (como hacen `pytest` o `ruff` con sus cachés), así que en cualquier repo esa carpeta se ignora sola y `secscan` no modifica ningún fichero del repo analizado. Este proyecto además ignora los nombres que genera (`secscan-report.*`, `informe*/`). Con `-o fichero.md` el nombre lo eliges tú: añádelo a tu `.gitignore`.
- **La GitHub Action sí publica el informe, en GitHub**: lo comenta en el PR, lo sube como artefacto (14 días), lo copia al resumen del job y sube el SARIF a la pestaña de seguridad. Si no quieres alguna de esas salidas, desactívalas con `comment-on-pr: "false"` y `upload-sarif: "false"`; el artefacto y el resumen del job siguen siendo visibles para quien tenga acceso al repo.
- **Hacia fuera**: `semgrep --config auto` descarga las reglas y envía métricas anónimas a Semgrep; Trivy y ZAP descargan sus bases de datos y reglas. Con `--no-semgrep-metrics` (o `semgrep-metrics: "false"` en la action) Semgrep **no envía métricas ni comprueba su versión**. `--config auto` las exige (con `--metrics off` falla), así que en ese modo se usa el conjunto de reglas fijo `p/default`: los hallazgos pueden diferir de los de `auto`, y las reglas se siguen descargando del registro de Semgrep (no hay modo totalmente sin red). Es un cambio de comportamiento, por eso no es el valor por defecto.

## Informes

| Formato | Para qué |
|---|---|
| `table` | Terminal (por defecto). |
| `html` | Informe visual de **un solo fichero**: sin JavaScript ni recursos externos, claro/oscuro según el sistema y legible en móvil. Se abre en cualquier navegador. |
| `md` | Markdown portable, para pegar en un PR, una wiki o un issue. |
| `json` | Datos completos, para otras herramientas. |
| `sarif` | Estándar de la industria; GitHub lo entiende en su pestaña de seguridad. |

Los informes que se comparten solo muestran el **nombre** de la carpeta escaneada, no la ruta local. Todo el texto que viene del repo (títulos, rutas, fragmentos) se escapa, y el HTML lleva una política CSP que impide scripts y recursos externos. Cada hallazgo incluye su **huella**, lista para copiarla a `.secscan.yml`.

### Aviso de contenido sospechoso

Escapar y la CSP neutralizan el texto malicioso del repo escaneado, pero en silencio. Además, `secscan` **lo avisa y lo detalla**: si un nombre de fichero, una regla, un título, una descripción, un error o una ruta analizada contiene marcado que habría ejecutado código (`<script>`, `onerror=`, `<iframe>`, `javascript:`…), el informe abre con una alerta y una lista **«Fragmentos a revisar»** (terminal, HTML y Markdown). Cada fila dice dónde está, en qué campo, qué tipo de marcado es y **la etiqueta exacta**, para que una persona decida si es un ataque o un falso positivo.

Los fragmentos se muestran siempre escapados (en HTML dentro de `<code>`): se ven, pero no se interpretan. Se detallan hasta 20; el resto están en el informe JSON (`hostile_hits`). Es una señal, no una garantía: la defensa real es escapar y la CSP. No se revisa el fragmento de código (`snippet`), porque las plantillas HTML legítimas lo contienen a menudo; ese se escapa igual.

## Triaje: `.secscan.yml`

Vive en el repo escaneado, así cada decisión queda versionada y con su motivo.

```yaml
ignore:
  paths: ["**/tests/**"]
  rules: [dependabot-missing-cooldown]
  findings:
    - id: 3f9a1c2b7d4e8a10      # huella estable (sin número de línea) del informe JSON
      reason: URL fija de configuración, no viene de la petición
```

## Decisiones de diseño

- **Modelo unificado** (`models.py`): cada herramienta se convierte a `Finding`. La huella no incluye la línea, así un falso positivo marcado sigue marcado si el código se mueve.
- **Cobertura**: se guarda qué se analizó, también lo limpio. «0 CVEs en `uv.lock`» es un dato.
- **Seguridad del propio escáner**: repo montado en solo lectura, contenedores con tu uid (nunca root), Gitleaks sin red, directorio de informes `0700` y lectura que rechaza enlaces simbólicos, `subprocess` sin shell, `yaml.safe_load`, secretos enmascarados y todo texto del repo escapado antes de pintarlo.
- **`--history` sobre un clon limpio**: el historial se lee de un clon espejo desechable, nunca del repo original. Un `.git/config` ajeno puede declarar programas que git ejecuta (fsmonitor, textconv, gpg…); el clon genera su propia configuración y esa no se copia. El clon se hace **dentro del contenedor** (sin red, sin root, repo en solo lectura), no en el host, porque git también ha tenido vulnerabilidades al procesar repos ajenos. Se prueba con un repo hostil real. En ese modo se revisan los commits, no el árbol de trabajo sin commitear; no se admiten `.git` que sean enlaces o ficheros (worktrees).
- **Una alerta de ZAP es un hallazgo por sitio, no por URL**: así la huella no cambia según las páginas que el rastreo encuentre; las URL afectadas van en la descripción.
- **Avisos**: si hay rutas que no se pueden leer, el informe lo dice; no se da «limpio» sobre lo que no se miró.
- **Parsers puros** probados con salidas reales guardadas en `tests/fixtures/` (sin Docker).

## Privacidad

`semgrep --config auto` descarga reglas de internet y envía métricas anónimas a Semgrep. Trivy descarga su base de datos (~130 MB, en caché en `~/.cache/secscan/trivy`).

## Limitaciones

- ZAP `stable` e imágenes de Trivy van con la etiqueta `latest`/`stable`: no están fijadas por versión ni *digest*.
- El escaneo web no autentica: solo ve lo que ve un visitante anónimo. Y el rastreo está limitado por `--minutes`.
- `image` necesita la imagen en local y espacio temporal para su `.tar`.
- La IP fijada con `--add-host` cubre un cambio de DNS durante el escaneo; no sustituye a confirmar con `--i-own-this` que el destino es tuyo.
- Mientras corre `web` contra `localhost`, ZAP abre puertos en `127.0.0.1` (sin autenticar): no lo uses en una máquina compartida con usuarios en los que no confíes.
- Que ZAP no sale del alcance se comprobó con ZAP real contra servidores que registran peticiones: enlaces a otro puerto, enlaces a una ruta hermana (`/app` frente a `/application`) y redirecciones 302 hacia otro puerto. No se probó con un DNS que cambie durante el escaneo ni con redirecciones a otro *host*; en ese caso solo protege la IP fijada.
- ZAP descarga las reglas pasivas beta al arrancar: el escaneo web necesita red hacia los servidores de ZAP, y si esa descarga falla se ejecuta sin ellas (sin aviso).

## Tests

```bash
uv run pytest
```
