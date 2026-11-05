# Decisiones de diseño

Por qué `secscan` hace las cosas como las hace. Casi todo viene de una idea: lo que se escanea no es de fiar. Puede ser
el código de un tercero, una web ajena o un PR de un fork, y la herramienta no debe poder ser atacada a través de ello.

## Una sola forma de hablar con todas las herramientas

Cada herramienta (Gitleaks, Semgrep, Trivy, ZAP, Nmap) se ejecuta en su contenedor, y su salida se convierte a un mismo
tipo, `Finding`. Esas funciones de conversión son puras y se prueban con salidas guardadas, sin Docker.

- La **huella** de un hallazgo no incluye el número de línea, así que uno marcado como falso positivo sigue marcado si
  el código se mueve.
- Se guarda **qué se analizó**, también lo que salió limpio. «0 CVEs en `uv.lock`» es un dato; no haber mirado nada es
  otra cosa.
- Si una herramienta falla, el informe lo dice y la salida es 2. Nunca se da «limpio» sobre lo que no se pudo mirar.
- Si hay rutas que el usuario no puede leer, también se avisa.

## Cómo se protege de lo que escanea

- El repo se monta en **solo lectura**, los contenedores corren con tu usuario (nunca root) y Gitleaks no tiene red.
- El directorio temporal de informes es privado (`0700`) y el informe se lee rechazando enlaces simbólicos y ficheros
  que no sean tuyos.
- No se usa `shell=True`, el YAML se lee con `safe_load` y los secretos salen siempre enmascarados.
- **Todo texto que viene de un repo o de una web** (títulos, rutas, fragmentos, errores) se escapa en la terminal, en el
  HTML y en el Markdown. El HTML lleva además una política CSP que impide scripts y recursos externos.
- En el Markdown, `@usuario` y `#123` se rompen con un espacio de ancho cero, para que un fichero llamado `@alguien`
  no notifique a esa persona desde un comentario de un PR.

### Aviso de contenido sospechoso

Escapar y la CSP neutralizan el texto malicioso, pero en silencio. Por eso, si un nombre de fichero, una regla, un
título, una descripción, un error o una ruta analizada contiene algo que habría ejecutado código (`<script>`,
`onerror=`, `<iframe>`, `javascript:`…), el informe abre con una alerta y una lista de fragmentos a revisar. Cada fila
dice dónde está, en qué campo, de qué tipo es y la etiqueta exacta, para decidir si es un ataque o un falso positivo.
Se muestran escapados, y hasta 20.

Es una señal, no una garantía: es una lista de patrones. La defensa real es escapar. No se revisa el fragmento de
código del hallazgo, porque las plantillas HTML legítimas lo llevan a menudo.

## `--history`: leer el historial sin fiarse del repo

Un `.git/config` ajeno puede declarar programas que git ejecuta (`fsmonitor`, `textconv`, `gpg`…). Por eso el historial
no se lee del repo original, sino de un **clon espejo desechable**, y ese clon se hace **dentro del contenedor** (sin
red, sin root, con el repo en solo lectura), no en tu máquina: git también ha tenido vulnerabilidades al procesar repos
ajenos. El clon genera su propia configuración y la del repo no se copia. Se ha probado con un repo hostil real.

Además, el contenedor corre con variables de entorno que anulan las claves de git que ejecutan programas, y con
`--no-textconv`, `--no-ext-diff` y `--no-show-signature`. Es una segunda barrera.

## Escaneo web: qué se comprueba antes y cómo se limita

Antes de lanzar ningún contenedor:

- Solo `http://` y `https://`, sin usuario ni contraseña en la URL (quedarían en los informes), sin fragmento y sin
  espacios ni caracteres de control.
- Nunca direcciones de enlace local (`169.254.0.0/16`, donde vive el metadata de la nube), sin especificar o multicast,
  ni siquiera con `--i-own-this`. Se comprueba también a qué resuelve un nombre.
- Solo una IP literal de loopback o el nombre exacto `localhost` se permiten sin confirmar. Cualquier otro nombre
  exige `--i-own-this`, aunque hoy resuelva a `127.0.0.1`: su DNS lo controla otra persona y mañana puede apuntar a
  otro sitio. Los rangos privados también lo exigen.
- Las direcciones validadas de un nombre (también `localhost`) se fijan dentro del contenedor con `--add-host`, para
  que un cambio posterior del DNS no desvíe el escaneo.

El alcance del rastreo se construye a partir de la URL ya analizada, con un límite explícito tras el host, el puerto y
la ruta. Así, `https://mia.example` no admite `https://mia.example.evil.com/`, `https://mia.example@evil.com/` ni el
puerto `:12345` cuando el destino es `:1234`, y `/app` no admite `/application`.

El Automation Framework de ZAP añade cada URL del contexto a ese alcance **como un prefijo** (`url.*`). Por eso la URL
del contexto lleva siempre una barra final: sin ella, `http://127.0.0.1:1234` era prefijo de `http://127.0.0.1:12345/…`
y el rastreo lo seguía. Se comprobó con ZAP real: el servidor del otro puerto recibía la petición.

### Por qué no se usa `zap-baseline.py`

El script oficial arranca ZAP como demonio con `-host 0.0.0.0` y la API sin clave. Con `--network host`, eso dejaba la
API y un proxy accesibles desde la red mientras duraba el escaneo (se comprobó). `secscan` ejecuta ZAP con `-cmd
-autorun` y su propio plan, sin `-host`, e instala igualmente las reglas pasivas beta para no perder cobertura. El
complemento OAST abre además un servidor de *callbacks* en todas las interfaces, y se limita a loopback. Medido con
ZAP 2.17, todo lo que abre el proceso escucha solo en `127.0.0.1`.

Una alerta de ZAP es un hallazgo **por sitio**, no por URL: si no, la huella cambiaría según las páginas que el rastreo
encuentre.

## Contenedores que no se quedan colgados

Cada contenedor lleva un nombre único. Si el escaneo vence o lo interrumpes con Ctrl-C, se mata con `docker kill`.
Antes, al vencer el tiempo se mataba el cliente de Docker y el contenedor seguía corriendo.

## Imágenes: sin el socket de Docker

`image` exporta la imagen a un `.tar` con `docker save` y Trivy lee ese fichero. En ningún contenedor se monta el
socket de Docker, porque daría control total de la máquina. El nombre de la imagen se valida para que no pueda leerse
como una opción.

## La GitHub Action

Pensada para un workflow que procesa código de terceros:

- Usa `pull_request`, no `pull_request_target`: éste da permisos de escritura y secretos a código de forks.
- Permisos mínimos. En los PR de forks, donde el token es de solo lectura, se omiten el comentario y el SARIF sin
  romper el job.
- Ninguna expresión `${{ }}` dentro de un `run:`: las entradas viajan por variables de entorno, así que el título de
  un PR o el nombre de una rama no pueden inyectar comandos.
- El log va entre órdenes `stop-commands` con un token aleatorio: una línea del repo escaneado que empiece por
  `::error::` no la interpreta el runner.
- Solo se actualiza el comentario del propio `github-actions[bot]`: cualquiera puede escribir la marca en el suyo.
- El job no queda en verde si hay hallazgos o si una herramienta falló, pero el informe se publica antes de fallar.
- Las actions de terceros van fijadas por commit, y Dependabot propone las nuevas con 7 días de espera.
- El entorno virtual y los informes se crean fuera del repo escaneado.

Los tests de `tests/test_workflows.py` impiden volver atrás en todo esto, y se ha comprobado que cada uno falla si se
rompe la regla a propósito.

## El proyecto no guarda rastros ni lleva nombres

- No firma nada ni lleva el nombre de nadie, ni en los informes ni en los metadatos del paquete o de la action. Quien la
  usa decide si firma sus informes (`--signed-by`).
- Los ficheros de `tests/fixtures` salen de proyectos de ejemplo inventados, nunca de un repo real.
- Un test falla si en el proyecto aparece la ruta personal, el nombre o el correo de quien lo ejecuta, o cualquier
  dirección de correo.
