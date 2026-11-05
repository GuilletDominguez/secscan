# Limitaciones

Lo que `secscan` no hace o hace a medias. Está escrito con lo que se ha comprobado, y dice cuándo algo no se ha
probado. Para ajustar lo que sí se puede ajustar, mira [configuration.md](configuration.md).

## No es una auditoría

Junta lo que dicen Gitleaks, Semgrep, Trivy y ZAP. Que no salga nada no quiere decir que no haya nada, y lo que salga
puede ser un falso positivo. Ninguna de esas herramientas lo detecta todo, ni `secscan` lo promete.

No hace: análisis de licencias, SBOM, escaneo activo (el que envía ataques), autenticación en las webs, seguridad en
tiempo de ejecución, cumplimiento normativo.

## Dónde funciona

- **Solo se ha probado en Linux.** En Windows no funciona (usa `os.getuid`). En macOS con Docker Desktop no se ha
  probado, en especial el escaneo web de `localhost`, que usa `--network host`.
- Hace falta **Docker** con el demonio accesible, y **Python 3.13 o superior**.
- Las imágenes son grandes. Medidas en una descarga real: ZAP 3,75 GB, Semgrep 1,58 GB, Trivy 264 MB, Gitleaks 77 MB.
  La primera ejecución tarda por eso, y la base de datos de Trivy son otros ~130 MB.
- Las imágenes van con la etiqueta `latest` (`stable` la de ZAP), no fijadas por versión ni por `digest`. Una versión
  nueva puede cambiar los resultados, y el mismo escaneo hecho en dos fechas puede dar cosas distintas.
- En CI, Docker Hub limita las descargas anónimas por IP, y la descarga de las imágenes puede fallar por eso.
- Cada herramienta tiene un tiempo máximo fijo de **10 minutos**, que no se puede cambiar. En repos muy grandes puede
  quedarse corto y el escaneo falla con «superó 600s». En `web`, el máximo es `--minutes` más 15 minutos.

## Gitleaks (secretos)

- Todo secreto sale como severidad **alta**. No distingue una clave real de una de pruebas: eso se decide al revisar,
  y se ignora con `.secscan.yml`. Es normal que `tests/` llene el informe de falsos positivos de `generic-api-key`.
- Los valores salen siempre enmascarados. Nunca se guarda un secreto real en un informe.
- Por defecto mira los ficheros de la carpeta, no el historial.
- `--history` revisa los commits, **no** el árbol de trabajo sin commitear: para tener los dos, ejecuta con y sin la
  opción. Necesita un `.git` que sea un directorio de verdad: no vale un enlace simbólico ni un fichero `.git`
  (worktrees, submódulos). Trabaja sobre un clon temporal, que en repos enormes tarda y ocupa disco.

## Semgrep (código)

- **No analiza `tests/` por defecto.** Se ha comprobado: en un proyecto con 4 ficheros de Python, analizó los 2 que
  no estaban en `tests/`. Es el comportamiento de Semgrep. Mira la cobertura (la lista de ficheros analizados) en el
  informe.
- Si la carpeta es un repo de git, Semgrep solo mira los ficheros versionados. Un fichero nuevo sin añadir no se
  analiza.
- Con métricas usa `--config auto`; sin ellas, el conjunto fijo `p/default`. Pueden dar hallazgos distintos en un
  proyecto real. Solo se ha comparado en un proyecto de ejemplo, donde dieron lo mismo.
- Las reglas siempre se descargan del registro de Semgrep: no hay modo sin red.
- Muchas reglas de Semgrep dicen `warning` o se declaran de baja confianza, así que en lo que se ha visto la mayoría de
  hallazgos salen como severidad baja o media.
- Lo marcado con `# nosemgrep` no aparece en el informe.

## Trivy (dependencias, configuración e imágenes)

- En `scan` solo mira vulnerabilidades y configuración (Dockerfile, IaC). **No busca secretos en el código**: de eso se
  ocupa Gitleaks.
- Solo analiza lo que reconoce: ficheros de dependencias (`uv.lock`, `requirements.txt`…) y de configuración. En una
  prueba con un repo real no analizó un `compose.yaml`.
- Los resultados dependen de la fecha de su base de datos: «0 vulnerabilidades» hoy no es «ninguna» mañana. Por eso la
  action refresca la caché a diario.
- `image` necesita la imagen **en local** (`docker pull` antes). La exporta a un `.tar` temporal, que ocupa disco
  mientras dura el escaneo, y Trivy lo lee: no se monta el socket de Docker.
- En imágenes mira paquetes del sistema, de lenguaje y secretos en las capas. No mira la configuración de la imagen.

## ZAP (web)

- Es un escaneo **pasivo**: rastrea los enlaces y examina las respuestas (cabeceras, cookies, formularios). No ataca,
  así que no encuentra lo que solo se ve atacando (inyecciones, XSS…).
- **No se autentica.** Solo ve lo que ve un visitante anónimo.
- El rastreo es el normal, no el que ejecuta JavaScript: en aplicaciones que cargan casi todo con JavaScript verá poco.
- El rastreo dura como máximo `--minutes` (de 1 a 30) y la espera del análisis pasivo, 5 minutos. Una web grande no se
  recorre entera.
- Sale **un hallazgo por alerta y sitio**, no por URL: las URL afectadas van en la descripción (hasta 5), y ZAP guarda
  como mucho 10 alertas por regla.
- Descarga al arrancar las reglas pasivas beta. Si esa descarga falla, el escaneo sigue **sin ellas y sin avisar**.
- Mientras corre contra `localhost`, ZAP abre puertos en `127.0.0.1` sin autenticar. No lo uses en una máquina
  compartida con usuarios en los que no confíes.
- El alcance (mismo esquema, host, puerto y ruta) se ha probado con ZAP 2.17 y servidores que registraban peticiones:
  enlaces a otro puerto, a una ruta hermana y redirecciones 302 hacia otro puerto. No se ha probado con un DNS que
  cambie durante el escaneo ni con redirecciones a otro host; en ese caso solo protege la IP que se fijó al validar.
- Se ha probado contra una web real en producción (una aplicación de una sola página detrás de Cloudflare), dos veces
  y con resultados casi iguales. Solo se examinó la portada y sus ficheros estáticos: la parte que carga con JavaScript
  o exige sesión no se vio. Que salga bien en un sitio no demuestra que salga bien en cualquier otro.
- Se niega a escanear direcciones de enlace local (`169.254.x.x`, el metadata de la nube), sin especificar o multicast,
  aunque pases `--i-own-this`. Un nombre que resuelva a `127.0.0.1` pero no sea `localhost` también exige
  `--i-own-this`.
- Genera tráfico hacia el destino. Escanea solo lo tuyo o lo que tengas permiso para revisar.

## Informes

- El aviso de contenido sospechoso (`<script>`, `onerror=`…) es una lista de patrones: un atacante puede ofuscar el
  suyo para que no salte. Lo que protege de verdad es escapar todo, y eso se hace siempre. No se revisa el fragmento de
  código de un hallazgo, porque las plantillas HTML legítimas lo llevan a menudo; ese campo se escapa igual.
- El comentario de un PR se corta a unos 60 000 caracteres, el límite de GitHub, y enlaza al informe completo.
- La huella de un hallazgo cambia si cambia la regla, el fichero o el fragmento. Si cambias el código de esa línea, el
  hallazgo ignorado vuelve a salir.
- Un informe no se puede abrir de nuevo con la herramienta: es solo de lectura.

## GitHub Action

- **Se ha probado en GitHub**, con ejecuciones reales en pushes y pull requests (también en los que abre Dependabot):
  en este mismo repo, donde sube el SARIF a la pestaña de seguridad y comenta en el PR, y en tres repositorios
  privados. Además está validada con `actionlint` y `zizmor`, y con tests de lo que garantiza. Sigue **sin probarse**:
  un PR de un fork (debería omitir el comentario y el SARIF), la subida del SARIF en un repo privado con Advanced
  Security, `history: "true"` y varias ejecuciones con distinta `category`.
- Solo lanza `scan`. `web` e `image` necesitan una aplicación en marcha o una imagen construida, y no están en la
  action.
- En un PR de un fork el token es de solo lectura: no hay comentario ni subida a la pestaña de seguridad. El resumen del
  job y el artefacto sí se generan.
- En un repo privado, subir a la pestaña de seguridad necesita GitHub Advanced Security. Sin ello, esa subida falla,
  pero no tumba el escaneo (sale un aviso).
- Si escaneas una subcarpeta con `path`, las alertas de la pestaña de seguridad no apuntan al fichero correcto, porque
  las rutas son relativas a esa carpeta.
- El artefacto del informe se guarda 14 días.
- La action va fijada por commit y no se actualiza sola. Dependabot puede hacerlo si lo activas.
- El repo propio usa `uses: ./`. GitHub ha añadido una sintaxis nueva (`$/`) más segura contra un paso que sobrescriba
  la action en el disco, pero `actionlint` no la acepta todavía y no se ha podido probar.
