# Contribuir

## Entorno

```bash
uv sync
uv run pytest -q
```

Hace falta Docker solo para escanear de verdad y para algunos tests de integración, que se saltan solos si la
imagen no está descargada. Código y nombres en inglés; comentarios y documentación en español.

## Reglas del proyecto

Los tests las vigilan: si una te falla, es por esto.

- **Un cambio, sus tests.** Los parsers se prueban con salidas guardadas (`tests/fixtures/`), sin Docker.
- **Los fixtures salen de proyectos de ejemplo inventados**, nunca de un repo real: ni rutas, ni código, ni nombres.
  Un test falla si el proyecto contiene la ruta personal, el nombre o el correo de quien lo ejecuta.
- **El proyecto no firma nada ni lleva nombres propios.** Quien lo usa decide si firma sus informes (`--signed-by`).
- **Todo texto que venga de un repo o de una web escaneados es entrada no confiable**: se escapa en la terminal, el
  HTML y el Markdown, y nunca se pasa a un shell, a YAML o a una expresión de Actions.
- **Workflows**: `pull_request`, nunca `pull_request_target`; permisos mínimos; ninguna expresión `${{ }}` dentro de un
  `run:` (las entradas van por `env:`); actions de terceros **fijadas por commit** con el comentario de la versión.
  Valídalos con `actionlint` y `zizmor`.
- **Contenedores**: repo en solo lectura, usuario sin privilegios, sin socket de Docker, red cerrada si no hace falta.

## Antes de abrir un PR

```bash
uv run pytest -q
```

Y si tocaste `action.yml` o los workflows, pasa `actionlint`. Describe el porqué del cambio, no solo el qué.

Para avisar de una vulnerabilidad, mira [SECURITY.md](SECURITY.md): no abras una incidencia pública.
