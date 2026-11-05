# Tocar el código

```bash
uv sync
uv run pytest -q
```

Los tests que usan Docker se saltan solos si no tienes la imagen descargada. El código y los nombres van en inglés;
los comentarios y la documentación, en español.

Esto es libre: haz un fork y cambia lo que quieras. Si algún test se queja, suele ser por una de estas cosas:

- Los ficheros de `tests/fixtures` salen de proyectos de ejemplo inventados, nunca de un repositorio real.
- El proyecto no lleva el nombre, el correo ni la ruta de nadie.
- Los workflows usan `pull_request`, no `pull_request_target`, y las actions van fijadas por commit.
- Lo que viene de un repositorio o de una web escaneados se escapa antes de mostrarlo.
