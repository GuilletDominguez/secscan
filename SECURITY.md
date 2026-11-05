# Política de seguridad

`secscan` es una herramienta de seguridad que procesa código y sistemas de terceros, así que sus propios fallos
importan. Gracias por avisar de forma responsable.

## Cómo avisar de una vulnerabilidad

**No abras una incidencia pública.** Usa el aviso privado de GitHub: pestaña **Security** del repositorio →
**Report a vulnerability**. Incluye, si puedes, los pasos para reproducirlo y la versión (`secscan --version` o el
commit).

Se intentará responder en un plazo razonable y publicar la corrección antes que los detalles.

## Qué cuenta como vulnerabilidad

Fallos de `secscan` que permitan, por ejemplo:

- que **texto de un repo o de una web escaneados** ejecute código o inyecte contenido en un informe, un comentario de
  PR o el log de Actions (HTML, Markdown, menciones de GitHub, órdenes `::…::`);
- que un escaneo web **salga del alcance** pedido, alcance destinos que no debería (enlace local, metadata de la nube)
  o se salte la confirmación `--i-own-this`;
- que un contenedor reciba más acceso del previsto (montajes, red, usuario, socket de Docker);
- que la GitHub Action use permisos de más, o ejecute código no confiable con permisos de escritura;
- que se **guarde o filtre** información de un repo analizado fuera de lo que se pidió.

## Qué no

- Hallazgos de Gitleaks, Semgrep, Trivy o ZAP sobre sus propias reglas: se avisan en su proyecto.
- Vulnerabilidades en las imágenes de esas herramientas: igual, en su proyecto.
- Que un escáner no detecte algo: ninguno detecta todo, y `secscan` no lo promete.

## Versiones con soporte

Solo la última versión publicada.

## Qué esperar de la herramienta

Las decisiones de seguridad y sus límites conocidos están en el [README](README.md) (secciones *Como GitHub Action*,
*Qué rastros deja* y *Limitaciones*).
