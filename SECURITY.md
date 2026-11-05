# Seguridad

secscan es una herramienta de uso libre. No hay nadie al otro lado a quien avisar, ni canal de contacto, ni soporte,
y nadie se compromete a corregir nada ni a contestar.

Si encuentras un fallo de seguridad en el código, arréglalo en tu copia: es tuya para cambiarla. Si quieres compartir
el arreglo, un pull request es bienvenido, pero nadie te lo pide.

Ten en cuenta al usarla:

- No es una auditoría. Lanza Gitleaks, Semgrep, Trivy y ZAP y junta lo que dicen. Que no salga nada no quiere decir
  que no haya nada, y lo que salga puede ser un falso positivo. Qué hacer con los resultados lo decide quien la
  ejecuta.
- Viene sin garantía de ningún tipo.
- Escanea solo lo que sea tuyo o lo que tengas permiso para revisar. El escaneo web envía peticiones al sistema.

Cómo se protege la propia herramienta de lo que escanea, y dónde se queda corta, está en el README.
