# Política de seguridad

## Uso seguro

- Mantén `SERVER_SECURITY_LISTEN_HOST=127.0.0.1`.
- No publiques `.env`, `provider-approvals.json`, `data/`, reportes, registros ni claves privadas.
- Protege la PPK con frase secreta y verifica la huella SSH antes de conectarte.
- Conserva un acceso de recuperación del proveedor antes de cambiar UFW.
- Revisa manualmente cada ASN; bloquear un proveedor completo puede afectar redes legítimas.
- Actualiza Windows, Node.js, PuTTY, Tailscale, Python y los paquetes del VPS.

## Alcance de los permisos

El instalador añade reglas limitadas en `/etc/sudoers.d/server-securityctl`. Revisa ese archivo después de la instalación. El panel no necesita ni debe recibir acceso general a una shell de `root`.

## Reportar una vulnerabilidad

No publiques secretos ni detalles explotables en una incidencia pública. Usa una Security Advisory privada del repositorio y explica la versión afectada, el impacto y una forma mínima de reproducir el problema.
