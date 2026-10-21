<!--
Server Security Monitor v3.0
Created by FacuSecX
https://github.com/FacuSecX/
-->

<h1 align="center">🛡️ Server Security Monitor v3.0</h1>

<p align="center">
<img alt="Resumen de seguridad del servidor" src="https://i.ibb.co/ccHxDrV2/download-1.png" title="Server Security Monitor v3.0">
</p>
<br>

<p align="center">
  <a href="https://github.com/FacuSecX"><img alt="Autor: FacuSecX" src="https://img.shields.io/badge/Autor-FacuSecX-blue?style=for-the-badge&logo=github"></a>
  <img alt="Versión 3.0" src="https://img.shields.io/badge/Version-3.0-8b5cf6?style=for-the-badge">
  <img alt="Servidor Linux" src="https://img.shields.io/badge/Servidor-Linux-orange?style=for-the-badge&logo=linux">
  <img alt="Panel local para Windows" src="https://img.shields.io/badge/Panel-Windows-0078D4?style=for-the-badge">
</p>
<br>

Supervisá y administrá tu servidor Linux desde un panel local en Windows: consultá el tráfico de red, gestioná servicios y recibí alertas sin exponer el panel a Internet.
<br>
<br>
<p align="center">
<img alt="Resumen de seguridad del servidor" src="http://imgfz.com/i/GmuYwUL.png" title="Server Security Monitor v3.0">
</p>


## 🎯 Objetivo del proyecto

El objetivo de **Server Security Monitor** es **automatizar la instalación y administración de servicios en servidores Linux para usuarios que recién empiezan**, desde una interfaz visual en Windows. Buscamos reducir las tareas manuales y facilitar la puesta en marcha de aplicaciones sin exigir conocimientos avanzados de la terminal.

El proyecto busca:

- **Simplificar las instalaciones:** preparar las dependencias, la configuración inicial y el inicio de los servicios desde el panel.
- **Centralizar la administración:** gestionar servicios, puertos, usuarios, bases de datos y servidores de juego desde una misma interfaz.
- **Facilitar la supervisión:** mostrar el estado del servidor, el tráfico de red y las alertas para comprender qué está ocurriendo.
- **Acompañar el aprendizaje:** ofrecer controles claros y confirmaciones que ayuden a entender las acciones antes de aplicarlas.
- **Administrar distintos VPS:** reutilizar las cuentas del panel y mantener separado el historial de cada servidor.

## ✨ Funciones principales

- 📊 **Resumen e historial:** eventos, IP únicas, paquetes descartados y nivel de riesgo, con historial local por servidor.
- ⚡ **Tráfico de red:** conexiones entrantes y salientes, con filtros por IP, protocolo, país, ISP y puerto.
- 🌍 **Países e IP:** geolocalización, proveedores, ASN e investigación de direcciones.
- 🔐 **SSH:** accesos exitosos, intentos fallidos, usuarios probados e informes descargables.
- 🚫 **Bloqueos:** administración de IPv4/IPv6 y proveedores, con revisión de bloqueos masivos.
- 🔌 **Puertos y redirecciones:** apertura y cierre de accesos, procesos asociados y Port Forwarding TCP/UDP.
- 📦 **Servicios:** instalación, gestión y eliminación de Nginx, Apache, WordPress, phpMyAdmin y otros componentes.
- 🎮 **SA-MP:** instalación del servidor de juego con FTP opcional, aislado en su carpeta.
- 📁 **FTP seguro:** usuarios, carpetas y permisos propios mediante FTPS con TLS.
- 🗃️ **MySQL/MariaDB:** bases, usuarios, tablas y permisos; exploración de datos según los privilegios de cada cuenta.
- ☁️ **Cloudflare en Nginx:** bloqueo del acceso directo y SSL/HTTPS, con estados independientes.
- 🔔 **Alertas:** notificaciones en el panel y por Telegram ante accesos no autorizados.
- 🛡️ **Cuentas y permisos:** administrador principal, usuarios adicionales y operaciones protegidas con Windows Hello.
- 💻 **Terminal:** acceso SSH para el administrador principal, desbloqueado con Windows Hello.
- 🎨 **Personalización:** temas, colores, animaciones y sonidos.
- 🧹 **Limpieza:** borrado manual o programado de registros, con estado e historial.

## 🐧 Compatibilidad

**Las pruebas realizadas corresponden a Debian 12 y Debian 13.** Otras distribuciones pueden presentar errores de instalación o funcionamiento y todavía requieren validación completa.

En próximas actualizaciones ampliaremos las pruebas y la compatibilidad con más distribuciones, incluidas **Ubuntu y CentOS Stream**.

## 📋 Requisitos

**Windows:** Windows 10/11 de 64 bits, navegador y Windows Hello configurado con PIN o biometría. La distribución de Windows incluye [Node.js](https://nodejs.org/) y el runtime de .NET; no necesitás instalarlos por separado, ejecutar `npm install` ni instalar Python u OpenSSH para usar el programa.

**Servidor:** acceso SSH por contraseña o llave privada, permisos de administrador mediante `root` o `sudo`, systemd y conexión a los repositorios de paquetes.

La conexión admite una IP o un dominio accesible por SSH. Una red privada como [Tailscale](https://tailscale.com/download) es opcional.

## ⚙️ Instalación

### 1. Preparar el servidor Linux

Subí `instalar-servidor.sh` al VPS mediante SSH/SFTP y ejecutalo desde la carpeta donde lo guardaste:

```bash
sudo bash instalar-servidor.sh --usuario debian
```

Reemplazá `debian` si tu usuario SSH tiene otro nombre. Si ingresaste como `root`, omití `sudo` e indicá igualmente el usuario SSH que utilizará el panel.

Esperá **INSTALACIÓN COMPLETADA**. El script prepara las dependencias, el firewall y los componentes del panel. Los servicios y juegos se instalan después desde la interfaz.

Los registros de instalación se guardan en `/var/log/server-monitor-installer/`.

### 2. Ejecutar el programa en Windows

Copiá la carpeta completa del proyecto y abrí **`Server Monitor.exe`**. Conservá sus subcarpetas y aceptá el permiso de administrador de Windows durante la instalación.

Elegí **Nueva conexión**, ingresá la IP o el dominio, el puerto y el usuario SSH. Seleccioná contraseña o llave privada, comprobá la huella del servidor y completá Windows Hello cuando se solicite.

<p align="center">
<img alt="Seguridad SSH y registros de accesos" src="http://imgfz.com/i/lnYhaSB.png" title="Server Security Monitor v3.0">
</p>

### 3. Crear la cuenta administrativa

La primera vez, después de conectar el servidor, elegí tu usuario y contraseña del panel y confirmá con Windows Hello.

**La cuenta se crea una sola vez por instalación de Windows.** Se utiliza para todos los servidores guardados; agregar otra conexión no exige crear otro administrador. Las cuentas y credenciales se almacenan cifradas.


### 4. Abrir, cambiar de servidor o cerrar

El panel se abre en **http://127.0.0.1:8766**, salvo que elijas otro puerto local. Al iniciar nuevamente, podés seleccionar una conexión guardada o agregar otra.

Desde el icono del ojo junto al reloj de Windows:

- **Abrir panel:** muestra la interfaz en el navegador.
- **Cambiar conexión:** desconecta el servidor actual y abre el selector.
- **Cerrar programa:** cierra la conexión SSH y detiene el panel local.

Cerrar la pestaña del navegador mantiene el programa en segundo plano. Hay un servidor activo por vez y cada conexión conserva su propio historial, estadísticas, caché e informes.

## 📦 Instalar Servicios web y Aplicaciones

<p align="center">
<img alt="Seguridad SSH y registros de accesos" src="http://imgfz.com/i/dWcBp65.png" title="Server Security Monitor v3.0">
</p>
<br>

Al instalar WordPress, phpMyAdmin o Servicios, el panel prepara las dependencias, instala e inicia la base de datos si falta y configura el servidor web. Habilita los puertos web necesarios; **no hace falta publicar el puerto 3306** para una base local.

Completá WordPress desde `http://IP/` o abrí phpMyAdmin en `http://IP/phpmyadmin/`. Desde **Gestionar servicios** podés iniciar, detener y reiniciar los componentes instalados.

En **Nginx → Cloudflare** podés habilitar por separado:

- **Bloqueo del acceso directo:** el firewall limita los puertos 80/443 a los rangos IPv4/IPv6 de Cloudflare.
- **SSL/HTTPS:** pegá el certificado Origin CA y su clave privada para configurar HTTPS y redirigir HTTP a 443.

El dominio debe estar configurado en Cloudflare con el proxy activo. Para Origin CA, utilizá **Full (strict)** en SSL/TLS.

## 🔔 Alertas de Telegram

1. Creá un bot con BotFather y obtené su token.
2. Iniciá una conversación con el bot y obtené el chat ID del destino; BotFather no proporciona ese dato.
3. Abrí **Sistema → Alertas**, completá los datos y activá el envío.

El servicio de alertas funciona en Linux y puede continuar aunque cierres el panel o apagues Windows.

## 🔒 Datos y seguridad

- El panel funciona localmente en Windows y se comunica con el VPS por SSH.
- Las acciones respetan los permisos del usuario; las operaciones sensibles requieren confirmación o Windows Hello.
- Las cuentas del panel se comparten entre conexiones, pero los datos de cada servidor se guardan por separado.
- Conservá en privado contraseñas, llaves, datos locales y respaldos.
- Revisá el alcance antes de borrar registros: la limpieza elimina el historial seleccionado.

## ⚠️ Limitaciones

Actualmente, el panel está probado en **Debian 12 y Debian 13**. Las demás distribuciones todavía no se han verificado y pueden presentar errores durante la instalación o el funcionamiento de algunos módulos.

La compatibilidad completa con otras distribuciones aún no está garantizada. En futuras actualizaciones ampliaremos las pruebas y mejoraremos la compatibilidad, incluyendo **Ubuntu y CentOS Stream**.

## 🤝 Autor

**Panel creado por [FacuSecX](https://github.com/FacuSecX/) · Versión 3.0**

[Telegram](https://t.me/FacuSecX) · [Apoyar el proyecto en PayPal](https://paypal.me/FacuSecX)
